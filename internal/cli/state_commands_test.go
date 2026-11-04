package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/plan"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

func stateFixture(t *testing.T, platform string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ownerHome := "/home/alice"
	if platform == "darwin" {
		ownerHome = "/Users/John Doe"
	}
	owner := "alice"
	if platform == "darwin" {
		owner = "John.Doe"
	}
	cfg := config.Default(platform, owner, ownerHome)
	cfg.StatePath = filepath.Join(dir, "state.json")
	st := state.State{
		Version: state.Version, Platform: platform,
		Backend: "bwrap", Config: cfg,
		Shared:  state.Shared{Path: cfg.SharedDir, ACL: "setfacl", Alias: cfg.SharedSource},
		Runtime: state.Runtime{Path: cfg.RuntimeRoot, CLIs: cfg.CLIs},
	}
	if platform == "darwin" {
		st.Backend = "seatbelt"
		st.Shared.ACL = "chmod"
		st.Shared.Alias = ""
	}
	if err := (state.Store{Path: cfg.StatePath, Root: dir}).Save(st); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, cfg.StatePath
}

func TestStatusUsesConfigStatePath(t *testing.T) {
	configPath, _ := stateFixture(t, "linux")
	app, stdout, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{"status", "--config", configPath, "--json"})
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var result struct {
		Installed bool `json:"installed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Installed {
		t.Fatal("state loaded through --config was not reported")
	}
}

func TestUpdateAndUninstallDryRunUseConfigStatePath(t *testing.T) {
	for _, operation := range []string{"update", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			configPath, _ := stateFixture(t, "linux")
			app, stdout, stderr := testApp()
			code := app.Run(context.Background(), "sandboxctl", []string{operation, "--config", configPath, "--dry-run", "--json"})
			if code != ExitOK {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			var result plan.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Operation != operation || !result.DryRun || len(result.Steps) == 0 {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestExplicitStateOverridesConfig(t *testing.T) {
	configPath, statePath := stateFixture(t, "linux")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = filepath.Join(filepath.Dir(statePath), "missing.json")
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	app, stdout, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{
		"status", "--config", configPath, "--state", statePath, "--json",
	})
	if code != ExitOK || !json.Valid(stdout.Bytes()) {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestStatusRejectsOtherPlatformState(t *testing.T) {
	configPath, _ := stateFixture(t, "darwin")
	app, _, _ := testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{"status", "--config", configPath}); code != ExitFailure {
		t.Fatalf("code=%d", code)
	}
}

func TestDoctorInvalidBackendIsUsageErrorWithJSON(t *testing.T) {
	app, _, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{"doctor", "--backend", "vm", "--json"})
	if code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	var result struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
		t.Fatalf("non-JSON error: %q", stderr.String())
	}
	if result.ExitCode != ExitUsage {
		t.Fatalf("unexpected error payload: %+v", result)
	}
}

func TestMissingStatusJSON(t *testing.T) {
	app, stdout, _ := testApp()
	path := filepath.Join(t.TempDir(), "missing.json")
	code := app.Run(context.Background(), "sandboxctl", []string{"status", "--state", path, "--json"})
	if code != ExitOK || !json.Valid(stdout.Bytes()) {
		t.Fatalf("code=%d output=%q", code, stdout.String())
	}
}

func TestReviewRequiresAbsolutePath(t *testing.T) {
	app, _, _ := testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{"review", "relative.txt"}); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
}
