package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/plan"
)

func testApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	app := New(stdout, stderr)
	app.Platform = "linux"
	app.Arch = "amd64"
	app.EUID = 1000
	return app, stdout, stderr
}

func writeTestConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.StatePath = filepath.Join(dir, "state.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cfg.StatePath
}

func TestInstallDryRun(t *testing.T) {
	configPath, statePath := writeTestConfig(t)
	app, stdout, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{
		"install", "--config", configPath, "--cli", "claude,opencode", "--dry-run", "--json",
	})
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var result plan.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.DryRun || len(result.Steps) == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(statePath); !errorsIsNotExist(err) {
		t.Fatalf("dry-run created state: %v", err)
	}
}

func writeSystemConfig(t *testing.T) string {
	t.Helper()
	configPath, _ := writeTestConfig(t)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.StatePath = config.Default("linux", "alice", "/home/alice").StatePath
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestInstallApplyRequiresRoot(t *testing.T) {
	configPath := writeSystemConfig(t)
	app, _, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{
		"install", "--config", configPath, "--yes",
	})
	if code != ExitFailure || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestInstallApplyRequiresYes(t *testing.T) {
	configPath := writeSystemConfig(t)
	app, _, stderr := testApp()
	app.EUID = 0
	code := app.Run(context.Background(), "sandboxctl", []string{
		"install", "--config", configPath,
	})
	if code != ExitUsage || !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestStatusMissing(t *testing.T) {
	app, stdout, _ := testApp()
	path := filepath.Join(t.TempDir(), "missing.json")
	if code := app.Run(context.Background(), "sandboxctl", []string{"status", "--state", path}); code != ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if strings.TrimSpace(stdout.String()) != "not installed" {
		t.Fatalf("output=%q", stdout.String())
	}
}

func TestLauncherDispatch(t *testing.T) {
	got := dispatchSymlink("claude-secure", []string{"--help"})
	want := []string{"enter", "--tool", "claude", "--", "--help"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	got = dispatchSymlink("ai-review-file", []string{"/tmp/input"})
	want = []string{"review", "/tmp/input"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestSkipCLIIsLimitedToInstallAndUpdate(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	app, _, _ := testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{
		"install", "--config", configPath, "--skip-cli", "--dry-run",
	}); code != ExitOK {
		t.Fatalf("install --skip-cli code=%d", code)
	}
	app, _, _ = testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{
		"status", "--skip-cli", "--state", filepath.Join(t.TempDir(), "missing.json"),
	}); code != ExitUsage {
		t.Fatalf("status accepted --skip-cli: code=%d", code)
	}
	configPath, _ = stateFixture(t, "linux")
	app, _, _ = testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{
		"update", "--config", configPath, "--skip-cli", "--dry-run",
	}); code != ExitOK {
		t.Fatalf("update --skip-cli code=%d", code)
	}
	app, _, _ = testApp()
	if code := app.Run(context.Background(), "sandboxctl", []string{
		"uninstall", "--config", configPath, "--skip-cli", "--dry-run",
	}); code != ExitUsage {
		t.Fatalf("uninstall accepted --skip-cli: code=%d", code)
	}
}

func TestColorizedStatusAndErrors(t *testing.T) {
	app, stdout, _ := testApp()
	app.forceColor = true
	if code := app.Run(context.Background(), "sandboxctl", []string{"status", "--state", filepath.Join(t.TempDir(), "missing.json")}); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), ansiYellow) || !strings.Contains(stdout.String(), "not installed") {
		t.Fatalf("unexpected colored status: %q", stdout.String())
	}

	configPath := writeSystemConfig(t)
	app, _, stderr := testApp()
	app.forceColor = true
	if code := app.Run(context.Background(), "sandboxctl", []string{"install", "--config", configPath, "--yes"}); code != ExitFailure {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), ansiRed) || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("unexpected colored error: %q", stderr.String())
	}
}

func TestColorizedPlanIsGreen(t *testing.T) {
	app, stdout, _ := testApp()
	app.forceColor = true
	configPath, _ := writeTestConfig(t)
	if code := app.Run(context.Background(), "sandboxctl", []string{"install", "--config", configPath, "--dry-run"}); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), ansiGreen) || !strings.Contains(stdout.String(), "dry-run") {
		t.Fatalf("unexpected colored plan: %q", stdout.String())
	}
}

func TestNoColorDisablesANSI(t *testing.T) {
	app, stdout, _ := testApp()
	app.forceColor = true
	if code := app.Run(context.Background(), "sandboxctl", []string{"status", "--no-color", "--state", filepath.Join(t.TempDir(), "missing.json")}); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("ANSI escape leaked with --no-color: %q", stdout.String())
	}
}

func TestReviewRejectsJSON(t *testing.T) {
	app, _, _ := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{"review", "--json", "/tmp/input.txt"})
	if code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
}

func TestReviewConfigFallsBackWhenStateIsMissing(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	app, _, _ := testApp()
	cfg, clis, err := app.reviewConfig(commonFlags{configPath: configPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StatePath == "" || len(clis) != 1 || clis[0] != "claude" {
		t.Fatalf("unexpected review config: state=%q clis=%v", cfg.StatePath, clis)
	}
}

func TestSpinnerRendersAndClears(t *testing.T) {
	app, _, stderr := testApp()
	app.forceSpinner = true
	spin := app.startSpinner("working")
	spin.Set("next step")
	spin.Stop()
	output := stderr.String()
	if !strings.Contains(output, "working") || !strings.Contains(output, "⠋") {
		t.Fatalf("spinner did not render: %q", output)
	}
	if !strings.HasSuffix(output, "\r\x1b[2K") {
		t.Fatalf("spinner did not clear its line: %q", output)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
