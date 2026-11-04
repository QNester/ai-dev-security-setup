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

func TestInstallApplyIsUnavailableAndDoesNotWriteState(t *testing.T) {
	configPath, statePath := writeTestConfig(t)
	app, _, stderr := testApp()
	code := app.Run(context.Background(), "sandboxctl", []string{
		"install", "--config", configPath, "--yes",
	})
	if code != ExitUnavailable || !strings.Contains(stderr.String(), "Phase 1") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(statePath); !errorsIsNotExist(err) {
		t.Fatalf("failed install created state: %v", err)
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
	want := []string{"enter", "--tool", "claude", "--help"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	got = dispatchSymlink("ai-review-file", []string{"/tmp/input"})
	want = []string{"review", "/tmp/input"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
