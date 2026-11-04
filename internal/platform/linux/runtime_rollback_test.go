package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	coreruntime "github.com/QNester/ai-dev-security-setup/internal/core/runtime"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

func rollbackDeps() Deps {
	return Deps{
		Runner: &scriptedRunner{run: func(runner.Command) (runner.Result, error) {
			return runner.Result{}, errors.New("not a mountpoint")
		}},
		LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
	}
}

func TestRollbackWithoutMarkerIsNoOp(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.RuntimeRoot = filepath.Join(dir, "tools")
	home := coreruntime.Home(cfg)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "keep"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (Runtime{Deps: rollbackDeps()}).Rollback(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "keep")); err != nil {
		t.Fatalf("rollback removed a runtime it did not install: %v", err)
	}
}

func TestRollbackRestoresPreviousRuntime(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.RuntimeRoot = filepath.Join(dir, "tools")
	home := coreruntime.Home(cfg)
	previous := coreruntime.Previous(cfg)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(previous, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, "old"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeMarkerPending(cfg), []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Runtime{Deps: rollbackDeps()}).Rollback(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "old")); err != nil {
		t.Fatalf("previous runtime was not restored: %v", err)
	}
	if _, err := os.Stat(runtimeMarkerPending(cfg)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transaction marker survived rollback: %v", err)
	}
}
