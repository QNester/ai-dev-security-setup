package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

func enterFixture(t *testing.T) (config.Config, state.State) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.RuntimeRoot = filepath.Join(dir, "runtime")
	cfg.SharedDir = filepath.Join(dir, "shared")
	cfg.SharedSource = filepath.Join(dir, "alias")
	cfg.AIHome = filepath.Join(dir, "ai-home")
	cfg.TmpRoot = filepath.Join(dir, "tmp")
	for _, path := range []string{cfg.SharedDir, cfg.SharedSource, cfg.AIHome, cfg.TmpRoot, filepath.Join(cfg.RuntimeRoot, "bin")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	program := filepath.Join(cfg.RuntimeRoot, "bin", "claude")
	if err := os.WriteFile(program, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := state.State{
		Version: state.Version, Platform: "linux", Backend: "bwrap", Config: cfg,
		Runtime: state.Runtime{Path: cfg.RuntimeRoot, CLIs: []string{"claude"}},
	}
	return cfg, st
}

func TestBuildEnterSpecBindsAliasAndNotOwnerHome(t *testing.T) {
	cfg, st := enterFixture(t)
	spec, err := buildEnterSpec(st, "claude", cfg.SharedDir, []string{"--version"})
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	if spec.Cwd != cfg.SharedDir || spec.Home != cfg.AIHome || spec.Tmp != cfg.TmpRoot {
		t.Fatalf("unexpected spec paths: %+v", spec)
	}
	if len(spec.Argv) < 2 || spec.Argv[len(spec.Argv)-1] != "--version" {
		t.Fatalf("unexpected argv: %v", spec.Argv)
	}
	if !strings.HasSuffix(spec.Argv[0], "bash") {
		t.Fatalf("entrypoint is not bash: %v", spec.Argv)
	}
	var alias, resolv bool
	for _, mount := range spec.BindMounts {
		if mount.Source == cfg.SharedSource && mount.Target == cfg.SharedDir && !mount.ReadOnly {
			alias = true
		}
		if mount.Target == "/etc/resolv.conf" && mount.ReadOnly {
			resolv = true
		}
		if mount.Source == cfg.OwnerHome {
			t.Fatalf("owner home is exposed: %+v", mount)
		}
	}
	if !alias || !resolv {
		t.Fatalf("missing bind mounts: %+v", spec.BindMounts)
	}
	if spec.ReviewFD != -1 {
		t.Fatalf("review fd=%d", spec.ReviewFD)
	}
}

func TestResolveStartDirKeepsPathsInsideSharedTree(t *testing.T) {
	cfg, _ := enterFixture(t)
	sub := filepath.Join(cfg.SharedDir, "project")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.SharedSource, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveStartDir(cfg, sub); err != nil || got != sub {
		t.Fatalf("got=%q err=%v", got, err)
	}
	alias := filepath.Join(cfg.SharedSource, "project")
	if got, err := resolveStartDir(cfg, alias); err != nil || got != sub {
		t.Fatalf("alias got=%q err=%v", got, err)
	}
	if _, err := resolveStartDir(cfg, "/home/alice/other"); err == nil {
		t.Fatal("path outside the shared tree was accepted")
	}
}

func TestWrapIncludesAliasBindMount(t *testing.T) {
	_, st := enterFixture(t)
	spec, err := buildEnterSpec(st, "claude", st.Config.SharedDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	argv, err := (linux.Sandbox{}).Wrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--bind" && argv[i+1] == st.Config.SharedSource && argv[i+2] == st.Config.SharedDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("alias bind missing from %v", argv)
	}
}
