//go:build integration && linux

package integrationlinux

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

func TestBubblewrapReviewExposesOnlyDescriptor(t *testing.T) {
	if os.Getenv("SANDBOXCTL_INTEGRATION") != "1" {
		t.Skip("set SANDBOXCTL_INTEGRATION=1 to run the Bubblewrap review probe")
	}
	dir := t.TempDir()
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.SharedDir = filepath.Join(dir, "shared")
	cfg.SharedSource = filepath.Join(dir, "alias")
	cfg.RuntimeRoot = filepath.Join(dir, "runtime")
	cfg.AIHome = filepath.Join(dir, "home")
	cfg.TmpRoot = filepath.Join(dir, "tmp")
	cfg.MaxReviewBytes = 4096
	for _, path := range []string{cfg.SharedDir, cfg.SharedSource, cfg.AIHome, cfg.TmpRoot, filepath.Join(cfg.RuntimeRoot, "bin")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(cfg.RuntimeRoot, "bin", "claude")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat /review/input\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(cfg.SharedDir, "input.txt")
	content := "only this file is visible\n"
	if err := os.WriteFile(input, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	prepared, err := (linux.Review{}).Prepare(context.Background(), cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Cleanup()
	argv, err := (linux.Sandbox{}).Wrap(context.Background(), prepared.Spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range argv {
		if arg == cfg.SharedDir {
			t.Fatalf("review argv mounts the shared tree: %v", argv)
		}
	}
	result, err := (runner.OSRunner{}).Run(context.Background(), runner.Command{
		Path: argv[0], Args: argv[1:], Env: []string{},
		ExtraFiles: prepared.Files, MaxOutputBytes: 4096,
	})
	if err != nil {
		t.Fatalf("review argv failed: %v; stderr=%q", err, result.Stderr)
	}
	if !bytes.Equal([]byte(result.Stdout), []byte(content)) {
		t.Fatalf("stdout=%q want=%q", result.Stdout, content)
	}
	if err := prepared.Spec.Validate(); err != nil {
		t.Fatal(err)
	}
	var _ base.ReviewBackend = linux.Review{}
}
