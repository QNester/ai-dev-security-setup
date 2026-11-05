package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

func reviewFixture(t *testing.T) (config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.SharedDir = filepath.Join(dir, "shared")
	cfg.SharedSource = filepath.Join(dir, "alias")
	cfg.RuntimeRoot = filepath.Join(dir, "runtime")
	cfg.AIHome = filepath.Join(dir, "home")
	cfg.TmpRoot = filepath.Join(dir, "tmp")
	cfg.MaxReviewBytes = 1024
	for _, path := range []string{cfg.SharedDir, cfg.SharedSource, cfg.AIHome, cfg.TmpRoot, filepath.Join(cfg.RuntimeRoot, "bin")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	claude := filepath.Join(cfg.RuntimeRoot, "bin", "claude")
	if err := os.WriteFile(claude, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cfg.SharedDir, "input.txt")
	if err := os.WriteFile(file, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg, file
}

func TestReviewPrepareReturnsDescriptorSpec(t *testing.T) {
	cfg, file := reviewFixture(t)
	result, err := (Review{}).Prepare(context.Background(), cfg, file)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Cleanup()
	if result.Spec.ReviewFD != 3 || len(result.Files) != 1 {
		t.Fatalf("unexpected review result: fd=%d files=%d", result.Spec.ReviewFD, len(result.Files))
	}
	if result.Spec.Cwd != "/review" {
		t.Fatalf("cwd=%q", result.Spec.Cwd)
	}
	if !strings.HasSuffix(result.Spec.Argv[0], "/bin/claude") {
		t.Fatalf("argv=%v", result.Spec.Argv)
	}
	for _, mount := range result.Spec.BindMounts {
		if mount.Source == cfg.SharedDir || mount.Target == cfg.SharedDir {
			t.Fatalf("review spec mounts the shared tree: %+v", mount)
		}
	}
	if err := result.Spec.Validate(); err != nil {
		t.Fatal(err)
	}
	info, err := result.Files[0].Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("review descriptor is empty")
	}
}

func TestReviewAcceptsAliasPath(t *testing.T) {
	cfg, file := reviewFixture(t)
	alias := filepath.Join(cfg.SharedSource, "input.txt")
	result, err := (Review{}).Prepare(context.Background(), cfg, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Cleanup()
	if !strings.HasSuffix(result.Spec.Argv[0], "/bin/claude") {
		t.Fatalf("argv=%v", result.Spec.Argv)
	}
	if file == alias {
		t.Fatal("fixture did not exercise alias mapping")
	}
}

func TestReviewRejectsUnsafeInputs(t *testing.T) {
	cfg, file := reviewFixture(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(cfg.SharedDir, "link.txt")
	if err := os.Symlink(file, symlink); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(cfg.SharedDir, "large.txt")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", 2048)), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(cfg.SharedDir, "binary.bin")
	if err := os.WriteFile(binary, []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"outside": outside,
		"symlink": symlink,
		"large":   large,
		"binary":  binary,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := (Review{}).Prepare(context.Background(), cfg, path)
			if err == nil {
				result.Cleanup()
				t.Fatal("unsafe review input was accepted")
			}
		})
	}
}

func TestReviewSpecDoesNotSetSecrets(t *testing.T) {
	cfg, file := reviewFixture(t)
	result, err := (Review{}).Prepare(context.Background(), cfg, file)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Cleanup()
	for key := range result.Spec.Env {
		if strings.Contains(strings.ToUpper(key), "KEY") || strings.Contains(strings.ToUpper(key), "TOKEN") {
			t.Fatalf("review environment contains a secret-like variable %q", key)
		}
	}
	if result.Spec.ReviewFD != 3 {
		t.Fatalf("review fd=%d", result.Spec.ReviewFD)
	}
}

var _ base.ReviewBackend = Review{}
