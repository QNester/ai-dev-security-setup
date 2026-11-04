package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRuntimeBinaryRequiresExecutableInsideRuntime(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveRuntimeBinary(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != path {
		t.Fatalf("resolved=%q want=%q", resolved, path)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveRuntimeBinary(root, "claude"); err == nil {
		t.Fatal("non-executable binary was accepted")
	}
}

func TestResolveRuntimeBinaryRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveRuntimeBinary(root, "claude"); err == nil {
		t.Fatal("symlink escaping the runtime was accepted")
	}
}
