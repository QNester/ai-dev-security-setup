package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteAndSafeOpen(t *testing.T) {
	dir := testRoot(t)
	path := filepath.Join(dir, "state.json")
	if err := AtomicWriteFileInRoot(dir, path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFileInRoot(dir, path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := SafeOpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestRefuseSymlinks(t *testing.T) {
	dir := testRoot(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeOpenRegular(link); err == nil {
		t.Fatal("SafeOpenRegular followed a symlink")
	}
	if err := AtomicWriteFileInRoot(dir, link, []byte("changed"), 0o600); err == nil {
		t.Fatal("AtomicWriteFile replaced a symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "secret" {
		t.Fatalf("target changed: %q, %v", data, err)
	}
}
