package fsx

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSafeOpenRegularRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		file, err := SafeOpenRegular(path)
		if file != nil {
			file.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("SafeOpenRegular blocked on FIFO")
	}
}

func TestAtomicWriteRejectsSymlinkParent(t *testing.T) {
	dir := t.TempDir()
	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(dir, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linkParent, "state.json")
	if err := AtomicWriteFile(path, []byte("data"), 0o600); err == nil {
		t.Fatal("symlink parent was accepted")
	}
	if _, err := os.Stat(filepath.Join(realParent, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("file was written through symlink: %v", err)
	}
}

func TestAtomicWriteRejectsWorldWritableParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(filepath.Join(dir, "state.json"), []byte("data"), 0o600); err == nil {
		t.Fatal("world-writable parent was accepted")
	}
}
