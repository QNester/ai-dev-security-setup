package fsx

import (
	"syscall"
	"testing"
)

func TestUnsupportedDirectorySync(t *testing.T) {
	for _, err := range []error{syscall.EINVAL, syscall.ENOTSUP} {
		if !unsupportedDirectorySync(err) {
			t.Fatalf("expected unsupported sync error: %v", err)
		}
	}
	if unsupportedDirectorySync(syscall.EIO) {
		t.Fatal("I/O error must not be ignored")
	}
}
