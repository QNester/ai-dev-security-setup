package darwin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

func TestSeatbeltWrapUsesReviewProfileWithoutSharedTree(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "sandbox-exec")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := base.Spec{
		Argv:       []string{"/opt/ai-tools/bin/claude", "--print"},
		Cwd:        "/private/var/review",
		Env:        map[string]string{"HOME": "/Users/ai-dev"},
		Home:       "/Users/ai-dev",
		Tmp:        "/private/var/lib/ai-sandbox/tmp",
		Network:    base.NetworkOpen,
		Review:     true,
		ReviewFD:   -1,
		ReviewPath: "/private/var/review/input",
	}
	argv, err := (Sandbox{SandboxExec: executable}).Wrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) < 4 || argv[0] != executable || argv[1] != "-p" {
		t.Fatalf("unexpected argv: %v", argv)
	}
	profile := argv[2]
	if !strings.Contains(profile, `(deny default)`) ||
		!strings.Contains(profile, `(literal "/opt/ai-tools/bin/claude")`) ||
		!strings.Contains(profile, `(subpath "/private/var/review")`) {
		t.Fatalf("unexpected review profile:\n%s", profile)
	}
	if strings.Contains(profile, "/home/alice/Developer") {
		t.Fatalf("review profile names the shared tree:\n%s", profile)
	}
}

func TestSeatbeltWrapKeepsLifecycleUnavailable(t *testing.T) {
	spec := base.Spec{Argv: []string{"/usr/bin/true"}, Network: base.NetworkOpen, ReviewFD: -1}
	if _, err := (Sandbox{}).Wrap(context.Background(), spec); err == nil {
		t.Fatal("non-review macOS sandbox execution was accepted")
	}
}
