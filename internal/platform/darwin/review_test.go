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

func TestSeatbeltWrapBuildsNativeProfile(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "sandbox-exec")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := base.Spec{
		Argv:        []string{"/bin/bash", "-c", "exec /opt/ai-tools/bin/claude"},
		Cwd:         "/Users/alice/Developer",
		Env:         map[string]string{"HOME": "/Users/ai-dev"},
		Home:        "/Users/ai-dev",
		Tmp:         "/private/var/lib/ai-sandbox/tmp",
		Workspace:   "/Users/alice/Developer",
		RuntimeRoot: "/opt/ai-tools",
		Network:     base.NetworkOpen,
		ReviewFD:    -1,
	}
	argv, err := (Sandbox{SandboxExec: executable}).Wrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) < 4 || argv[0] != executable || argv[1] != "-p" {
		t.Fatalf("unexpected argv: %v", argv)
	}
	profile := argv[2]
	for _, fragment := range []string{
		`(subpath "/opt/ai-tools")`,
		`(subpath "/Users/ai-dev")`,
		`(subpath "/Users/alice/Developer")`,
		`(allow network-outbound)`,
	} {
		if !strings.Contains(profile, fragment) {
			t.Fatalf("profile missing %s:\n%s", fragment, profile)
		}
	}
	if strings.Contains(profile, `(subpath "/Users/alice")`) {
		t.Fatalf("profile exposed the owner home:\n%s", profile)
	}
}
