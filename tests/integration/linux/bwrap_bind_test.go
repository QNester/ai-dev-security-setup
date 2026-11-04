//go:build integration && linux

package integrationlinux

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

func TestBubblewrapBindsAliasAndReadOnlyFile(t *testing.T) {
	if os.Getenv("SANDBOXCTL_INTEGRATION") != "1" {
		t.Skip("set SANDBOXCTL_INTEGRATION=1 to run the read-only Bubblewrap probe")
	}
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	home := filepath.Join(dir, "home")
	tmp := filepath.Join(dir, "tmp")
	for _, path := range []string{shared, home, tmp} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(shared, "input"), []byte("bound\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := base.Spec{
		Argv:       []string{"/bin/cat", "input"},
		Cwd:        "/home/ai-dev/shared",
		Env:        map[string]string{"PATH": "/usr/bin:/bin"},
		Home:       home,
		Tmp:        tmp,
		Network:    base.NetworkOpen,
		BindMounts: []base.BindMount{{Source: shared, Target: "/home/ai-dev/shared"}, {Source: hosts, Target: "/etc/hosts", ReadOnly: true}},
		ReviewFD:   -1,
	}
	argv, err := (linux.Sandbox{}).Wrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (runner.OSRunner{}).Run(context.Background(), runner.Command{
		Path: argv[0], Args: argv[1:], Env: []string{"PATH=/usr/bin:/bin"}, MaxOutputBytes: 4096,
	})
	if err != nil {
		t.Fatalf("argv execution failed: %v; stdout=%q stderr=%q", err, result.Stdout, result.Stderr)
	}
	if result.Stdout != "bound\n" {
		t.Fatalf("unexpected stdout: %q", result.Stdout)
	}
}
