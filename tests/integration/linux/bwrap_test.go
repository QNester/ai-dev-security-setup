//go:build integration && linux

package integrationlinux

import (
	"context"
	"os"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

func TestBubblewrapRunsTrue(t *testing.T) {
	if os.Getenv("SANDBOXCTL_INTEGRATION") != "1" {
		t.Skip("set SANDBOXCTL_INTEGRATION=1 to run the read-only Bubblewrap probe")
	}
	spec := base.Spec{
		Argv: []string{"/usr/bin/true"}, Cwd: "/", Network: base.NetworkOpen,
		Env: map[string]string{"PATH": "/usr/bin:/bin"}, ReviewFD: -1,
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
}
