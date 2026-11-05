package contract

import (
	"context"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/platform/darwin"
	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
)

func TestSandboxContract(t *testing.T) {
	backends := []base.Sandbox{linux.Sandbox{}, darwin.Sandbox{}}
	for _, backend := range backends {
		t.Run(backend.Name(), func(t *testing.T) {
			if backend.Name() == "" {
				t.Fatal("empty backend name")
			}
			// A backend may legitimately be unavailable on the host running
			// the portable contract suite (for example sandbox-exec is not on
			// Linux). The invalid-spec assertion below is the portable part.
			spec := base.Spec{Argv: []string{"/usr/bin/true"}, Network: base.NetworkOpen, ReviewFD: -1}
			_, _ = backend.Wrap(context.Background(), spec)
			spec.Network = "invalid"
			if _, err := backend.Wrap(context.Background(), spec); err == nil {
				t.Fatal("invalid portable spec was accepted")
			}
		})
	}
}
