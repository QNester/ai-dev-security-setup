package contract

import (
	"context"
	"errors"
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
			spec := base.Spec{Argv: []string{"/usr/bin/true"}, Network: base.NetworkOpen, ReviewFD: -1}
			if _, err := backend.Wrap(context.Background(), spec); !errors.Is(err, base.ErrNotImplemented) {
				t.Fatalf("unexpected error: %v", err)
			}
			spec.Network = "invalid"
			if _, err := backend.Wrap(context.Background(), spec); err == nil {
				t.Fatal("invalid portable spec was accepted")
			}
		})
	}
}
