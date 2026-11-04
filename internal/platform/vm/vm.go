// Package vm defines the Lima/UTM fallback that delegates to Linux in a VM.
package vm

import (
	"context"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

type Sandbox struct{}

func (Sandbox) Name() string                    { return "vm" }
func (Sandbox) Available(context.Context) error { return base.ErrNotImplemented }
func (Sandbox) Wrap(_ context.Context, spec base.Spec) ([]string, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return nil, base.ErrNotImplemented
}
