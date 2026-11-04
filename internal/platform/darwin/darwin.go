// Package darwin implements best-effort native macOS adapters.
package darwin

import (
	"context"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

type Sandbox struct{}

func (Sandbox) Name() string                    { return "seatbelt" }
func (Sandbox) Available(context.Context) error { return base.ErrNotImplemented }
func (Sandbox) Wrap(_ context.Context, spec base.Spec) ([]string, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return nil, base.ErrNotImplemented
}

type Users struct{}

func (Users) EnsureUser(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Users) EnsureGroup(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Users) DeleteUser(context.Context, base.Config) error  { return base.ErrNotImplemented }

type ACL struct{}

func (ACL) GrantShared(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (ACL) RevokeShared(context.Context, base.Config) error { return base.ErrNotImplemented }
func (ACL) Verify(context.Context, base.Config) error       { return base.ErrNotImplemented }

type Network struct{}

func (Network) Apply(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Network) Verify(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Network) Remove(context.Context, base.Config) error { return base.ErrNotImplemented }

type Services struct{}

func (Services) Install(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Services) Remove(context.Context, base.Config) error  { return base.ErrNotImplemented }

type Review struct{}

func (Review) Prepare(context.Context, string) (base.Spec, func(), error) {
	return base.Spec{}, func() {}, base.ErrNotImplemented
}

func Backends() base.Backends {
	return base.Backends{
		Users: Users{}, ACL: ACL{}, Sandbox: Sandbox{}, Network: Network{},
		Services: Services{}, Review: Review{},
	}
}
