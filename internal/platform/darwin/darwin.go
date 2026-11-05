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

type Host struct{}

func (Host) Prepare(context.Context, base.Config) (bool, error) { return false, base.ErrNotImplemented }
func (Host) Verify(context.Context, base.Config) error          { return base.ErrNotImplemented }
func (Host) VerifyRemoved(context.Context, base.Config) error   { return base.ErrNotImplemented }
func (Host) RemoveTemporary(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Host) Cleanup(context.Context, base.Config) error         { return base.ErrNotImplemented }

type Users struct{}

func (Users) EnsureUser(context.Context, base.Config) (bool, error) {
	return false, base.ErrNotImplemented
}
func (Users) EnsureGroup(context.Context, base.Config) (bool, error) {
	return false, base.ErrNotImplemented
}
func (Users) DeleteUser(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Users) DeleteGroup(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Users) Verify(context.Context, base.Config) error      { return base.ErrNotImplemented }

type ACL struct{}

func (ACL) DenyOwner(context.Context, base.Config) error       { return base.ErrNotImplemented }
func (ACL) RevokeOwnerDeny(context.Context, base.Config) error { return base.ErrNotImplemented }
func (ACL) GrantShared(context.Context, base.Config) error     { return base.ErrNotImplemented }
func (ACL) RevokeShared(context.Context, base.Config) error    { return base.ErrNotImplemented }
func (ACL) Verify(context.Context, base.Config) error          { return base.ErrNotImplemented }

type Runtime struct{}

func (Runtime) Install(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Runtime) Verify(context.Context, base.Config) error   { return base.ErrNotImplemented }
func (Runtime) Remove(context.Context, base.Config) error   { return base.ErrNotImplemented }
func (Runtime) Rollback(context.Context, base.Config) error { return base.ErrNotImplemented }

type Network struct{}

func (Network) Apply(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Network) Verify(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Network) Remove(context.Context, base.Config) error { return base.ErrNotImplemented }

type Services struct{}

func (Services) Install(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Services) Verify(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Services) Remove(context.Context, base.Config) error  { return base.ErrNotImplemented }

type Launchers struct{}

func (Launchers) Install(context.Context, base.Config) error { return base.ErrNotImplemented }
func (Launchers) Verify(context.Context, base.Config) error  { return base.ErrNotImplemented }
func (Launchers) Remove(context.Context, base.Config) error  { return base.ErrNotImplemented }

type Review struct{}

func (Review) Prepare(context.Context, base.Config, string) (base.ReviewResult, error) {
	return base.ReviewResult{}, base.ErrNotImplemented
}

func Backends() base.Backends {
	return base.Backends{
		Host: Host{}, Users: Users{}, ACL: ACL{}, Runtime: Runtime{},
		Sandbox: Sandbox{}, Network: Network{}, Services: Services{},
		Launchers: Launchers{}, Review: Review{},
	}
}
