// Package darwin implements best-effort native macOS adapters.
package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/templates"
)

const defaultSandboxExec = "/usr/bin/sandbox-exec"

type Sandbox struct {
	SandboxExec string
}

func (Sandbox) Name() string { return "seatbelt" }

func (s Sandbox) Available(context.Context) error {
	info, err := os.Stat(s.execPath())
	if err != nil {
		return fmt.Errorf("sandbox-exec is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("sandbox-exec is not executable")
	}
	return nil
}

func (s Sandbox) Wrap(ctx context.Context, spec base.Spec) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if !spec.Review {
		return nil, base.ErrNotImplemented
	}
	if spec.ReviewFD >= 0 {
		return nil, errors.New("descriptor review is not available on macOS; use staged review")
	}
	if spec.ReviewPath == "" {
		return nil, errors.New("macOS review requires a staged input path")
	}
	if err := s.Available(ctx); err != nil {
		return nil, err
	}
	profile, err := renderReviewProfile(spec)
	if err != nil {
		return nil, err
	}
	argv := []string{s.execPath(), "-p", profile}
	return append(argv, spec.Argv...), nil
}

func (s Sandbox) execPath() string {
	if s.SandboxExec != "" {
		return s.SandboxExec
	}
	return defaultSandboxExec
}

func renderReviewProfile(spec base.Spec) (string, error) {
	data, err := templates.FS.ReadFile("darwin/ai-review.sb")
	if err != nil {
		return "", err
	}
	tmpRule := ""
	if spec.Tmp != "" {
		tmpRule = fmt.Sprintf(" (subpath %q)", spec.Tmp)
	}
	values := map[string]any{
		"Program":     spec.Argv[0],
		"RuntimeRoot": filepath.Dir(filepath.Dir(spec.Argv[0])),
		"AIHome":      spec.Home,
		"ReviewDir":   filepath.Dir(spec.ReviewPath),
		"ReviewPath":  spec.ReviewPath,
		"TmpRule":     tmpRule,
	}
	tmpl, err := template.New("ai-review.sb").Option("missingkey=error").Parse(string(data))
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, values); err != nil {
		return "", err
	}
	return output.String(), nil
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

func Backends() base.Backends {
	return base.Backends{
		Host: Host{}, Users: Users{}, ACL: ACL{}, Runtime: Runtime{},
		Sandbox: Sandbox{}, Network: Network{}, Services: Services{},
		Launchers: Launchers{}, Review: Review{},
	}
}
