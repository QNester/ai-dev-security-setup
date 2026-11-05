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
	if spec.ReviewFD >= 0 {
		return nil, errors.New("descriptor review is not available on macOS; use staged review")
	}
	if !spec.Review {
		if spec.Workspace == "" || spec.RuntimeRoot == "" {
			return nil, errors.New("macOS sandbox requires workspace and runtime roots")
		}
		if err := s.Available(ctx); err != nil {
			return nil, err
		}
		profile, err := renderEntryProfile(spec)
		if err != nil {
			return nil, err
		}
		argv := []string{s.execPath(), "-p", profile}
		return append(argv, spec.Argv...), nil
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

func renderEntryProfile(spec base.Spec) (string, error) {
	data, err := templates.FS.ReadFile("darwin/ai-sandbox.sb")
	if err != nil {
		return "", err
	}
	values := map[string]any{
		"Program":      spec.Argv[0],
		"RuntimeRoot":  spec.RuntimeRoot,
		"AIHome":       spec.Home,
		"TmpRoot":      spec.Tmp,
		"SharedDir":    spec.Workspace,
		"NetworkRules": "(allow network-outbound)\n(allow mach-lookup)\n(allow sysctl-read)\n(allow process-fork)\n(allow file-read-metadata)",
	}
	tmpl, err := template.New("ai-sandbox.sb").Option("missingkey=error").Parse(string(data))
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, values); err != nil {
		return "", err
	}
	return output.String(), nil
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
		"RuntimeRoot": spec.RuntimeRoot,
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

func Backends() base.Backends { return BackendsWithDeps(Deps{}) }

func BackendsWithDeps(deps Deps) base.Backends {
	return base.Backends{
		Host: Host{Deps: deps}, Users: Users{Deps: deps}, ACL: ACL{Deps: deps},
		Runtime: Runtime{Deps: deps}, Sandbox: Sandbox{}, Network: Network{Deps: deps},
		Services: Services{}, Launchers: Launchers{Deps: deps}, Review: Review{},
	}
}
