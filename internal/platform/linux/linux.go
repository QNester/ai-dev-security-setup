// Package linux implements Linux adapters.
package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

const defaultBwrapPath = "/usr/bin/bwrap"

type Sandbox struct {
	CommandRunner runner.Runner
	BwrapPath     string
}

func (Sandbox) Name() string { return "bwrap" }

func (s Sandbox) Available(ctx context.Context) error {
	_, err := s.commandRunner().Run(ctx, runner.Command{
		Path: s.bwrapPath(),
		Args: []string{"--unshare-user", "--ro-bind", "/", "/", "/usr/bin/true"},
		Env:  []string{"PATH=/usr/bin:/bin"}, MaxOutputBytes: 4096,
	})
	if err != nil {
		return fmt.Errorf("bubblewrap user namespace check: %w", err)
	}
	return nil
}

func (s Sandbox) Wrap(ctx context.Context, spec base.Spec) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.ValidatePath(s.bwrapPath()); err != nil {
		return nil, fmt.Errorf("invalid Bubblewrap path: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := validateMountConflicts(spec); err != nil {
		return nil, err
	}
	args := []string{
		"--die-with-parent", "--new-session",
		"--unshare-user", "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-cgroup",
		"--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev",
	}
	for _, path := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		args = append(args, "--ro-bind", path, path)
	}
	args = append(args, "--tmpfs", "/etc", "--tmpfs", "/home", "--tmpfs", "/run", "--tmpfs", "/var")
	if spec.Tmp != "" {
		args = append(args, "--bind", spec.Tmp, "/tmp")
	} else {
		args = append(args, "--tmpfs", "/tmp")
	}
	if spec.ReviewFD >= 0 {
		args = append(args, "--dir", "/review")
	}
	for _, path := range sortedUnique(spec.ReadOnlyPaths) {
		args = append(args, "--dir", filepath.Dir(path), "--ro-bind", path, path)
	}
	if spec.Home != "" {
		args = append(args, "--dir", filepath.Dir(spec.Home), "--dir", spec.Home, "--bind", spec.Home, spec.Home)
	}
	for _, path := range sortedUnique(spec.WritablePaths) {
		if path == spec.Home || path == spec.Tmp {
			continue
		}
		args = append(args, "--dir", filepath.Dir(path), "--bind", path, path)
	}
	for _, mount := range spec.BindMounts {
		if targetIsDirectory(mount) {
			args = append(args, "--dir", filepath.Dir(mount.Target), "--dir", mount.Target)
		} else {
			args = append(args, "--dir", filepath.Dir(mount.Target))
		}
		flag := "--bind"
		if mount.ReadOnly {
			flag = "--ro-bind"
		}
		args = append(args, flag, mount.Source, mount.Target)
	}
	if spec.ReviewFD >= 0 {
		args = append(args, "--ro-bind-data", strconv.Itoa(spec.ReviewFD), "/review/input")
	}
	keys := make([]string, 0, len(spec.Env))
	for key, value := range spec.Env {
		if !validEnvName(key) || strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("invalid sandbox environment variable %q", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	args = append(args, "--clearenv")
	for _, key := range keys {
		args = append(args, "--setenv", key, spec.Env[key])
	}
	if spec.Cwd != "" {
		args = append(args, "--chdir", spec.Cwd)
	}
	args = append(args, spec.Argv...)
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, s.bwrapPath())
	return append(argv, args...), nil
}

func (s Sandbox) bwrapPath() string {
	if s.BwrapPath != "" {
		return s.BwrapPath
	}
	return defaultBwrapPath
}

func (s Sandbox) commandRunner() runner.Runner {
	if s.CommandRunner != nil {
		return s.CommandRunner
	}
	return runner.OSRunner{}
}

func targetIsDirectory(mount base.BindMount) bool {
	if info, err := os.Stat(mount.Target); err == nil {
		return info.IsDir()
	}
	if info, err := os.Stat(mount.Source); err == nil {
		return info.IsDir()
	}
	return false
}

func sortedUnique(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if !seen[path] {
			seen[path] = true
			result = append(result, path)
		}
	}
	sort.Strings(result)
	return result
}

func validateMountConflicts(spec base.Spec) error {
	readOnly := make(map[string]bool, len(spec.ReadOnlyPaths))
	for _, path := range spec.ReadOnlyPaths {
		readOnly[path] = true
	}
	writable := make(map[string]bool, len(spec.WritablePaths)+len(spec.BindMounts))
	for _, path := range spec.WritablePaths {
		writable[path] = true
	}
	for _, mount := range spec.BindMounts {
		if mount.Target == "" || mount.Source == "" {
			return fmt.Errorf("bind mounts require a source and target")
		}
		if mount.Target == spec.Home || mount.Target == spec.Tmp {
			return fmt.Errorf("bind mount target is already managed: %s", mount.Target)
		}
		if mount.ReadOnly {
			if writable[mount.Target] {
				return fmt.Errorf("bind target is already writable: %s", mount.Target)
			}
			readOnly[mount.Target] = true
			continue
		}
		if readOnly[mount.Target] {
			return fmt.Errorf("path is both read-only and writable: %s", mount.Target)
		}
		writable[mount.Target] = true
	}
	for path := range writable {
		if readOnly[path] {
			return fmt.Errorf("path is both read-only and writable: %s", path)
		}
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" || !(name[0] == '_' || name[0] >= 'A' && name[0] <= 'Z' || name[0] >= 'a' && name[0] <= 'z') {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func Backends() base.Backends { return BackendsWithDeps(Deps{}) }

// BackendsWithDeps keeps the adapter construction explicit for tests.
func BackendsWithDeps(deps Deps) base.Backends {
	return base.Backends{
		Host:      Host{Deps: deps},
		Users:     Users{Deps: deps},
		ACL:       ACL{Deps: deps},
		Runtime:   Runtime{Deps: deps},
		Sandbox:   Sandbox{CommandRunner: deps.Runner},
		Network:   Network{Deps: deps},
		Services:  Services{Deps: deps},
		Launchers: Launchers{Deps: deps},
		Review:    Review{},
	}
}
