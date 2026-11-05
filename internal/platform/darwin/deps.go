package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

// Deps are the effectful primitives used by the native macOS adapters.
type Deps struct {
	Runner     runner.Runner
	LookPath   func(string) (string, error)
	Executable string
	EUID       int
}

func (d Deps) runner() runner.Runner {
	if d.Runner != nil {
		return d.Runner
	}
	return runner.OSRunner{}
}

func (d Deps) euid() int {
	if d.EUID != 0 {
		return d.EUID
	}
	return os.Geteuid()
}

func (d Deps) lookPath(name string) (string, error) {
	look := d.LookPath
	if look == nil {
		look = exec.LookPath
	}
	path, err := look(name)
	if err != nil {
		if !strings.ContainsRune(name, filepath.Separator) {
			for _, directory := range []string{
				"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
			} {
				candidate := filepath.Join(directory, name)
				if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
					path = candidate
					err = nil
					break
				}
			}
		}
		if err != nil {
			return "", fmt.Errorf("required command %q is unavailable: %w", name, err)
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("command %q resolved to an unsafe path %q", name, path)
	}
	return path, nil
}

func (d Deps) run(ctx context.Context, name string, args ...string) (runner.Result, error) {
	path, err := d.lookPath(name)
	if err != nil {
		return runner.Result{}, err
	}
	return d.runPath(ctx, "", path, systemEnv(), args...)
}

func (d Deps) runPath(ctx context.Context, dir, path string, env []string, args ...string) (runner.Result, error) {
	result, err := d.runner().Run(ctx, runner.Command{
		Path: path, Args: args, Env: env, Dir: dir, MaxOutputBytes: 256 * 1024,
	})
	if err != nil {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.Stdout)
		}
		if detail != "" {
			return result, fmt.Errorf("run %s: %w: %s", filepath.Base(path), err, detail)
		}
		return result, fmt.Errorf("run %s: %w", filepath.Base(path), err)
	}
	return result, nil
}

func (d Deps) ok(ctx context.Context, name string, args ...string) bool {
	_, err := d.run(ctx, name, args...)
	return err == nil
}

func systemEnv() []string {
	return []string{
		"PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=/var/root",
		"LANG=C.UTF-8",
		"TMPDIR=/tmp",
	}
}

func (d Deps) runAsDir(ctx context.Context, cfg config.Config, dir, program string, env []string, args []string) (runner.Result, error) {
	return d.runAsAccount(ctx, cfg.AIUser, dir, program, env, args)
}

func (d Deps) runAsAccount(ctx context.Context, username, dir, program string, env []string, args []string) (runner.Result, error) {
	if !filepath.IsAbs(program) || filepath.Clean(program) != program {
		return runner.Result{}, fmt.Errorf("program must be a clean absolute path: %q", program)
	}
	current, err := user.Current()
	if err != nil {
		return runner.Result{}, err
	}
	if d.euid() != 0 {
		if current.Username != username {
			return runner.Result{}, fmt.Errorf("must run as root or %s", username)
		}
		return d.runPath(ctx, dir, program, env, args...)
	}
	sudo, err := d.lookPath("sudo")
	if err != nil {
		return runner.Result{}, err
	}
	envPath, err := d.lookPath("env")
	if err != nil {
		return runner.Result{}, err
	}
	commandArgs := []string{"-i"}
	commandArgs = append(commandArgs, env...)
	commandArgs = append(commandArgs, program)
	commandArgs = append(commandArgs, args...)
	runArgs := []string{"-u", username, "--", envPath}
	runArgs = append(runArgs, commandArgs...)
	return d.runPath(ctx, dir, sudo, nil, runArgs...)
}

func (d Deps) LookupIDs(ctx context.Context, cfg config.Config) (users.UID, error) {
	uidResult, err := d.run(ctx, "id", "-u", cfg.AIUser)
	if err != nil {
		return users.UID{}, fmt.Errorf("look up %s: %w", cfg.AIUser, err)
	}
	gidResult, err := d.run(ctx, "id", "-g", cfg.AIUser)
	if err != nil {
		return users.UID{}, fmt.Errorf("look up %s primary group: %w", cfg.AIUser, err)
	}
	groupResult, err := d.run(ctx, "id", "-G", cfg.AIUser)
	if err != nil {
		return users.UID{}, fmt.Errorf("look up %s groups: %w", cfg.AIUser, err)
	}
	uid, err := strconv.ParseUint(strings.TrimSpace(uidResult.Stdout), 10, 32)
	if err != nil {
		return users.UID{}, err
	}
	gid, err := strconv.ParseUint(strings.TrimSpace(gidResult.Stdout), 10, 32)
	if err != nil {
		return users.UID{}, err
	}
	result := users.UID{User: uint32(uid), Group: uint32(gid)}
	for _, value := range strings.Fields(groupResult.Stdout) {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return users.UID{}, err
		}
		result.Aux = append(result.Aux, uint32(parsed))
	}
	if err := users.ValidateIDs(result); err != nil {
		return users.UID{}, err
	}
	return result, nil
}

func fileInfoOwner(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(stat.Uid), true
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
