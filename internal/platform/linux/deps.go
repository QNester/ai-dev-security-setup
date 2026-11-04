package linux

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
	"time"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

// Deps are the effectful primitives used by the Linux adapters. Tests replace
// the command runner and path lookup while production uses the zero value.
type Deps struct {
	Runner     runner.Runner
	LookPath   func(string) (string, error)
	ReadFile   func(string) ([]byte, error)
	Executable string
	EUID       int
}

func (d Deps) runner() runner.Runner {
	if d.Runner != nil {
		return d.Runner
	}
	return runner.OSRunner{}
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
				"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
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

func (d Deps) readFile(path string) ([]byte, error) {
	if d.ReadFile != nil {
		return d.ReadFile(path)
	}
	return os.ReadFile(path)
}

func (d Deps) euid() int {
	if d.EUID != 0 {
		return d.EUID
	}
	return os.Geteuid()
}

// run executes an absolute command with a clean environment. On failure the
// bounded stderr is included so the caller can diagnose permission problems.
func (d Deps) run(ctx context.Context, name string, args ...string) (runner.Result, error) {
	path, err := d.lookPath(name)
	if err != nil {
		return runner.Result{}, err
	}
	return d.runPath(ctx, path, systemEnv(), args...)
}

func systemEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}
}

func (d Deps) runPath(ctx context.Context, path string, env []string, args ...string) (runner.Result, error) {
	return d.runPathDir(ctx, "", path, env, args...)
}

func (d Deps) runPathDir(ctx context.Context, dir, path string, env []string, args ...string) (runner.Result, error) {
	started := time.Now()
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
		return result, fmt.Errorf("run %s after %s: %w", filepath.Base(path), time.Since(started).Round(time.Millisecond), err)
	}
	return result, nil
}

func (d Deps) ok(ctx context.Context, name string, args ...string) bool {
	_, err := d.run(ctx, name, args...)
	return err == nil
}

// runAs executes program as the AI account with exactly the supplied
// environment. It uses runuser when the process is root and otherwise verifies
// that the current account already matches.
func (d Deps) runAs(ctx context.Context, cfg config.Config, program string, env []string, args []string) (runner.Result, error) {
	return d.runAsDir(ctx, cfg, "", program, env, args)
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
		return d.runPathDir(ctx, dir, program, env, args...)
	}
	runuser, err := d.lookPath("runuser")
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
	// The working directory is inherited by runuser and its child.
	return d.runPathDir(ctx, dir, runuser, nil, runArgs...)
}

// LookupIDs resolves the account and its full allowed group set.
func (d Deps) LookupIDs(cfg config.Config) (users.UID, error) {
	account, err := user.Lookup(cfg.AIUser)
	if err != nil {
		return users.UID{}, fmt.Errorf("look up %s: %w", cfg.AIUser, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return users.UID{}, fmt.Errorf("parse UID for %s: %w", cfg.AIUser, err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return users.UID{}, fmt.Errorf("parse GID for %s: %w", cfg.AIUser, err)
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return users.UID{}, fmt.Errorf("read groups for %s: %w", cfg.AIUser, err)
	}
	result := users.UID{User: uint32(uid), Group: uint32(gid)}
	for _, value := range groupIDs {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return users.UID{}, fmt.Errorf("parse group ID %q: %w", value, err)
		}
		result.Aux = append(result.Aux, uint32(parsed))
	}
	if err := users.ValidateIDs(result); err != nil {
		return users.UID{}, err
	}
	return result, nil
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

// fileInfoOwner returns the owning UID for a file. The bool is false when the
// platform does not expose a Unix owner.
func fileInfoOwner(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(stat.Uid), true
}
