package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
)

var requiredCommands = []string{
	"chmod", "chown", "curl", "dscl", "dseditgroup", "env", "find", "id",
	"ls", "mkdir", "pgrep", "pkill", "pwpolicy", "sandbox-exec", "ssh-keygen",
	"sudo", "tar", "uuidgen",
}

type Host struct{ Deps Deps }

func (h Host) Prepare(ctx context.Context, cfg config.Config) (bool, error) {
	if err := h.ensureCommands(); err != nil {
		return false, err
	}
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return false, err
	}
	if h.Deps.ok(ctx, "id", "-u", cfg.AIUser) {
		if err := h.verifySandboxExec(ctx, cfg); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (h Host) ensureCommands() error {
	var missing []string
	for _, command := range requiredCommands {
		if _, err := h.Deps.lookPath(command); err != nil {
			missing = append(missing, command)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing macOS commands: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (h Host) ensureIdle(ctx context.Context, cfg config.Config) error {
	result, err := h.Deps.run(ctx, "pgrep", "-u", cfg.AIUser)
	if err != nil {
		return nil
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return fmt.Errorf("stop all %s processes before changing the sandbox", cfg.AIUser)
	}
	return nil
}

func (h Host) verifySandboxExec(ctx context.Context, cfg config.Config) error {
	sandboxExec, err := h.Deps.lookPath("sandbox-exec")
	if err != nil {
		return err
	}
	_, err = h.Deps.runAsAccount(ctx, cfg.AIUser, "", sandboxExec,
		[]string{"PATH=/usr/bin:/bin", "HOME=" + cfg.AIHome, "LANG=C.UTF-8"},
		[]string{"-p", "(version 1)(allow default)", "/usr/bin/true"},
	)
	if err != nil {
		return fmt.Errorf("seatbelt sandbox-exec probe failed: %w", err)
	}
	return nil
}

func (h Host) Verify(ctx context.Context, cfg config.Config) error {
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return err
	}
	if err := h.verifySandboxExec(ctx, cfg); err != nil {
		return err
	}
	info, err := os.Lstat("/usr/bin/sandbox-exec")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("sandbox-exec is missing or not executable")
	}
	return nil
}

func (h Host) VerifyRemoved(ctx context.Context, cfg config.Config) error {
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return err
	}
	paths := append(services.AllLaunchers(),
		services.LibexecPath, cfg.RuntimeRoot, cfg.TmpRoot,
		"/private/var/lib/ai-sandbox-review",
	)
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("resource still exists after uninstall: %s", path)
		} else if !isNotExist(err) {
			return err
		}
	}
	for _, path := range []string{cfg.OwnerHome, cfg.SharedDir} {
		if output, err := h.Deps.run(ctx, "ls", "-le", path); err == nil {
			if _, ok := aclIndex(output.Stdout, "user:"+cfg.AIUser); ok {
				return fmt.Errorf("ACL entry for %s still exists on %s", cfg.AIUser, path)
			}
		}
	}
	return nil
}

func (h Host) RemoveTemporary(_ context.Context, cfg config.Config) error {
	if cfg.TmpRoot != "/private/var/lib/ai-sandbox/tmp" {
		return fmt.Errorf("refusing to remove unexpected temporary root %s", cfg.TmpRoot)
	}
	var problems []error
	for _, path := range []string{cfg.TmpRoot, "/private/var/lib/ai-sandbox-review"} {
		if err := os.RemoveAll(path); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func (h Host) Cleanup(context.Context, config.Config) error { return nil }
