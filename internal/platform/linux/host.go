package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
	"github.com/QNester/ai-dev-security-setup/internal/templates"
)

const restrictedUsernsPath = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

var requiredCommands = []string{
	"apparmor_parser", "bash", "bwrap", "chgrp", "chmod", "curl", "env", "findmnt",
	"getent", "getfacl", "git", "groupadd", "id", "mkdir", "mount", "nft",
	"passwd", "pgrep", "pkill", "runuser", "setfacl", "sha256sum", "ssh-keygen",
	"sudo", "systemctl", "tar", "umount", "useradd", "userdel", "usermod", "xz",
}

var requiredFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
}

type Host struct{ Deps Deps }

func (h Host) Prepare(ctx context.Context, cfg config.Config) (bool, error) {
	if err := h.ensurePackages(ctx); err != nil {
		return false, err
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return false, fmt.Errorf("a running systemd instance is required")
	}
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return false, err
	}
	restricted, err := h.usernsRestricted()
	if err != nil {
		return false, err
	}
	wroteProfile := false
	if restricted {
		data, err := templates.FS.ReadFile("linux/ai-dev-bwrap.apparmor4")
		if err != nil {
			return false, err
		}
		if err := backupFile(services.BackupRoot, services.AppArmorProfile); err != nil {
			return false, err
		}
		if err := fsx.AtomicWriteFile(services.AppArmorProfile, data, 0o644); err != nil {
			return false, fmt.Errorf("write AppArmor profile: %w", err)
		}
		if _, err := h.Deps.run(ctx, "apparmor_parser", "-r", services.AppArmorProfile); err != nil {
			return false, fmt.Errorf("load AppArmor profile: %w", err)
		}
		wroteProfile = true
	}
	// The account may not exist yet on a first install. Its namespace probe
	// runs in Verify after the account has been created.
	if h.Deps.ok(ctx, "id", "-u", cfg.AIUser) {
		if err := h.verifyBwrap(ctx, cfg); err != nil {
			return wroteProfile, fmt.Errorf("bubblewrap cannot create a user namespace: %w", err)
		}
	}
	return wroteProfile, nil
}

func (h Host) ensurePackages(ctx context.Context) error {
	var missing []string
	for _, command := range requiredCommands {
		if _, err := h.Deps.lookPath(command); err != nil {
			missing = append(missing, command)
		}
	}
	packages := map[string]bool{}
	for _, command := range missing {
		packages[packageFor(command)] = true
	}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); err != nil {
			packages["ca-certificates"] = true
		}
	}
	if len(packages) == 0 {
		return nil
	}
	apt, err := h.Deps.lookPath("apt-get")
	if err != nil {
		detail := strings.Join(missing, ", ")
		if detail == "" {
			detail = "the TLS certificate bundle"
		}
		return fmt.Errorf("missing required components (%s) and apt-get is unavailable", detail)
	}
	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	sort.Strings(names)
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"LANG=C.UTF-8",
	}
	if _, err := h.Deps.runPath(ctx, apt, env, "update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	args := append([]string{"install", "-y", "--no-install-recommends"}, names...)
	if _, err := h.Deps.runPath(ctx, apt, env, args...); err != nil {
		return fmt.Errorf("install prerequisites: %w", err)
	}
	for _, command := range requiredCommands {
		if _, err := h.Deps.lookPath(command); err != nil {
			return fmt.Errorf("required command %q is still unavailable after package installation", command)
		}
	}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); err != nil {
			return fmt.Errorf("required certificate bundle %q is still unavailable", file)
		}
	}
	return nil
}

func packageFor(command string) string {
	switch command {
	case "bwrap":
		return "bubblewrap"
	case "bash":
		return "bash"
	case "git":
		return "git"
	case "xz":
		return "xz-utils"
	case "nft":
		return "nftables"
	case "setfacl", "getfacl":
		return "acl"
	case "curl":
		return "curl"
	case "systemctl":
		return "systemd"
	case "apparmor_parser":
		return "apparmor"
	case "pgrep", "pkill":
		return "procps"
	case "findmnt", "mount", "umount", "runuser":
		return "util-linux"
	case "tar":
		return "tar"
	case "getent":
		return "libc-bin"
	case "passwd", "groupadd", "useradd", "userdel", "usermod":
		return "passwd"
	case "sha256sum", "chgrp", "chmod", "id", "env", "mkdir":
		return "coreutils"
	case "ssh-keygen":
		return "openssh-client"
	default:
		return command
	}
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

func (h Host) verifyBwrap(ctx context.Context, cfg config.Config) error {
	bwrap, err := h.Deps.lookPath("bwrap")
	if err != nil {
		return err
	}
	_, err = h.Deps.runAs(ctx, cfg, bwrap,
		[]string{"PATH=/usr/bin:/bin"},
		[]string{"--unshare-user", "--ro-bind", "/", "/", "/usr/bin/true"},
	)
	return err
}

func (h Host) usernsRestricted() (bool, error) {
	data, err := h.Deps.readFile(restrictedUsernsPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read user-namespace policy: %w", err)
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

func (h Host) Verify(ctx context.Context, cfg config.Config) error {
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return err
	}
	if err := h.verifyBwrap(ctx, cfg); err != nil {
		return fmt.Errorf("bubblewrap user namespaces are unavailable: %w", err)
	}
	restricted, err := h.usernsRestricted()
	if err != nil {
		return err
	}
	if restricted {
		info, err := os.Lstat(services.AppArmorProfile)
		if err != nil {
			return fmt.Errorf("targeted AppArmor profile is missing: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("targeted AppArmor profile has unsafe permissions")
		}
	}
	return nil
}

func (h Host) VerifyRemoved(ctx context.Context, cfg config.Config) error {
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return err
	}
	paths := append(services.AllLaunchers(),
		services.LibexecPath, services.UnitPath, services.NftablesDropIn,
		services.NftFile, services.AppArmorProfile, cfg.RuntimeRoot, cfg.TmpRoot,
	)
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("resource still exists after uninstall: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if h.Deps.ok(ctx, "findmnt", "-M", cfg.SharedSource) {
		return fmt.Errorf("shared alias is still mounted: %s", cfg.SharedSource)
	}
	result, err := h.Deps.run(ctx, "getfacl", "-cp", cfg.OwnerHome)
	if err == nil && hasLine(result.Stdout, "user:"+cfg.AIUser+":---") {
		return fmt.Errorf("owner home still denies %s", cfg.AIUser)
	}
	result, err = h.Deps.run(ctx, "getfacl", "-cp", cfg.SharedDir)
	if err == nil {
		for _, line := range strings.Split(result.Stdout, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "user:"+cfg.AIUser+":") || strings.HasPrefix(line, "default:user:"+cfg.AIUser+":") {
				return fmt.Errorf("shared tree still grants %s", cfg.AIUser)
			}
		}
	}
	return nil
}

func (h Host) RemoveTemporary(ctx context.Context, cfg config.Config) error {
	if cfg.TmpRoot != "/var/lib/ai-sandbox/tmp" && cfg.TmpRoot != "/private/var/lib/ai-sandbox/tmp" {
		return fmt.Errorf("refusing to remove unexpected temporary root %s", cfg.TmpRoot)
	}
	if err := assertNoMounts(ctx, h.Deps, cfg.TmpRoot); err != nil {
		return err
	}
	if err := os.RemoveAll(cfg.TmpRoot); err != nil {
		return fmt.Errorf("remove temporary root: %w", err)
	}
	return nil
}

func (h Host) Cleanup(ctx context.Context, cfg config.Config) error {
	if err := h.ensureIdle(ctx, cfg); err != nil {
		return err
	}
	if info, err := os.Lstat(services.AppArmorProfile); err == nil && info.Mode().IsRegular() {
		_, _ = h.Deps.run(ctx, "apparmor_parser", "-R", services.AppArmorProfile)
		if err := os.Remove(services.AppArmorProfile); err != nil && !isNotExist(err) {
			return fmt.Errorf("remove AppArmor profile: %w", err)
		}
	}
	return nil
}
