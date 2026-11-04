package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
)

type Users struct{ Deps Deps }

func (u Users) EnsureGroup(ctx context.Context, cfg config.Config) (bool, error) {
	created := false
	if !u.Deps.ok(ctx, "getent", "group", users.SharedGroup) {
		if _, err := u.Deps.run(ctx, "groupadd", "--system", users.SharedGroup); err != nil {
			return false, fmt.Errorf("create shared group: %w", err)
		}
		created = true
	}
	if !u.Deps.ok(ctx, "getent", "group", users.PrimaryGroup(cfg)) {
		if _, err := u.Deps.run(ctx, "groupadd", "--system", users.PrimaryGroup(cfg)); err != nil {
			return false, fmt.Errorf("create AI primary group: %w", err)
		}
		created = true
	}
	return created, nil
}

func (u Users) EnsureUser(ctx context.Context, cfg config.Config) (bool, error) {
	created := false
	if !u.Deps.ok(ctx, "id", "-u", cfg.AIUser) {
		if _, err := u.Deps.run(ctx, "useradd",
			"--create-home",
			"--gid", users.PrimaryGroup(cfg),
			"--home-dir", cfg.AIHome,
			"--shell", "/bin/bash",
			"--comment", "Isolated AI development user",
			cfg.AIUser,
		); err != nil {
			return false, fmt.Errorf("create AI user: %w", err)
		}
		created = true
	}
	nologin := "/bin/false"
	if path, err := u.Deps.lookPath("nologin"); err == nil {
		nologin = path
	}
	for _, command := range [][]string{
		{"usermod", "-g", users.PrimaryGroup(cfg), cfg.AIUser},
		{"passwd", "-l", cfg.AIUser},
		{"usermod", "-s", nologin, cfg.AIUser},
		{"usermod", "-G", users.SharedGroup, cfg.AIUser},
	} {
		if _, err := u.Deps.run(ctx, command[0], command[1:]...); err != nil {
			return created, fmt.Errorf("secure AI account: %w", err)
		}
	}
	if err := u.ensureOwnedDirectory(cfg, cfg.AIHome, 0o700); err != nil {
		return created, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.TmpRoot), 0o755); err != nil {
		return created, fmt.Errorf("create temporary root parent: %w", err)
	}
	if err := u.ensureOwnedDirectory(cfg, cfg.TmpRoot, 0o700); err != nil {
		return created, err
	}
	if err := u.ensureOwnerKey(ctx, cfg); err != nil {
		return created, err
	}
	return created, nil
}

func (u Users) ensureOwnerKey(ctx context.Context, cfg config.Config) error {
	if err := requireRealPath(cfg.OwnerHome); err != nil {
		return fmt.Errorf("owner home: %w", err)
	}
	directory := filepath.Dir(cfg.OwnerSSHKey)
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("owner SSH directory must be a real directory")
		}
	} else if !isNotExist(err) {
		return err
	}
	mkdir, err := u.Deps.lookPath("mkdir")
	if err != nil {
		return err
	}
	env := []string{"HOME=" + cfg.OwnerHome, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	if _, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, mkdir, env, []string{"-p", "-m", "700", directory}); err != nil {
		return fmt.Errorf("create owner SSH directory: %w", err)
	}
	chmod, err := u.Deps.lookPath("chmod")
	if err != nil {
		return err
	}
	if _, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, chmod, env, []string{"700", directory}); err != nil {
		return fmt.Errorf("secure owner SSH directory: %w", err)
	}
	info, err := os.Lstat(cfg.OwnerSSHKey)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("owner SSH key must be a regular file")
		}
		if _, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, chmod, env, []string{"600", cfg.OwnerSSHKey}); err != nil {
			return fmt.Errorf("secure owner SSH key: %w", err)
		}
		return nil
	}
	if !isNotExist(err) {
		return err
	}
	sshKeygen, err := u.Deps.lookPath("ssh-keygen")
	if err != nil {
		return err
	}
	if _, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, sshKeygen, env, []string{
		"-q", "-t", "ed25519", "-N", "", "-C", "ai-dev-deploy", "-f", cfg.OwnerSSHKey,
	}); err != nil {
		return fmt.Errorf("create owner SSH deploy key: %w", err)
	}
	return nil
}

func (u Users) ensureOwnedDirectory(cfg config.Config, path string, mode os.FileMode) error {
	if parent := filepath.Dir(path); parent != "/" {
		if info, err := os.Lstat(parent); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("parent of %s must be a real directory", path)
			}
		} else if !isNotExist(err) {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s must be a real directory", path)
		}
	} else if isNotExist(err) {
		if err := os.MkdirAll(path, mode); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
	} else {
		return err
	}
	ids, err := u.Deps.LookupIDs(cfg)
	if err != nil {
		return err
	}
	if err := os.Chown(path, int(ids.User), int(ids.Group)); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func (u Users) DeleteUser(ctx context.Context, cfg config.Config) error {
	if !u.Deps.ok(ctx, "id", "-u", cfg.AIUser) {
		return nil
	}
	if _, err := u.Deps.run(ctx, "userdel", "-r", cfg.AIUser); err != nil {
		return fmt.Errorf("remove AI user: %w", err)
	}
	if u.Deps.ok(ctx, "getent", "group", users.PrimaryGroup(cfg)) {
		if _, err := u.Deps.run(ctx, "groupdel", users.PrimaryGroup(cfg)); err != nil {
			return fmt.Errorf("remove AI primary group: %w", err)
		}
	}
	return nil
}

func (u Users) DeleteGroup(ctx context.Context, cfg config.Config) error {
	var problems []error
	for _, name := range []string{users.PrimaryGroup(cfg), users.SharedGroup} {
		if !u.Deps.ok(ctx, "getent", "group", name) {
			continue
		}
		if _, err := u.Deps.run(ctx, "groupdel", name); err != nil {
			problems = append(problems, fmt.Errorf("remove group %s: %w", name, err))
		}
	}
	return errors.Join(problems...)
}

func (u Users) Verify(ctx context.Context, cfg config.Config) error {
	result, err := u.Deps.run(ctx, "id", "-nG", cfg.AIUser)
	if err != nil {
		return fmt.Errorf("inspect AI groups: %w", err)
	}
	allowed := map[string]bool{}
	for _, name := range users.SupplementaryGroups(cfg) {
		allowed[name] = true
	}
	for _, name := range strings.Fields(result.Stdout) {
		if !allowed[name] {
			return fmt.Errorf("AI account has unexpected supplementary group %q", name)
		}
	}
	ids, err := u.Deps.LookupIDs(cfg)
	if err != nil {
		return err
	}
	if ids.User == 0 || ids.Group == 0 {
		return fmt.Errorf("AI account must not use root IDs")
	}
	info, err := os.Lstat(cfg.AIHome)
	if err != nil {
		return fmt.Errorf("inspect AI home: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("AI home must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("AI home must not be accessible by group or other")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect AI home ownership")
	}
	if uint32(stat.Uid) != ids.User || uint32(stat.Gid) != ids.Group {
		return fmt.Errorf("AI home ownership does not match the AI account")
	}
	if _, err := u.Deps.run(ctx, "getent", "group", users.SharedGroup); err != nil {
		return fmt.Errorf("shared group is missing: %w", err)
	}
	sharedGroup, err := user.LookupGroup(users.SharedGroup)
	if err != nil {
		return fmt.Errorf("look up shared group: %w", err)
	}
	if sharedGroup.Gid == "0" {
		return fmt.Errorf("shared group must not use GID 0")
	}
	status, err := u.Deps.run(ctx, "passwd", "-S", cfg.AIUser)
	if err != nil {
		return fmt.Errorf("inspect AI password status: %w", err)
	}
	fields := strings.Fields(status.Stdout)
	if len(fields) < 2 || fields[1] != "L" {
		return fmt.Errorf("AI account password is not locked")
	}
	account, err := u.Deps.run(ctx, "getent", "passwd", cfg.AIUser)
	if err != nil {
		return fmt.Errorf("inspect AI passwd entry: %w", err)
	}
	entry := strings.Split(strings.TrimSpace(account.Stdout), ":")
	if len(entry) < 7 {
		return fmt.Errorf("AI passwd entry is malformed")
	}
	if entry[6] != "/usr/sbin/nologin" && entry[6] != "/sbin/nologin" && entry[6] != "/bin/false" {
		return fmt.Errorf("AI login shell is not disabled: %s", entry[6])
	}
	return nil
}
