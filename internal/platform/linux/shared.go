package linux

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/core/shared"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
)

type ACL struct{ Deps Deps }

func (a ACL) DenyOwner(ctx context.Context, cfg config.Config) error {
	if err := requireRealPath(cfg.OwnerHome); err != nil {
		return fmt.Errorf("owner home: %w", err)
	}
	if _, err := a.Deps.run(ctx, "setfacl", "-m", shared.OwnerHomeDeny(cfg), cfg.OwnerHome); err != nil {
		return fmt.Errorf("deny AI access to owner home: %w", err)
	}
	return nil
}

func (a ACL) RevokeOwnerDeny(ctx context.Context, cfg config.Config) error {
	_, _ = a.Deps.run(ctx, "setfacl", "-x", shared.OwnerHomeDeny(cfg), cfg.OwnerHome)
	return nil
}

func (a ACL) GrantShared(ctx context.Context, cfg config.Config) error {
	if err := requireRealPath(cfg.SharedDir); err != nil {
		return fmt.Errorf("shared tree: %w", err)
	}
	info, err := os.Lstat(cfg.SharedDir)
	if err != nil {
		return fmt.Errorf("inspect shared tree: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("shared tree must be a real directory")
	}
	if err := a.DenyOwner(ctx, cfg); err != nil {
		return err
	}
	access := "-m " + strings.Join(shared.AccessEntries(cfg), ",")
	defaults := "-d -m " + strings.Join(shared.DefaultEntries(cfg), ",")
	err = filepath.WalkDir(cfg.SharedDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("shared tree contains unsupported file type: %s", path)
		}
		if _, err := a.Deps.run(ctx, "chgrp", users.SharedGroup, path); err != nil {
			return fmt.Errorf("set shared group on %s: %w", path, err)
		}
		if _, err := a.Deps.run(ctx, "setfacl", access, path); err != nil {
			return fmt.Errorf("set access ACL on %s: %w", path, err)
		}
		if entry.IsDir() {
			if _, err := a.Deps.run(ctx, "setfacl", defaults, path); err != nil {
				return fmt.Errorf("set default ACL on %s: %w", path, err)
			}
			if _, err := a.Deps.run(ctx, "chmod", "g+s", path); err != nil {
				return fmt.Errorf("set group inheritance on %s: %w", path, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.ensureAlias(ctx, cfg)
}

func (a ACL) ensureAlias(ctx context.Context, cfg config.Config) error {
	if _, err := os.Lstat(cfg.SharedSource); err == nil {
		info, _ := os.Lstat(cfg.SharedSource)
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("shared alias %s must be a real directory", cfg.SharedSource)
		}
	} else if !isNotExist(err) {
		return err
	}
	if parent := filepath.Dir(cfg.SharedSource); parent != "/" {
		if info, err := os.Lstat(parent); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("shared alias parent must be a real directory")
			}
		} else if !isNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(cfg.SharedSource, 0o750); err != nil {
		return fmt.Errorf("create shared alias: %w", err)
	}
	if err := os.Chmod(cfg.SharedSource, 0o750); err != nil {
		return fmt.Errorf("secure shared alias: %w", err)
	}
	mounted := a.Deps.ok(ctx, "findmnt", "-M", cfg.SharedSource)
	if mounted {
		source, err := a.Deps.run(ctx, "findmnt", "-n", "-M", cfg.SharedSource, "-o", "SOURCE")
		if err != nil {
			return fmt.Errorf("inspect shared alias source: %w", err)
		}
		if strings.TrimSpace(source.Stdout) != cfg.SharedDir {
			if _, err := a.Deps.run(ctx, "umount", cfg.SharedSource); err != nil {
				return fmt.Errorf("replace stale shared alias: %w", err)
			}
			mounted = false
		}
	}
	if !mounted {
		if _, err := a.Deps.run(ctx, "mount", "--bind", cfg.SharedDir, cfg.SharedSource); err != nil {
			return fmt.Errorf("bind shared tree: %w", err)
		}
		if _, err := a.Deps.run(ctx, "mount", "-o", "remount,bind,nosuid,nodev", cfg.SharedSource); err != nil {
			return fmt.Errorf("apply alias mount options: %w", err)
		}
	}
	if err := a.updateFstab(cfg); err != nil {
		return err
	}
	options, err := a.Deps.run(ctx, "findmnt", "-n", "-M", cfg.SharedSource, "-o", "OPTIONS")
	if err != nil {
		return fmt.Errorf("inspect shared alias: %w", err)
	}
	if !strings.Contains(options.Stdout, "nosuid") || !strings.Contains(options.Stdout, "nodev") {
		return fmt.Errorf("shared alias is missing nosuid/nodev")
	}
	return nil
}

func (a ACL) updateFstab(cfg config.Config) error {
	if err := backupFile(services.BackupRoot, "/etc/fstab"); err != nil {
		return err
	}
	data, err := os.ReadFile("/etc/fstab")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read /etc/fstab: %w", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	kept := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == cfg.SharedSource {
			continue
		}
		if strings.TrimSpace(line) == "" && len(kept) > 0 && kept[len(kept)-1] == "" {
			continue
		}
		kept = append(kept, line)
	}
	entry := strings.Join([]string{
		cfg.SharedDir, cfg.SharedSource, "none",
		strings.Join(shared.FstabOptions(cfg), ","), "0", "0",
	}, " ")
	kept = append(kept, entry)
	content := strings.Join(kept, "\n") + "\n"
	if err := fsx.AtomicWriteFile("/etc/fstab", []byte(content), 0o644); err != nil {
		return fmt.Errorf("update /etc/fstab: %w", err)
	}
	return nil
}

func (a ACL) RevokeShared(ctx context.Context, cfg config.Config) error {
	var problems []error
	sharedGID := groupID(users.SharedGroup)
	if _, err := os.Stat(cfg.SharedDir); err == nil {
		_ = filepath.WalkDir(cfg.SharedDir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			// ACL entries may already be absent after a partial installation
			// or a previous uninstall; removal is intentionally idempotent.
			_, _ = a.Deps.run(ctx, "setfacl", "-x", "u:"+cfg.AIUser, path)
			_, _ = a.Deps.run(ctx, "setfacl", "-x", "u:"+cfg.OwnerUser, path)
			_, _ = a.Deps.run(ctx, "setfacl", "-x", "g:"+users.SharedGroup, path)
			if entry.IsDir() {
				_, _ = a.Deps.run(ctx, "setfacl", "-k", path)
				if sharedGID >= 0 && fileGID(path) == sharedGID {
					_, _ = a.Deps.run(ctx, "chmod", "g-s", path)
				}
			}
			return nil
		})
	}
	_ = a.RevokeOwnerDeny(ctx, cfg)
	problems = append(problems, a.removeAlias(ctx, cfg))
	return errors.Join(problems...)
}

func (a ACL) removeAlias(ctx context.Context, cfg config.Config) error {
	var problems []error
	if a.Deps.ok(ctx, "findmnt", "-M", cfg.SharedSource) {
		if _, err := a.Deps.run(ctx, "umount", cfg.SharedSource); err != nil {
			problems = append(problems, fmt.Errorf("unmount shared alias: %w", err))
		}
	}
	if err := a.removeFstab(cfg); err != nil {
		problems = append(problems, err)
	}
	if info, err := os.Lstat(cfg.SharedSource); err == nil {
		if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			if err := os.Remove(cfg.SharedSource); err != nil && !isNotExist(err) {
				problems = append(problems, fmt.Errorf("remove shared alias directory: %w", err))
			}
		}
	}
	return errors.Join(problems...)
}

func (a ACL) removeFstab(cfg config.Config) error {
	data, err := os.ReadFile("/etc/fstab")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read /etc/fstab: %w", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == cfg.SharedSource {
			continue
		}
		kept = append(kept, line)
	}
	return fsx.AtomicWriteFile("/etc/fstab", []byte(strings.Join(kept, "\n")+"\n"), 0o644)
}

func (a ACL) Verify(ctx context.Context, cfg config.Config) error {
	result, err := a.Deps.run(ctx, "getfacl", "-cp", cfg.OwnerHome)
	if err != nil {
		return fmt.Errorf("inspect owner home ACL: %w", err)
	}
	wantDeny := "user:" + cfg.AIUser + ":---"
	if !strings.Contains(result.Stdout, wantDeny) {
		return fmt.Errorf("owner home does not deny %s", cfg.AIUser)
	}
	result, err = a.Deps.run(ctx, "getfacl", "-cp", cfg.SharedDir)
	if err != nil {
		return fmt.Errorf("inspect shared ACL: %w", err)
	}
	for _, line := range []string{
		"user:" + cfg.AIUser + ":rwx",
		"group:" + users.SharedGroup + ":rwx",
		"other::---",
		"default:user:" + cfg.AIUser + ":rwx",
		"default:group:" + users.SharedGroup + ":rwx",
		"default:other::---",
	} {
		if !hasLine(result.Stdout, line) {
			return fmt.Errorf("shared ACL is missing %s", line)
		}
	}
	info, err := os.Lstat(cfg.SharedDir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSetgid == 0 {
		return fmt.Errorf("shared tree root is missing setgid")
	}
	if !a.Deps.ok(ctx, "findmnt", "-M", cfg.SharedSource) {
		return fmt.Errorf("shared alias is not mounted")
	}
	options, err := a.Deps.run(ctx, "findmnt", "-n", "-M", cfg.SharedSource, "-o", "OPTIONS")
	if err != nil {
		return err
	}
	if !strings.Contains(options.Stdout, "nosuid") || !strings.Contains(options.Stdout, "nodev") {
		return fmt.Errorf("shared alias is missing nosuid/nodev")
	}
	source, err := a.Deps.run(ctx, "findmnt", "-n", "-M", cfg.SharedSource, "-o", "SOURCE")
	if err != nil {
		return err
	}
	if strings.TrimSpace(source.Stdout) != cfg.SharedDir {
		return fmt.Errorf("shared alias points to %s instead of %s", strings.TrimSpace(source.Stdout), cfg.SharedDir)
	}
	return nil
}

func requireRealPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return fmt.Errorf("must not traverse symlinks: %s resolves to %s", path, resolved)
	}
	return nil
}

func groupID(name string) int {
	group, err := user.LookupGroup(name)
	if err != nil {
		return -1
	}
	value, err := strconv.Atoi(group.Gid)
	if err != nil {
		return -1
	}
	return value
}

func fileGID(path string) int {
	info, err := os.Lstat(path)
	if err != nil {
		return -1
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Gid)
}

func hasLine(output, wanted string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

func backupFile(root, source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read backup source %s: %w", source, err)
	}
	dir := filepath.Join(root, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	destination := filepath.Join(dir, filepath.Base(source))
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		return fmt.Errorf("write backup %s: %w", destination, err)
	}
	return nil
}
