package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
)

type Users struct{ Deps Deps }

func (u Users) EnsureGroup(ctx context.Context, cfg config.Config) (bool, error) {
	created := false
	for _, name := range []string{users.SharedGroup, users.PrimaryGroup(cfg)} {
		if u.Deps.ok(ctx, "dscl", ".", "-read", "/Groups/"+name) {
			continue
		}
		gid, err := nextID(ctx, u.Deps, "/Groups", "PrimaryGroupID")
		if err != nil {
			return false, err
		}
		generated, err := u.Deps.run(ctx, "uuidgen")
		if err != nil {
			return false, err
		}
		for _, args := range [][]string{
			{".", "-create", "/Groups/" + name},
			{".", "-create", "/Groups/" + name, "PrimaryGroupID", strconv.Itoa(gid)},
			{".", "-create", "/Groups/" + name, "RealName", "sandboxctl " + name},
			{".", "-create", "/Groups/" + name, "GeneratedUID", strings.TrimSpace(generated.Stdout)},
		} {
			if _, err := u.Deps.run(ctx, "dscl", args...); err != nil {
				return false, fmt.Errorf("create group %s: %w", name, err)
			}
		}
		created = true
	}
	return created, nil
}

func (u Users) EnsureUser(ctx context.Context, cfg config.Config) (bool, error) {
	created := false
	primary, err := groupID(ctx, u.Deps, cfg.AIUser)
	if err != nil {
		return false, err
	}
	if !u.Deps.ok(ctx, "id", "-u", cfg.AIUser) {
		uid, err := nextID(ctx, u.Deps, "/Users", "UniqueID")
		if err != nil {
			return false, err
		}
		generated, err := u.Deps.run(ctx, "uuidgen")
		if err != nil {
			return false, err
		}
		for _, args := range [][]string{
			{".", "-create", "/Users/" + cfg.AIUser},
			{".", "-create", "/Users/" + cfg.AIUser, "RealName", "Isolated AI development user"},
			{".", "-create", "/Users/" + cfg.AIUser, "UniqueID", strconv.Itoa(uid)},
			{".", "-create", "/Users/" + cfg.AIUser, "PrimaryGroupID", strconv.Itoa(primary)},
			{".", "-create", "/Users/" + cfg.AIUser, "NFSHomeDirectory", cfg.AIHome},
			{".", "-create", "/Users/" + cfg.AIUser, "UserShell", "/usr/bin/false"},
			{".", "-create", "/Users/" + cfg.AIUser, "GeneratedUID", strings.TrimSpace(generated.Stdout)},
		} {
			if _, err := u.Deps.run(ctx, "dscl", args...); err != nil {
				return false, fmt.Errorf("create AI user: %w", err)
			}
		}
		created = true
	}
	for _, args := range [][]string{
		{".", "-create", "/Users/" + cfg.AIUser, "PrimaryGroupID", strconv.Itoa(primary)},
		{".", "-create", "/Users/" + cfg.AIUser, "NFSHomeDirectory", cfg.AIHome},
		{".", "-create", "/Users/" + cfg.AIUser, "UserShell", "/usr/bin/false"},
	} {
		if _, err := u.Deps.run(ctx, "dscl", args...); err != nil {
			return created, fmt.Errorf("secure AI user: %w", err)
		}
	}
	_, _ = u.Deps.run(ctx, "pwpolicy", "-u", cfg.AIUser, "disableuser")
	_, _ = u.Deps.run(ctx, "dseditgroup", "-o", "edit", "-d", cfg.AIUser, "-t", "user", "admin")
	_, _ = u.Deps.run(ctx, "dseditgroup", "-o", "edit", "-a", cfg.AIUser, "-t", "user", users.SharedGroup)
	if err := u.ensureOwnedDirectory(ctx, cfg, cfg.AIHome, 0o700); err != nil {
		return created, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.TmpRoot), 0o755); err != nil {
		return created, err
	}
	if err := u.ensureOwnedDirectory(ctx, cfg, cfg.TmpRoot, 0o700); err != nil {
		return created, err
	}
	if err := u.ensureOwnerKey(ctx, cfg); err != nil {
		return created, err
	}
	return created, nil
}

func (u Users) ensureOwnedDirectory(ctx context.Context, cfg config.Config, path string, mode os.FileMode) error {
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
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a real directory", path)
		}
	} else if isNotExist(err) {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
	} else {
		return err
	}
	ids, err := u.Deps.LookupIDs(ctx, cfg)
	if err != nil {
		return err
	}
	if err := os.Chown(path, int(ids.User), int(ids.Group)); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func (u Users) ensureOwnerKey(ctx context.Context, cfg config.Config) error {
	if err := requireRealPath(cfg.OwnerHome); err != nil {
		return fmt.Errorf("owner home: %w", err)
	}
	directory := filepath.Dir(cfg.OwnerSSHKey)
	env := []string{"HOME=" + cfg.OwnerHome, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	if _, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, "/bin/mkdir", env, []string{"-p", "-m", "700", directory}); err != nil {
		return fmt.Errorf("create owner SSH directory: %w", err)
	}
	if info, err := os.Lstat(cfg.OwnerSSHKey); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("owner SSH key must be a regular file")
		}
		_, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, "/bin/chmod", env, []string{"600", cfg.OwnerSSHKey})
		return err
	} else if !isNotExist(err) {
		return err
	}
	_, err := u.Deps.runAsAccount(ctx, cfg.OwnerUser, cfg.OwnerHome, "/usr/bin/ssh-keygen", env, []string{
		"-q", "-t", "ed25519", "-N", "", "-C", "ai-dev-deploy", "-f", cfg.OwnerSSHKey,
	})
	if err != nil {
		return fmt.Errorf("create owner SSH deploy key: %w", err)
	}
	return nil
}

func (u Users) DeleteUser(ctx context.Context, cfg config.Config) error {
	_, _ = u.Deps.run(ctx, "dscl", ".", "-delete", "/Users/"+cfg.AIUser)
	_ = os.RemoveAll(cfg.AIHome)
	return nil
}

func (u Users) DeleteGroup(ctx context.Context, cfg config.Config) error {
	var problems []error
	for _, name := range []string{users.PrimaryGroup(cfg), users.SharedGroup} {
		if _, err := u.Deps.run(ctx, "dscl", ".", "-delete", "/Groups/"+name); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func (u Users) Verify(ctx context.Context, cfg config.Config) error {
	result, err := u.Deps.run(ctx, "id", "-nG", cfg.AIUser)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, name := range users.SupplementaryGroups(cfg) {
		allowed[name] = true
	}
	for _, name := range strings.Fields(result.Stdout) {
		if !allowed[name] {
			return fmt.Errorf("AI account has unexpected group %q", name)
		}
	}
	shell, err := u.Deps.run(ctx, "dscl", ".", "-read", "/Users/"+cfg.AIUser, "UserShell")
	if err != nil {
		return err
	}
	if !strings.Contains(shell.Stdout, "/usr/bin/false") && !strings.Contains(shell.Stdout, "/usr/bin/nologin") {
		return fmt.Errorf("AI login shell is not disabled")
	}
	policy, err := u.Deps.run(ctx, "pwpolicy", "-u", cfg.AIUser, "-getpolicy")
	if err != nil {
		return fmt.Errorf("inspect AI password policy: %w", err)
	}
	if !strings.Contains(strings.ToLower(policy.Stdout+policy.Stderr), "disabled") {
		return fmt.Errorf("AI account is not disabled")
	}
	ids, err := u.Deps.LookupIDs(ctx, cfg)
	if err != nil {
		return err
	}
	info, err := os.Lstat(cfg.AIHome)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("AI home must be a private real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot inspect AI home ownership")
	}
	if uint32(stat.Uid) != ids.User || uint32(stat.Gid) != ids.Group {
		return fmt.Errorf("AI home ownership does not match the AI account")
	}
	return nil
}

func nextID(ctx context.Context, deps Deps, record, attribute string) (int, error) {
	result, err := deps.run(ctx, "dscl", ".", "-list", record, attribute)
	if err != nil {
		return 0, err
	}
	used := map[int]bool{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.Atoi(fields[1])
		if err == nil {
			used[value] = true
		}
	}
	for id := 501; id < 100000; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, errors.New("no free account ID found")
}

func groupID(ctx context.Context, deps Deps, name string) (int, error) {
	result, err := deps.run(ctx, "dscl", ".", "-read", "/Groups/"+name, "PrimaryGroupID")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(result.Stdout)
	if len(fields) < 2 {
		return 0, fmt.Errorf("cannot parse group ID for %s", name)
	}
	return strconv.Atoi(strings.TrimSuffix(fields[len(fields)-1], ":"))
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
