package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/shared"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
)

const aclRights = "read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity"

type ACL struct{ Deps Deps }

func (a ACL) DenyOwner(ctx context.Context, cfg config.Config) error {
	if err := requireRealPath(cfg.OwnerHome); err != nil {
		return fmt.Errorf("owner home: %w", err)
	}
	if err := a.removeEntry(ctx, cfg.OwnerHome, "user:"+cfg.AIUser); err != nil {
		return err
	}
	entry := "user:" + cfg.AIUser + " deny " + aclRights
	if _, err := a.Deps.run(ctx, "chmod", "+a", entry, cfg.OwnerHome); err != nil {
		return fmt.Errorf("deny AI access to owner home: %w", err)
	}
	return nil
}

func (a ACL) RevokeOwnerDeny(ctx context.Context, cfg config.Config) error {
	return a.removeEntry(ctx, cfg.OwnerHome, "user:"+cfg.AIUser)
}

func (a ACL) GrantShared(ctx context.Context, cfg config.Config) error {
	if err := requireRealPath(cfg.SharedDir); err != nil {
		return fmt.Errorf("shared tree: %w", err)
	}
	if err := a.removeEntry(ctx, cfg.OwnerHome, "user:"+cfg.AIUser); err != nil {
		return err
	}
	entry := "user:" + cfg.AIUser + " allow execute"
	if _, err := a.Deps.run(ctx, "chmod", "+a", entry, cfg.OwnerHome); err != nil {
		return fmt.Errorf("grant execute-only traversal of owner home: %w", err)
	}
	entries := []string{
		"user:" + cfg.AIUser + " allow " + aclRights,
		"user:" + cfg.OwnerUser + " allow " + aclRights,
		"group:" + users.SharedGroup + " allow " + aclRights,
	}
	for _, entry := range entries {
		if _, err := a.Deps.run(ctx, "find", cfg.SharedDir, "-type", "f", "-exec", "chmod", "+a", entry, "{}", "+"); err != nil {
			return fmt.Errorf("apply file ACL: %w", err)
		}
		if _, err := a.Deps.run(ctx, "find", cfg.SharedDir, "-type", "d", "-exec", "chmod", "+a", entry, "{}", "+"); err != nil {
			return fmt.Errorf("apply directory ACL: %w", err)
		}
	}
	for _, entry := range entries {
		inherit := entry + ",file_inherit,directory_inherit"
		if _, err := a.Deps.run(ctx, "find", cfg.SharedDir, "-type", "d", "-exec", "chmod", "+a", inherit, "{}", "+"); err != nil {
			return fmt.Errorf("apply default ACL: %w", err)
		}
	}
	return nil
}

func (a ACL) RevokeShared(ctx context.Context, cfg config.Config) error {
	var problems []error
	if _, err := os.Stat(cfg.SharedDir); err == nil {
		if _, err := a.Deps.run(ctx, "find", cfg.SharedDir, "-type", "f", "-exec", "chmod", "-N", "{}", "+"); err != nil {
			problems = append(problems, fmt.Errorf("remove file ACLs: %w", err))
		}
		if _, err := a.Deps.run(ctx, "find", cfg.SharedDir, "-type", "d", "-exec", "chmod", "-N", "{}", "+"); err != nil {
			problems = append(problems, fmt.Errorf("remove directory ACLs: %w", err))
		}
	}
	if err := a.removeEntry(ctx, cfg.OwnerHome, "user:"+cfg.AIUser); err != nil {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
}

func (a ACL) removeEntry(ctx context.Context, path, name string) error {
	for attempts := 0; attempts < 16; attempts++ {
		result, err := a.Deps.run(ctx, "ls", "-le", path)
		if err != nil {
			return err
		}
		index, found := aclIndex(result.Stdout, name)
		if !found {
			return nil
		}
		if _, err := a.Deps.run(ctx, "chmod", "-a#", strconv.Itoa(index), path); err != nil {
			return fmt.Errorf("remove ACL entry %s from %s: %w", name, path, err)
		}
	}
	return fmt.Errorf("could not remove ACL entry %s from %s", name, path)
}

func hasACL(output, fragment string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func aclIndex(output, name string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, name) {
			continue
		}
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}
		index, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err == nil {
			return index, true
		}
	}
	return 0, false
}

func (a ACL) Verify(ctx context.Context, cfg config.Config) error {
	owner, err := a.Deps.run(ctx, "ls", "-le", cfg.OwnerHome)
	if err != nil {
		return err
	}
	if !hasACL(owner.Stdout, "user:"+cfg.AIUser+" allow execute") {
		return fmt.Errorf("owner home does not grant execute-only traversal to %s", cfg.AIUser)
	}
	result, err := a.Deps.run(ctx, "ls", "-le", cfg.SharedDir)
	if err != nil {
		return err
	}
	if !hasACL(result.Stdout, "user:"+cfg.AIUser+" allow ") {
		return fmt.Errorf("shared tree does not grant access to %s", cfg.AIUser)
	}
	if !hasACL(result.Stdout, "group:"+users.SharedGroup+" allow ") {
		return fmt.Errorf("shared tree does not grant access to %s", users.SharedGroup)
	}
	realShared, err := filepath.EvalSymlinks(cfg.SharedDir)
	if err != nil || !shared.InsideShared(cfg, realShared) {
		return fmt.Errorf("shared tree escaped its configured root")
	}
	return nil
}
