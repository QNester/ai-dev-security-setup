// Package shared contains portable shared-tree access policy.
package shared

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
)

// AliasOptions are the mount options applied to the root-managed bind alias.
// The user namespace already neutralises privilege bits, but nosuid/nodev are
// defence in depth.
func AliasOptions() []string { return []string{"bind", "nosuid", "nodev"} }

// FstabOptions are the persistent mount options for the shared alias.
func FstabOptions(cfg config.Config) []string {
	return []string{
		"bind", "nosuid", "nodev", "nofail",
		"x-systemd.requires-mounts-for=" + cfg.SharedDir,
	}
}

// AccessEntries returns the POSIX ACL entries for an existing file or
// directory. "X" grants execute only where it already applies.
func AccessEntries(cfg config.Config) []string {
	return []string{
		"u:" + cfg.AIUser + ":rwX",
		"u:" + cfg.OwnerUser + ":rwX",
		"g:" + users.SharedGroup + ":rwX",
		"g::rwX",
		"m::rwX",
		"o::---",
	}
}

// DefaultEntries returns the default ACL entries applied to directories.
func DefaultEntries(cfg config.Config) []string {
	return []string{
		"u::rwX",
		"u:" + cfg.AIUser + ":rwX",
		"u:" + cfg.OwnerUser + ":rwX",
		"g::rwX",
		"g:" + users.SharedGroup + ":rwX",
		"m::rwX",
		"o::---",
	}
}

// OwnerHomeDeny is the explicit ACL that prevents the AI account from
// traversing the owner's home while keeping the shared tree reachable through
// the bind alias.
func OwnerHomeDeny(cfg config.Config) string { return "u:" + cfg.AIUser + ":---" }

// InsideShared reports whether path is the shared tree or a descendant.
func InsideShared(cfg config.Config, path string) bool {
	return path == cfg.SharedDir || strings.HasPrefix(path, cfg.SharedDir+string(filepath.Separator))
}

// MapToAlias converts an absolute path in the real shared tree to the same
// relative path under the alias. It returns the alias root when path is
// outside the shared tree.
func MapToAlias(cfg config.Config, path string) string {
	if !InsideShared(cfg, path) {
		return cfg.SharedSource
	}
	rel, err := filepath.Rel(cfg.SharedDir, path)
	if err != nil || rel == "." {
		return cfg.SharedSource
	}
	return filepath.Join(cfg.SharedSource, rel)
}

// VerifyPath rejects a shared tree that is not a real directory.
func VerifyPath(cfg config.Config) error {
	if !filepath.IsAbs(cfg.SharedDir) || filepath.Clean(cfg.SharedDir) != cfg.SharedDir {
		return fmt.Errorf("shared tree must be a clean absolute path")
	}
	if !InsideShared(cfg, cfg.SharedDir) {
		return fmt.Errorf("shared tree path is invalid")
	}
	return nil
}
