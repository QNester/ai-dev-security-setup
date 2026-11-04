// Package users contains portable account lifecycle policy.
package users

import (
	"fmt"
	"regexp"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

// SharedGroup is the single supplementary group granted to the AI account.
// The account's primary group is always its own group with the same name.
const SharedGroup = "ai-dev-share"

var groupPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// PrimaryGroup returns the dedicated primary group name for the AI account.
func PrimaryGroup(cfg config.Config) string { return cfg.AIUser }

// SupplementaryGroups returns the complete allowed group list. The order is
// significant when replacing an existing supplementary list.
func SupplementaryGroups(cfg config.Config) []string {
	return []string{PrimaryGroup(cfg), SharedGroup}
}

// UID identifies the account's numeric user and group IDs together with all
// allowed supplementary group IDs.
type UID struct {
	User  uint32
	Group uint32
	Aux   []uint32
}

func (u UID) Valid() bool { return u.User != 0 }

// ValidateIDs rejects a resolved account that could act as root or that
// belongs to an unexpected supplementary group.
func ValidateIDs(uid UID) error {
	if uid.User == 0 {
		return fmt.Errorf("AI account resolves to UID 0")
	}
	if uid.Group == 0 {
		return fmt.Errorf("AI primary group resolves to GID 0")
	}
	return nil
}

// ValidateName checks a portable account or group name.
func ValidateName(name string) error {
	if !groupPattern.MatchString(name) || name == "root" {
		return fmt.Errorf("invalid non-root account name %q", name)
	}
	return nil
}
