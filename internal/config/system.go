package config

import (
	"errors"
	"fmt"
	"strings"
)

func (c Config) ValidateSystem(platform string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var stateRoot, aiHome, ownerRoot, tmpRoot string
	switch platform {
	case "linux":
		stateRoot = "/var/lib/ai-sandbox"
		aiHome = "/home/" + c.AIUser
		ownerRoot = "/home/"
		tmpRoot = "/var/lib/ai-sandbox/tmp"
	case "darwin":
		stateRoot = "/Library/Application Support/ai-sandbox"
		aiHome = "/Users/" + c.AIUser
		ownerRoot = "/Users/"
		tmpRoot = "/private/var/lib/ai-sandbox/tmp"
	default:
		return fmt.Errorf("unsupported platform %q", platform)
	}
	if !within(stateRoot, c.StatePath) {
		return fmt.Errorf("state_path must be inside %s", stateRoot)
	}
	if c.AIHome != aiHome || !strings.HasPrefix(c.OwnerHome, ownerRoot) || c.TmpRoot != tmpRoot {
		return errors.New("AI home, owner home, or tmp root does not match platform policy")
	}
	if platform == "linux" && !strings.HasPrefix(c.SharedSource, "/srv/") {
		return errors.New("linux shared alias must be under /srv")
	}
	if platform == "darwin" && !strings.HasPrefix(c.SharedSource, "/Users/Shared/") {
		return errors.New("macOS shared alias must be under /Users/Shared")
	}
	return nil
}
