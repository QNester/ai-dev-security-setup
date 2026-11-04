package state

import (
	"errors"
	"strings"
)

func (s State) validatePlatformPaths() []error {
	var problems []error
	switch s.Platform {
	case "linux":
		if s.Config.AIHome != "/home/"+s.Config.AIUser {
			problems = append(problems, errors.New("linux AI home must be /home/<ai_user>"))
		}
		if !strings.HasPrefix(s.Config.OwnerHome, "/home/") {
			problems = append(problems, errors.New("linux owner home must be under /home"))
		}
		if !strings.HasPrefix(s.Config.SharedSource, "/srv/") {
			problems = append(problems, errors.New("linux shared alias must be under /srv"))
		}
		if s.Config.TmpRoot != "/var/lib/ai-sandbox/tmp" {
			problems = append(problems, errors.New("linux tmp root has an unexpected platform path"))
		}
	case "darwin":
		if s.Config.AIHome != "/Users/"+s.Config.AIUser {
			problems = append(problems, errors.New("macOS AI home must be /Users/<ai_user>"))
		}
		if !strings.HasPrefix(s.Config.OwnerHome, "/Users/") {
			problems = append(problems, errors.New("macOS owner home must be under /Users"))
		}
		if !strings.HasPrefix(s.Config.SharedSource, "/Users/Shared/") {
			problems = append(problems, errors.New("macOS shared source must be under /Users/Shared"))
		}
		if s.Config.TmpRoot != "/private/var/lib/ai-sandbox/tmp" {
			problems = append(problems, errors.New("macOS tmp root has an unexpected platform path"))
		}
	}
	return problems
}
