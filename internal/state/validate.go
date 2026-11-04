package state

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

var resourceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

func (s State) Validate() error {
	var problems []error
	if s.Version != Version {
		problems = append(problems, fmt.Errorf("unsupported state version %d", s.Version))
	}
	if s.Platform != "linux" && s.Platform != "darwin" {
		problems = append(problems, fmt.Errorf("unsupported state platform %q", s.Platform))
	}
	if err := s.Config.Validate(); err != nil {
		problems = append(problems, fmt.Errorf("invalid config: %w", err))
	}
	problems = append(problems, s.validateBackend()...)
	problems = append(problems, s.validateShared()...)
	problems = append(problems, s.validateRuntime()...)
	problems = append(problems, s.validateServices()...)
	problems = append(problems, s.validateBackups()...)
	if s.Created.User != "" && s.Created.User != s.Config.AIUser {
		problems = append(problems, errors.New("created user does not match configured AI user"))
	}
	if s.Firewall != nil {
		if !resourceNamePattern.MatchString(s.Firewall.Type) || !resourceNamePattern.MatchString(s.Firewall.Table) {
			problems = append(problems, errors.New("firewall type and table must be valid resource names"))
		}
	}
	return errors.Join(problems...)
}

func (s State) validateBackend() []error {
	switch s.Platform {
	case "linux":
		if s.Backend != "bwrap" {
			return []error{fmt.Errorf("linux state requires bwrap backend, got %q", s.Backend)}
		}
		if s.Config.Backend == "vm" {
			return []error{errors.New("linux state config cannot select VM backend")}
		}
	case "darwin":
		if s.Backend != "seatbelt" && s.Backend != "vm" {
			return []error{fmt.Errorf("macOS state requires seatbelt or vm backend, got %q", s.Backend)}
		}
		if (s.Backend == "seatbelt" && s.Config.Backend == "vm") ||
			(s.Backend == "vm" && s.Config.Backend == "native") {
			return []error{errors.New("state backend and configured backend disagree")}
		}
	default:
		return nil
	}
	return nil
}

func (s State) validateShared() []error {
	var problems []error
	if err := config.ValidatePath(s.Shared.Path); err != nil {
		problems = append(problems, fmt.Errorf("shared path: %w", err))
	} else if s.Shared.Path != s.Config.SharedDir {
		problems = append(problems, errors.New("shared path does not match config"))
	}
	if s.Shared.ACL == "" {
		problems = append(problems, errors.New("shared ACL mechanism is required"))
	}
	if s.Platform == "linux" && s.Shared.Alias == "" {
		problems = append(problems, errors.New("linux shared alias is required"))
	}
	if s.Shared.Alias != "" {
		if err := config.ValidatePath(s.Shared.Alias); err != nil {
			problems = append(problems, fmt.Errorf("shared alias: %w", err))
		} else if s.Shared.Alias != s.Config.SharedSource {
			problems = append(problems, errors.New("shared alias does not match config"))
		}
	}
	return problems
}

func (s State) validateRuntime() []error {
	var problems []error
	if err := config.ValidatePath(s.Runtime.Path); err != nil {
		problems = append(problems, fmt.Errorf("runtime path: %w", err))
	} else if s.Runtime.Path != s.Config.RuntimeRoot {
		problems = append(problems, errors.New("runtime path does not match config"))
	}
	if len(s.Runtime.CLIs) == 0 {
		problems = append(problems, errors.New("runtime CLI list is required"))
	}
	configured := make(map[string]bool, len(s.Config.CLIs))
	for _, cli := range s.Config.CLIs {
		configured[cli] = true
	}
	seen := make(map[string]bool, len(s.Runtime.CLIs))
	for _, cli := range s.Runtime.CLIs {
		if !configured[cli] {
			problems = append(problems, fmt.Errorf("runtime CLI %q is not configured", cli))
		}
		if seen[cli] {
			problems = append(problems, fmt.Errorf("duplicate runtime CLI %q", cli))
		}
		seen[cli] = true
	}
	return problems
}

func (s State) validateServices() []error {
	var problems []error
	seen := make(map[string]bool, len(s.Services))
	for _, service := range s.Services {
		if !resourceNamePattern.MatchString(service.Name) {
			problems = append(problems, fmt.Errorf("invalid service name %q", service.Name))
		}
		if seen[service.Name] {
			problems = append(problems, fmt.Errorf("duplicate service %q", service.Name))
		}
		seen[service.Name] = true
		if err := config.ValidatePath(service.Path); err != nil {
			problems = append(problems, fmt.Errorf("service %s path: %w", service.Name, err))
		}
	}
	return problems
}

func (s State) validateBackups() []error {
	var problems []error
	seen := make(map[string]bool, len(s.Backups))
	for _, backup := range s.Backups {
		if err := config.ValidatePath(backup.Source); err != nil {
			problems = append(problems, fmt.Errorf("backup source: %w", err))
		}
		if err := config.ValidatePath(backup.Path); err != nil {
			problems = append(problems, fmt.Errorf("backup path: %w", err))
		}
		if backup.Source == backup.Path {
			problems = append(problems, errors.New("backup source and path must differ"))
		}
		if backup.Path == s.Config.StatePath {
			problems = append(problems, errors.New("backup must not replace active state"))
		}
		if seen[backup.Path] {
			problems = append(problems, fmt.Errorf("duplicate backup path %q", backup.Path))
		}
		seen[backup.Path] = true
	}
	return problems
}
