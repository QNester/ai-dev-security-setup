package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const MaxReviewBytesLimit = 64 * 1024 * 1024

var (
	aiUsernamePattern    = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
	ownerUsernamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	pathPattern          = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	modelPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)
)

func (c Config) Validate() error {
	var problems []error
	if c.Version != Version {
		problems = append(problems, fmt.Errorf("unsupported config version %d", c.Version))
	}
	if !aiUsernamePattern.MatchString(c.AIUser) || c.AIUser == "root" {
		problems = append(problems, errors.New("ai_user must be a valid non-root account name"))
	}
	if !ownerUsernamePattern.MatchString(c.OwnerUser) || strings.EqualFold(c.OwnerUser, "root") {
		problems = append(problems, errors.New("owner_user must be a valid non-root account name"))
	}
	if strings.EqualFold(c.AIUser, c.OwnerUser) {
		problems = append(problems, errors.New("AI and owner accounts must differ"))
	}
	absolutePaths := []struct{ name, value string }{
		{"owner_home", c.OwnerHome}, {"shared_dir", c.SharedDir}, {"owner_ssh_key", c.OwnerSSHKey},
	}
	for _, item := range absolutePaths {
		if err := ValidatePath(item.value); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", item.name, err))
		}
	}
	restrictedPaths := []struct{ name, value string }{
		{"ai_home", c.AIHome}, {"shared_source", c.SharedSource},
		{"runtime_root", c.RuntimeRoot}, {"tmp_root", c.TmpRoot},
	}
	for _, item := range restrictedPaths {
		if err := validateRestrictedPath(item.value); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", item.name, err))
		}
	}
	if err := ValidatePath(c.StatePath); err != nil {
		problems = append(problems, fmt.Errorf("state_path: %w", err))
	}
	if len(c.CLIs) == 0 {
		problems = append(problems, errors.New("at least one CLI is required"))
	}
	seen := make(map[string]bool, len(c.CLIs))
	for _, cli := range c.CLIs {
		if !supportedCLI(cli) {
			problems = append(problems, fmt.Errorf("unsupported CLI %q", cli))
		}
		if seen[cli] {
			problems = append(problems, fmt.Errorf("duplicate CLI %q", cli))
		}
		seen[cli] = true
	}
	switch c.Backend {
	case "auto", "native", "vm":
	default:
		problems = append(problems, fmt.Errorf("unsupported backend %q", c.Backend))
	}
	if c.MaxReviewBytes <= 0 || c.MaxReviewBytes > MaxReviewBytesLimit {
		problems = append(problems, fmt.Errorf("max_review_bytes must be between 1 and %d", MaxReviewBytesLimit))
	}
	if err := validateLiteLLMURL(c.LiteLLMBaseURL); err != nil {
		problems = append(problems, err)
	}
	if len(c.LiteLLMModels) == 0 {
		problems = append(problems, errors.New("at least one LiteLLM model is required"))
	}
	defaultFound := false
	for _, model := range c.LiteLLMModels {
		if !modelPattern.MatchString(model) {
			problems = append(problems, fmt.Errorf("invalid LiteLLM model %q", model))
		}
		defaultFound = defaultFound || model == c.LiteLLMDefaultModel
	}
	if !modelPattern.MatchString(c.LiteLLMDefaultModel) || !defaultFound {
		problems = append(problems, errors.New("LiteLLM default model must be in the model list"))
	}
	problems = append(problems, validateRelationships(c)...)
	return errors.Join(problems...)
}

func validateRelationships(c Config) []error {
	var problems []error
	if overlap(c.AIHome, c.OwnerHome) {
		problems = append(problems, errors.New("AI home and owner home must not overlap"))
	}
	if !within(c.OwnerHome, c.SharedDir) {
		problems = append(problems, errors.New("shared_dir must be inside owner_home"))
	}
	if overlap(c.SharedDir, c.SharedSource) {
		problems = append(problems, errors.New("shared tree and shared alias must not overlap"))
	}
	for _, path := range []string{c.AIHome, c.OwnerHome, c.RuntimeRoot, c.TmpRoot} {
		if overlap(path, c.SharedSource) {
			problems = append(problems, fmt.Errorf("shared_source must not overlap %s", path))
		}
	}
	if !within(c.OwnerHome, c.OwnerSSHKey) || within(c.SharedDir, c.OwnerSSHKey) {
		problems = append(problems, errors.New("owner SSH key must be in owner home outside the shared tree"))
	}
	for _, path := range []string{c.OwnerHome, c.AIHome, c.SharedDir, c.SharedSource, c.TmpRoot} {
		if overlap(path, c.RuntimeRoot) {
			problems = append(problems, fmt.Errorf("runtime_root must not overlap %s", path))
		}
	}
	if overlap(c.AIHome, c.TmpRoot) || overlap(c.SharedDir, c.TmpRoot) {
		problems = append(problems, errors.New("tmp_root must be separate from homes and shared tree"))
	}
	for _, path := range []string{c.AIHome, c.SharedDir, c.RuntimeRoot, c.TmpRoot, c.SharedSource} {
		if overlap(path, c.StatePath) {
			problems = append(problems, fmt.Errorf("state_path must not overlap %s", path))
		}
	}
	for _, protected := range []string{"/etc", "/usr", "/tmp", "/run", "/dev", "/proc", "/sys", "/boot", "/root"} {
		if overlap(protected, c.SharedSource) {
			problems = append(problems, fmt.Errorf("shared_source must not overlap %s", protected))
		}
	}
	return problems
}

func validateRestrictedPath(path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if !pathPattern.MatchString(path) {
		return errors.New("contains unsupported characters")
	}
	return nil
}

func ValidatePath(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("must be absolute")
	}
	if strings.ContainsRune(path, '\x00') || strings.ContainsAny(path, "\r\n") {
		return errors.New("contains control characters")
	}
	if filepath.Clean(path) != path {
		return errors.New("must be clean and contain no traversal")
	}
	return nil
}

func validateLiteLLMURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("litellm_base_url must be an HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("litellm_base_url must not contain credentials, query, or fragment")
	}
	if u.Scheme == "http" && !strings.EqualFold(u.Hostname(), "localhost") {
		address, err := netip.ParseAddr(u.Hostname())
		if err != nil || !address.IsLoopback() {
			return errors.New("litellm_base_url must use HTTPS for non-loopback hosts")
		}
	}
	return nil
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func overlap(a, b string) bool {
	return a == b || within(a, b) || within(b, a)
}
