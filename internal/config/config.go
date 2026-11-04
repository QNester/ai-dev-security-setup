// Package config defines portable sandbox configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/fsx"
)

const Version = 1

var SupportedCLIs = []string{"claude", "kimi", "pi", "opencode"}

type Config struct {
	Version             int      `json:"version"`
	AIUser              string   `json:"ai_user"`
	OwnerUser           string   `json:"owner_user"`
	OwnerHome           string   `json:"owner_home"`
	AIHome              string   `json:"ai_home"`
	SharedDir           string   `json:"shared_dir"`
	SharedSource        string   `json:"shared_source"`
	RuntimeRoot         string   `json:"runtime_root"`
	TmpRoot             string   `json:"tmp_root"`
	StatePath           string   `json:"state_path"`
	OwnerSSHKey         string   `json:"owner_ssh_key"`
	CLIs                []string `json:"clis"`
	Backend             string   `json:"backend"`
	MaxReviewBytes      int64    `json:"max_review_bytes"`
	LiteLLMBaseURL      string   `json:"litellm_base_url"`
	LiteLLMModels       []string `json:"litellm_models"`
	LiteLLMDefaultModel string   `json:"litellm_default_model"`
}

func Default(platform, ownerUser, ownerHome string) Config {
	aiHome := "/home/ai-dev"
	statePath := "/var/lib/ai-sandbox/state.json"
	if platform == "darwin" {
		aiHome = "/Users/ai-dev"
		statePath = "/Library/Application Support/ai-sandbox/state.json"
	}
	return Config{
		Version:             Version,
		AIUser:              "ai-dev",
		OwnerUser:           ownerUser,
		OwnerHome:           ownerHome,
		AIHome:              aiHome,
		SharedDir:           filepath.Join(ownerHome, "Developer"),
		SharedSource:        "/srv/ai-dev-shared",
		RuntimeRoot:         "/opt/ai-tools",
		TmpRoot:             "/var/lib/ai-sandbox/tmp",
		StatePath:           statePath,
		OwnerSSHKey:         filepath.Join(ownerHome, ".ssh", "ai-dev-deploy"),
		CLIs:                []string{"claude"},
		Backend:             "auto",
		MaxReviewBytes:      1024 * 1024,
		LiteLLMBaseURL:      "http://127.0.0.1:4000/v1",
		LiteLLMModels:       []string{"anthropic/claude-sonnet-4-5"},
		LiteLLMDefaultModel: "anthropic/claude-sonnet-4-5",
	}
}

func ParseCLIList(value string) ([]string, error) {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	seen := make(map[string]bool, len(fields))
	clis := make([]string, 0, len(fields))
	for _, field := range fields {
		name := strings.ToLower(strings.TrimSpace(field))
		if !supportedCLI(name) {
			return nil, fmt.Errorf("unsupported CLI %q", field)
		}
		if !seen[name] {
			seen[name] = true
			clis = append(clis, name)
		}
	}
	if len(clis) == 0 {
		return nil, errors.New("at least one CLI is required")
	}
	return clis, nil
}

func supportedCLI(name string) bool {
	for _, supported := range SupportedCLIs {
		if name == supported {
			return true
		}
	}
	return false
}

func Load(path string) (Config, error) {
	var cfg Config
	file, err := fsx.SafeOpenRegular(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected second JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}
