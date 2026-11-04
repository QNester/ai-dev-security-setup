package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultValidation(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		cfg := Default(platform, "alice", filepath.Join(map[string]string{
			"linux": "/home", "darwin": "/Users",
		}[platform], "alice"))
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s defaults are invalid: %v", platform, err)
		}
	}
}

func TestValidationRejectsUnsafePaths(t *testing.T) {
	tests := map[string]func(*Config){
		"traversal":            func(c *Config) { c.SharedDir = "/home/alice/../etc" },
		"shared outside home":  func(c *Config) { c.SharedDir = "/srv/projects" },
		"runtime in shared":    func(c *Config) { c.RuntimeRoot = "/home/alice/Developer/tools" },
		"alias overlaps owner": func(c *Config) { c.SharedSource = "/home/alice/alias" },
		"key in shared":        func(c *Config) { c.OwnerSSHKey = "/home/alice/Developer/key" },
		"state in shared":      func(c *Config) { c.StatePath = "/home/alice/Developer/state.json" },
		"root owner":           func(c *Config) { c.OwnerUser = "root" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Default("linux", "alice", "/home/alice")
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestParseCLIList(t *testing.T) {
	clis, err := ParseCLIList("claude, opencode claude")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(clis, ",") != "claude,opencode" {
		t.Fatalf("unexpected selection: %v", clis)
	}
	if _, err := ParseCLIList("claude;id"); err == nil {
		t.Fatal("expected invalid CLI error")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default("linux", "alice", "/home/alice")
	data := []byte(`{"version":1,"unknown":true}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
