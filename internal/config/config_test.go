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

func TestDarwinDefaultsAllowNativeAccountNamesAndSpaces(t *testing.T) {
	cfg := Default("darwin", "John.Doe", "/Users/John Doe")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.SharedSource != "/Users/Shared/ai-dev-shared" {
		t.Fatalf("unexpected macOS shared source: %s", cfg.SharedSource)
	}
	if cfg.TmpRoot != "/private/var/lib/ai-sandbox/tmp" {
		t.Fatalf("unexpected macOS tmp root: %s", cfg.TmpRoot)
	}
}

func TestStateMustNotOverlapManagedTrees(t *testing.T) {
	for _, path := range []string{
		"/opt/ai-tools/state.json", "/var/lib/ai-sandbox/tmp/state.json", "/srv/ai-dev-shared/state.json",
	} {
		cfg := Default("linux", "alice", "/home/alice")
		cfg.StatePath = path
		if err := cfg.Validate(); err == nil {
			t.Fatalf("state path %s was accepted", path)
		}
	}
}

func TestLiteLLMRequiresHTTPSOffLoopback(t *testing.T) {
	cfg := Default("linux", "alice", "/home/alice")
	cfg.LiteLLMBaseURL = "http://example.com/v1"
	if err := cfg.Validate(); err == nil {
		t.Fatal("plain HTTP off loopback was accepted")
	}
	cfg.LiteLLMBaseURL = "https://example.com/v1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("HTTPS endpoint was rejected: %v", err)
	}
}

func TestReviewSizeHasUpperBound(t *testing.T) {
	cfg := Default("linux", "alice", "/home/alice")
	cfg.MaxReviewBytes = MaxReviewBytesLimit + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("oversized review limit was accepted")
	}
}

func TestValidationErrorsAreDeterministic(t *testing.T) {
	cfg := Default("linux", "alice", "/home/alice")
	cfg.OwnerHome = "relative home"
	cfg.AIHome = "relative ai"
	first := cfg.Validate().Error()
	for range 10 {
		if got := cfg.Validate().Error(); got != first {
			t.Fatalf("error order changed:\n%s\n%s", first, got)
		}
	}
}
