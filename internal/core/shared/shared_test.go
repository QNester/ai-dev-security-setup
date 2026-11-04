package shared

import (
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

func TestACLEntriesCoverOwnerAIAndDefault(t *testing.T) {
	cfg := config.Default("linux", "alice", "/home/alice")
	access := strings.Join(AccessEntries(cfg), ",")
	for _, fragment := range []string{"u:ai-dev:rwX", "u:alice:rwX", "g:ai-dev-share:rwX", "o::---"} {
		if !strings.Contains(access, fragment) {
			t.Fatalf("missing %s in %s", fragment, access)
		}
	}
	defaults := strings.Join(DefaultEntries(cfg), ",")
	if !strings.Contains(defaults, "u::rwX") || !strings.Contains(defaults, "g:ai-dev-share:rwX") {
		t.Fatalf("unexpected defaults: %s", defaults)
	}
}

func TestMapToAliasStaysUnderAlias(t *testing.T) {
	cfg := config.Default("linux", "alice", "/home/alice")
	if got := MapToAlias(cfg, cfg.SharedDir+"/project/file.go"); got != "/srv/ai-dev-shared/project/file.go" {
		t.Fatalf("got %q", got)
	}
	if got := MapToAlias(cfg, "/home/alice/other"); got != cfg.SharedSource {
		t.Fatalf("outside path was not clamped: %q", got)
	}
}
