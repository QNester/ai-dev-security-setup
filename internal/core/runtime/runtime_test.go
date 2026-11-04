package runtime

import (
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

func TestCandidatePathRejectsTraversal(t *testing.T) {
	if _, err := CandidatePath("/opt/ai-tools/runtime", "../bin"); err == nil {
		t.Fatal("traversal was accepted")
	}
	if _, err := CandidatePath("relative", ".local/bin/claude"); err == nil {
		t.Fatal("relative root was accepted")
	}
	got, err := CandidatePath("/opt/ai-tools/runtime", ".local/bin/claude")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/opt/ai-tools/runtime/.local/bin/claude" {
		t.Fatalf("got %q", got)
	}
}

func TestInstallerEnvironmentCannotSeeOwnerHome(t *testing.T) {
	cfg := config.Default("linux", "alice", "/home/alice")
	env := strings.Join(InstallerEnv(cfg, "/opt/ai-tools/runtime", "/opt/ai-tools/node"), "\n")
	if strings.Contains(env, "/home/alice") {
		t.Fatalf("installer environment leaked owner home: %s", env)
	}
	if !strings.Contains(env, "HOME=/opt/ai-tools/runtime") {
		t.Fatalf("installer HOME is wrong: %s", env)
	}
}

func TestInstallerForRejectsUnknownCLI(t *testing.T) {
	if _, err := InstallerFor("unknown"); err == nil {
		t.Fatal("unknown CLI was accepted")
	}
}

func TestWritableRootsIncludeAgentLocations(t *testing.T) {
	cfg := config.Default("linux", "alice", "/home/alice")
	roots := strings.Join(WritableRoots(cfg), ",")
	for _, path := range []string{cfg.AIHome, cfg.SharedDir, cfg.SharedSource, cfg.TmpRoot} {
		if !strings.Contains(roots, path) {
			t.Fatalf("missing writable root %s", path)
		}
	}
}
