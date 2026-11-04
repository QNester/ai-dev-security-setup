package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

func testState() State {
	return State{
		Version:  Version,
		Platform: "linux",
		Backend:  "bwrap",
		Config:   config.Default("linux", "alice", "/home/alice"),
		Runtime: Runtime{
			Path: "/opt/ai-tools",
			CLIs: []string{"claude"},
		},
	}
}

func TestSaveLoadBackupRestore(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "state", "state.json")}
	original := testState()
	if err := store.Save(original); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Backend != "bwrap" || loaded.Config.AIUser != "ai-dev" {
		t.Fatalf("unexpected state: %+v", loaded)
	}
	backup, err := store.Backup()
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.Backend = "changed"
	if err := store.Save(changed); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(backup.Path); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Backend != "bwrap" {
		t.Fatalf("backup was not restored: %+v", restored)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store := Store{Path: path}
	if err := store.Save(testState()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: link}).Load(); err == nil {
		t.Fatal("expected symlink error")
	}
}
