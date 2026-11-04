package state

import (
	"encoding/json"
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
		Created:  Created{User: "ai-dev", Group: "ai-dev"},
		Shared: Shared{
			Path: "/home/alice/Developer", ACL: "setfacl", Alias: "/srv/ai-dev-shared",
		},
		Services: []Service{{
			Name: "ai-dev-isolation.service", Path: "/etc/systemd/system/ai-dev-isolation.service",
		}},
		Runtime: Runtime{Path: "/opt/ai-tools", CLIs: []string{"claude"}},
	}
}

func testStateAt(path string) State {
	st := testState()
	st.Config.StatePath = path
	return st
}

func TestSaveLoadBackupRestore(t *testing.T) {
	dir := stateTestRoot(t)
	store := Store{Path: filepath.Join(dir, "state", "state.json"), Root: dir}
	original := testStateAt(store.Path)
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
	changed.Shared.ACL = "changed"
	if err := store.Save(changed); err == nil {
		t.Fatal("invalid ACL mechanism was accepted")
	}
	if err := store.Restore(backup.Path); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Shared.ACL != "setfacl" {
		t.Fatalf("backup was not restored: %+v", restored)
	}
}

func TestLoadRejectsSymlinkAndMismatchedPath(t *testing.T) {
	dir := stateTestRoot(t)
	path := filepath.Join(dir, "state.json")
	store := Store{Path: path, Root: dir}
	if err := store.Save(testStateAt(path)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: link}).Load(); err == nil {
		t.Fatal("expected symlink error")
	}
	other := testState()
	data, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("state with mismatched config state_path was accepted")
	}
}
