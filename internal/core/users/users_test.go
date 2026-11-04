package users

import (
	"reflect"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

func TestSupplementaryGroupsReplacePrivilege(t *testing.T) {
	cfg := config.Default("linux", "alice", "/home/alice")
	want := []string{"ai-dev", SharedGroup}
	if got := SupplementaryGroups(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("groups=%v want=%v", got, want)
	}
}

func TestValidateIDsRejectsRoot(t *testing.T) {
	if err := ValidateIDs(UID{User: 0, Group: 1000}); err == nil {
		t.Fatal("UID 0 was accepted")
	}
	if err := ValidateIDs(UID{User: 1001, Group: 0}); err == nil {
		t.Fatal("GID 0 was accepted")
	}
	if err := ValidateIDs(UID{User: 1001, Group: 1001}); err != nil {
		t.Fatal(err)
	}
}
