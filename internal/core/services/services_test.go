package services

import "testing"

func TestLauncherPathsAreRootOwnedLocations(t *testing.T) {
	if LauncherPath("claude") != "/usr/local/bin/claude-secure" {
		t.Fatalf("unexpected launcher path: %s", LauncherPath("claude"))
	}
	if LibexecPath != "/usr/local/libexec/sandboxctl" {
		t.Fatalf("unexpected libexec path: %s", LibexecPath)
	}
}

func TestServiceRecordsIncludeFirewallAndAppArmor(t *testing.T) {
	paths := map[string]bool{}
	for _, record := range ServiceRecords() {
		paths[record.Path] = true
	}
	for _, wanted := range []string{UnitPath, NftablesDropIn, AppArmorProfile} {
		if !paths[wanted] {
			t.Fatalf("missing service record %s", wanted)
		}
	}
}
