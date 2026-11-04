package state

import (
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

func TestStateValidationRejectsUnsafeResources(t *testing.T) {
	tests := map[string]func(*State){
		"platform backend mismatch": func(s *State) { s.Backend = "seatbelt" },
		"empty runtime path":        func(s *State) { s.Runtime.Path = "" },
		"foreign runtime path":      func(s *State) { s.Runtime.Path = "/tmp/runtime" },
		"missing CLIs":              func(s *State) { s.Runtime.CLIs = nil },
		"unconfigured CLI":          func(s *State) { s.Runtime.CLIs = []string{"opencode"} },
		"relative service path":     func(s *State) { s.Services[0].Path = "relative" },
		"empty service name":        func(s *State) { s.Services[0].Name = "" },
		"shared mismatch":           func(s *State) { s.Shared.Path = "/tmp/shared" },
		"missing alias":             func(s *State) { s.Shared.Alias = "" },
		"relative backup": func(s *State) {
			s.Backups = []Backup{{Source: "/etc/fstab", Path: "relative"}}
		},
		"backup replaces state": func(s *State) {
			s.Backups = []Backup{{Source: "/etc/fstab", Path: s.Config.StatePath}}
		},
		"created user mismatch": func(s *State) { s.Created.User = "other" },
		"invalid firewall":      func(s *State) { s.Firewall = &Firewall{Type: "nftables", Table: "bad table"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			st := testState()
			mutate(&st)
			if err := st.Validate(); err == nil {
				t.Fatal("expected state validation error")
			}
		})
	}
}

func TestValidDarwinState(t *testing.T) {
	st := testState()
	st.Platform = "darwin"
	st.Backend = "seatbelt"
	st.Config = config.Default("darwin", "John.Doe", "/Users/John Doe")
	st.Shared = Shared{Path: st.Config.SharedDir, ACL: "chmod"}
	st.Runtime.Path = st.Config.RuntimeRoot
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
}
