package state

import "testing"

func TestPlatformStateValidation(t *testing.T) {
	tests := map[string]func(*State){
		"created group": func(s *State) { s.Created.Group = "bad group" },
		"ACL mechanism": func(s *State) { s.Shared.ACL = "arbitrary" },
		"AI home":       func(s *State) { s.Config.AIHome = "/Users/ai-dev" },
		"owner home":    func(s *State) { s.Config.OwnerHome = "/Users/alice" },
		"tmp root":      func(s *State) { s.Config.TmpRoot = "/private/var/lib/ai-sandbox/tmp" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			st := testState()
			mutate(&st)
			if err := st.Validate(); err == nil {
				t.Fatal("expected platform state validation error")
			}
		})
	}
}
