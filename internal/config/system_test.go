package config

import "testing"

func TestSystemValidationUsesPlatformStateRoots(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		home := "/home/alice"
		if platform == "darwin" {
			home = "/Users/alice"
		}
		cfg := Default(platform, "alice", home)
		if err := cfg.ValidateSystem(platform); err != nil {
			t.Fatalf("%s defaults: %v", platform, err)
		}
		cfg.StatePath = "/tmp/state.json"
		if err := cfg.Validate(); err == nil {
			t.Fatal("direct temporary state path passed structural validation")
		}
		cfg.StatePath = home + "/state.json"
		if err := cfg.Validate(); err == nil {
			t.Fatal("owner-home state path passed structural validation")
		}
		cfg.StatePath = home + "/private/state.json"
		if err := cfg.ValidateSystem(platform); err == nil {
			t.Fatal("non-system state path passed system validation")
		}
	}
}
