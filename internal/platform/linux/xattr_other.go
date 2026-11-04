//go:build !linux

package linux

func hasSecurityCapability(string) (bool, error) { return false, nil }
