//go:build linux

package linux

import (
	"errors"
	"syscall"
)

func hasSecurityCapability(path string) (bool, error) {
	size, err := syscall.Listxattr(path, nil)
	if err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			return false, nil
		}
		return false, err
	}
	if size == 0 {
		return false, nil
	}
	buffer := make([]byte, size)
	size, err = syscall.Listxattr(path, buffer)
	if err != nil {
		return false, err
	}
	for _, name := range splitNUL(buffer[:size]) {
		if name == "security.capability" {
			return true, nil
		}
	}
	return false, nil
}

func splitNUL(value []byte) []string {
	var result []string
	start := 0
	for i, b := range value {
		if b == 0 {
			if i > start {
				result = append(result, string(value[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(value) {
		result = append(result, string(value[start:]))
	}
	return result
}
