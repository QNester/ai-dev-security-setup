// Package fsx contains filesystem operations with fail-closed checks.
package fsx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	return AtomicWriteFileInRoot("/", path, data, mode)
}

func AtomicWriteFileInRoot(root, path string, data []byte, mode os.FileMode) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("atomic write requires a clean absolute root")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("atomic write requires a clean absolute path")
	}
	if !pathWithin(root, path) {
		return errors.New("atomic write path escapes its root")
	}
	parent := filepath.Dir(path)
	if err := checkParentChain(root, parent); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	if err := checkParentChain(root, parent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular file %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(parent, ".sandboxctl-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func checkParentChain(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("parent escapes atomic write root")
	}
	current := root
	for _, component := range append([]string{""}, strings.Split(rel, string(filepath.Separator))...) {
		if component != "" && component != "." {
			current = filepath.Join(current, component)
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := checkDirectory(current, info); err != nil {
			return err
		}
	}
	return nil
}

func checkDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path component is not a real directory: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 || info.Mode()&os.ModeSetgid != 0 {
		return fmt.Errorf("path component is group/other writable or setgid: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine directory owner: %s", path)
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("path component is owned by UID %d: %s", stat.Uid, path)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		if unsupportedDirectorySync(err) {
			return nil
		}
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return directory.Close()
}

func unsupportedDirectorySync(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP)
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
