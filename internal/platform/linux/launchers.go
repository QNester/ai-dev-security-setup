package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
)

type Launchers struct{ Deps Deps }

func (l Launchers) Install(ctx context.Context, cfg config.Config) error {
	executable, err := l.executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(services.LibexecDir, 0o755); err != nil {
		return fmt.Errorf("create libexec directory: %w", err)
	}
	if info, err := os.Lstat(services.LibexecDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("libexec directory must be a real directory")
	}
	if err := os.Chown(services.LibexecDir, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(services.LibexecDir, 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		return fmt.Errorf("read sandboxctl executable: %w", err)
	}
	if err := backupFile(services.BackupRoot, services.LibexecPath); err != nil {
		return err
	}
	if err := fsx.AtomicWriteFile(services.LibexecPath, data, 0o755); err != nil {
		return fmt.Errorf("install sandboxctl: %w", err)
	}
	if info, err := os.Lstat(services.LauncherDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("launcher directory must be a real directory")
	}
	selected := make(map[string]bool, len(cfg.CLIs)+1)
	for _, cli := range cfg.CLIs {
		selected[services.LauncherPath(cli)] = true
	}
	review := contains(cfg.CLIs, "claude")
	if review {
		selected[services.ReviewLauncher] = true
	}
	for _, path := range services.AllLaunchers() {
		if !selected[path] {
			if err := removeLink(path); err != nil {
				return err
			}
		}
	}
	for _, cli := range cfg.CLIs {
		if err := replaceSymlink(services.LauncherPath(cli), services.LibexecPath); err != nil {
			return fmt.Errorf("install %s launcher: %w", cli, err)
		}
	}
	if review {
		if err := replaceSymlink(services.ReviewLauncher, services.LibexecPath); err != nil {
			return fmt.Errorf("install review launcher: %w", err)
		}
	}
	return l.Verify(ctx, cfg)
}

func (l Launchers) executable() (string, error) {
	path := l.Deps.Executable
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", fmt.Errorf("sandboxctl executable has an unsafe path")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("sandboxctl executable is not executable")
	}
	return resolved, nil
}

func (l Launchers) Verify(ctx context.Context, cfg config.Config) error {
	info, err := os.Lstat(services.LibexecPath)
	if err != nil {
		return fmt.Errorf("inspect sandboxctl: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("sandboxctl has unsafe permissions")
	}
	if uid, ok := fileInfoOwner(info); !ok || uid != 0 {
		return fmt.Errorf("sandboxctl must be owned by root")
	}
	paths := make([]string, 0, len(cfg.CLIs)+1)
	for _, cli := range cfg.CLIs {
		paths = append(paths, services.LauncherPath(cli))
	}
	if contains(cfg.CLIs, "claude") {
		paths = append(paths, services.ReviewLauncher)
	}
	for _, path := range paths {
		linkInfo, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("launcher %s is missing: %w", path, err)
		}
		if linkInfo.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("launcher %s is not a symlink", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if target != services.LibexecPath {
			return fmt.Errorf("launcher %s points to %s", path, target)
		}
		if uid, ok := fileInfoOwner(linkInfo); !ok || uid != 0 {
			return fmt.Errorf("launcher %s is not owned by root", path)
		}
	}
	return nil
}

func (l Launchers) Remove(ctx context.Context, cfg config.Config) error {
	var first error
	for _, path := range services.AllLaunchers() {
		if err := removeLink(path); err != nil && first == nil {
			first = err
		}
	}
	if err := removeLink(services.LibexecPath); err != nil && first == nil {
		first = err
	}
	return first
}

func removeLink(path string) error {
	info, err := os.Lstat(path)
	if isNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to remove directory %s", path)
	}
	if err := os.Remove(path); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}
