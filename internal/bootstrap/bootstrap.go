// Package bootstrap installs missing host prerequisites for doctor --fix.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

type Options struct {
	GOOS     string
	EUID     int
	LookPath func(string) (string, error)
	Getenv   func(string) string
	Runner   runner.Runner
	Stdout   io.Writer
	Stderr   io.Writer
	DryRun   bool
}

// Fix installs the missing dependency for the selected backend. It never
// installs Homebrew itself: that requires an interactive vendor script with
// sudo and must remain an explicit operator decision.
func Fix(ctx context.Context, options Options, backend string) error {
	if options.GOOS == "" {
		options.GOOS = "linux"
	}
	if options.LookPath == nil {
		options.LookPath = exec.LookPath
	}
	if options.Getenv == nil {
		options.Getenv = os.Getenv
	}
	if options.Stdout == nil {
		options.Stdout = io.Discard
	}
	if options.Stderr == nil {
		options.Stderr = io.Discard
	}
	if options.Runner == nil {
		options.Runner = runner.OSRunner{}
	}
	switch options.GOOS {
	case "linux":
		return fixLinux(ctx, options, backend)
	case "darwin":
		return fixDarwin(ctx, options, backend)
	default:
		return fmt.Errorf("doctor --fix is not available on %s", options.GOOS)
	}
}

func fixLinux(ctx context.Context, options Options, backend string) error {
	if backend == "vm" {
		return errors.New("the vm backend is not supported on linux")
	}
	if options.DryRun {
		return errors.New("doctor --fix --dry-run is not supported on Linux; run install --dry-run instead")
	}
	if options.EUID != 0 {
		return errors.New("linux package installation requires root; run with sudo")
	}
	host := linux.Host{Deps: linux.Deps{
		Runner: options.Runner, LookPath: options.LookPath, EUID: options.EUID,
	}}
	return host.EnsurePackages(ctx)
}

func fixDarwin(ctx context.Context, options Options, backend string) error {
	if backend == "native" {
		fmt.Fprintln(options.Stdout, "native backend selected; no VM provider is required")
		return nil
	}
	if backend != "" && backend != "auto" && backend != "vm" {
		return fmt.Errorf("unsupported macOS backend %q", backend)
	}
	if macOSVMProvider(options) {
		fmt.Fprintln(options.Stdout, "VM provider is already installed")
		return nil
	}
	brew, err := findBrew(options)
	if err != nil {
		return errors.New("lima is not installed and homebrew was not found; install homebrew from https://brew.sh, then run: brew install lima")
	}
	if options.EUID == 0 {
		return errors.New("homebrew must run as the workstation owner, not root; run doctor --fix without sudo")
	}
	command := []string{brew, "install", "lima"}
	if options.DryRun {
		fmt.Fprintln(options.Stdout, strings.Join(command, " "))
		return nil
	}
	fmt.Fprintln(options.Stdout, "Installing Lima with Homebrew...")
	result, err := options.Runner.Run(ctx, runner.Command{
		Path: brew,
		Args: []string{"install", "lima"},
		Env: []string{
			"HOME=" + options.Getenv("HOME"),
			"USER=" + options.Getenv("USER"),
			"SHELL=/bin/zsh",
			"PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
			"TERM=dumb",
			"HOMEBREW_NO_AUTO_UPDATE=1",
			"HOMEBREW_NO_ANALYTICS=1",
		},
		MaxOutputBytes: 1024 * 1024,
	})
	if err != nil {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.Stdout)
		}
		if detail != "" {
			return fmt.Errorf("install Lima with Homebrew: %w: %s", err, detail)
		}
		return fmt.Errorf("install Lima with Homebrew: %w", err)
	}
	if !macOSVMProvider(options) {
		return errors.New("homebrew finished, but limactl is not on path; open a new shell or add the homebrew bin directory to path")
	}
	fmt.Fprintln(options.Stdout, "Lima installed; re-run doctor")
	return nil
}

func macOSVMProvider(options Options) bool {
	for _, command := range []string{"limactl", "utmctl"} {
		if _, err := options.LookPath(command); err == nil {
			return true
		}
	}
	for _, path := range []string{
		"/opt/homebrew/bin/limactl",
		"/usr/local/bin/limactl",
		"/Applications/UTM.app",
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func findBrew(options Options) (string, error) {
	if path, err := options.LookPath("brew"); err == nil {
		if filepath.IsAbs(path) {
			return path, nil
		}
	}
	for _, path := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("homebrew is not installed")
}
