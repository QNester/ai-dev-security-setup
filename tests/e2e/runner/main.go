// Command e2e-run orchestrates a disposable Ubuntu guest and runs the e2e test
// binary inside it. It never runs the guest test on a non-disposable host
// without SANDBOXCTL_E2E=1 and the sentinel guard.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type provider interface {
	Prepare(context.Context) error
	Copy(context.Context, string, string) error
	Run(context.Context, []string, []string) error
	Cleanup(context.Context) error
}

type options struct {
	provider   string
	name       string
	ubuntu     string
	arch       string
	sandboxctl string
	e2eTest    string
	keep       bool
	timeout    time.Duration
}

func main() {
	var opts options
	flag.StringVar(&opts.provider, "provider", "hosted", "hosted, lima, or multipass")
	flag.StringVar(&opts.name, "name", "sandboxctl-e2e", "VM instance name")
	flag.StringVar(&opts.ubuntu, "ubuntu", "24.04", "Ubuntu release")
	flag.StringVar(&opts.arch, "arch", runtime.GOARCH, "guest architecture")
	flag.StringVar(&opts.sandboxctl, "sandboxctl", "", "prebuilt Linux sandboxctl binary")
	flag.StringVar(&opts.e2eTest, "e2e-test", "", "prebuilt Linux e2e test binary")
	flag.BoolVar(&opts.keep, "keep", false, "keep the VM for debugging")
	flag.DurationVar(&opts.timeout, "timeout", 30*time.Minute, "overall timeout")
	flag.Parse()

	if opts.arch != "amd64" && opts.arch != "arm64" {
		fatal("unsupported guest architecture %q", opts.arch)
	}
	if os.Getenv("SANDBOXCTL_E2E") != "1" {
		fatal("set SANDBOXCTL_E2E=1 to run destructive e2e tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	bin, testBin, err := artifacts(ctx, opts)
	if err != nil {
		fatal("%v", err)
	}
	var p provider
	switch opts.provider {
	case "hosted":
		if os.Getenv("CI") != "true" {
			fatal("hosted provider is only for disposable CI runners; use lima or multipass locally")
		}
		p = hosted{name: opts.name, sandboxctl: bin, test: testBin}
	case "lima":
		p = lima{name: opts.name, ubuntu: opts.ubuntu, arch: opts.arch, keep: opts.keep}
	case "multipass":
		p = multipass{name: opts.name, ubuntu: opts.ubuntu, keep: opts.keep}
	default:
		fatal("unknown provider %q", opts.provider)
	}
	if err := p.Prepare(ctx); err != nil {
		_ = p.Cleanup(context.Background())
		fatal("prepare: %v", err)
	}
	defer func() {
		if err := p.Cleanup(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup: %v\n", err)
		}
	}()
	guestBin := "/tmp/e2e/sandboxctl"
	guestTest := "/tmp/e2e/e2e.test"
	if opts.provider == "hosted" {
		guestBin = bin
		guestTest = testBin
	} else {
		for _, item := range []struct{ local, guest string }{
			{bin, guestBin}, {testBin, guestTest},
		} {
			if err := p.Copy(ctx, item.local, item.guest); err != nil {
				fatal("copy %s: %v", item.local, err)
			}
		}
	}
	if err := p.Run(ctx, []string{guestTest, "-test.v"}, []string{
		"SANDBOXCTL_E2E=1", "SANDBOXCTL_BIN=" + guestBin,
	}); err != nil {
		fatal("e2e: %v", err)
	}
}

func artifacts(ctx context.Context, opts options) (string, string, error) {
	root, err := findRoot()
	if err != nil {
		return "", "", err
	}
	bin := opts.sandboxctl
	if bin == "" {
		bin = filepath.Join(root, "dist", "sandboxctl-linux-"+opts.arch)
	}
	testBin := opts.e2eTest
	if testBin == "" {
		testBin = filepath.Join(root, "dist", "e2e-linux-"+opts.arch+".test")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		return "", "", err
	}
	if opts.sandboxctl == "" {
		if err := runHost(ctx, root, goBin, []string{"build", "-trimpath", "-o", bin, "./cmd/sandboxctl"}, []string{
			"GOOS=linux", "GOARCH=" + opts.arch, "CGO_ENABLED=0",
		}); err != nil {
			return "", "", err
		}
	}
	if opts.e2eTest == "" {
		if err := runHost(ctx, root, goBin, []string{"test", "-c", "-tags=e2e", "-o", testBin, "./tests/e2e/guest"}, []string{
			"GOOS=linux", "GOARCH=" + opts.arch, "CGO_ENABLED=0",
		}); err != nil {
			return "", "", err
		}
	}
	return bin, testBin, nil
}

func findRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("go.mod not found")
		}
		current = parent
	}
}

func runHost(ctx context.Context, dir, path string, args, env []string) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), env...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func runGuest(ctx context.Context, path string, args []string, env []string) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = append(os.Environ(), env...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "e2e-run: "+format+"\n", args...)
	os.Exit(1)
}

type hosted struct {
	name       string
	sandboxctl string
	test       string
}

func (h hosted) Prepare(ctx context.Context) error {
	if os.Geteuid() == 0 {
		return os.WriteFile("/etc/sandboxctl-e2e", []byte("e2e\n"), 0o600)
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New("hosted e2e requires root or sudo")
	}
	return runGuest(ctx, sudo, []string{"touch", "/etc/sandboxctl-e2e"}, nil)
}

func (hosted) Copy(context.Context, string, string) error { return nil }

func (h hosted) Run(ctx context.Context, argv, env []string) error {
	if os.Geteuid() == 0 {
		return runGuest(ctx, argv[0], argv[1:], env)
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New("hosted e2e requires root or sudo")
	}
	args := []string{"env"}
	args = append(args, env...)
	args = append(args, argv...)
	return runGuest(ctx, sudo, args, nil)
}

func (hosted) Cleanup(context.Context) error {
	if os.Geteuid() == 0 {
		if err := os.Remove("/etc/sandboxctl-e2e"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if sudo, err := exec.LookPath("sudo"); err == nil {
		_ = runGuest(context.Background(), sudo, []string{"rm", "-f", "/etc/sandboxctl-e2e"}, nil)
	}
	return nil
}

type lima struct {
	name   string
	ubuntu string
	arch   string
	keep   bool
}

func (l lima) Prepare(ctx context.Context) error {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return errors.New("limactl is required")
	}
	template := "template://ubuntu-" + l.ubuntu
	if err := runGuest(ctx, limactl, []string{"start", "--name", l.name, "--tty=false", template}, nil); err != nil {
		return err
	}
	if err := runGuest(ctx, limactl, []string{"shell", l.name, "--", "sudo", "mkdir", "-p", "/tmp/e2e"}, nil); err != nil {
		return err
	}
	return runGuest(ctx, limactl, []string{"shell", l.name, "--", "sudo", "touch", "/etc/sandboxctl-e2e"}, nil)
}

func (l lima) Copy(ctx context.Context, local, guest string) error {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return err
	}
	if err := runGuest(ctx, limactl, []string{"copy", local, l.name + ":" + guest}, nil); err != nil {
		return err
	}
	return runGuest(ctx, limactl, []string{"shell", l.name, "--", "sudo", "chmod", "0755", guest}, nil)
}

func (l lima) Run(ctx context.Context, argv, env []string) error {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return err
	}
	args := []string{"shell", l.name, "--", "sudo", "env"}
	args = append(args, env...)
	args = append(args, argv...)
	if err := runGuest(ctx, limactl, args, nil); err != nil {
		return err
	}
	return nil
}

func (l lima) Cleanup(ctx context.Context) error {
	if l.keep {
		return nil
	}
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return err
	}
	return runGuest(ctx, limactl, []string{"delete", "--force", l.name}, nil)
}

type multipass struct {
	name   string
	ubuntu string
	keep   bool
}

func (m multipass) Prepare(ctx context.Context) error {
	multipass, err := exec.LookPath("multipass")
	if err != nil {
		return errors.New("multipass is required")
	}
	if err := runGuest(ctx, multipass, []string{"launch", m.ubuntu, "--name", m.name}, nil); err != nil {
		return err
	}
	if err := runGuest(ctx, multipass, []string{"exec", m.name, "--", "sudo", "mkdir", "-p", "/tmp/e2e"}, nil); err != nil {
		return err
	}
	return runGuest(ctx, multipass, []string{"exec", m.name, "--", "sudo", "touch", "/etc/sandboxctl-e2e"}, nil)
}

func (m multipass) Copy(ctx context.Context, local, guest string) error {
	multipass, err := exec.LookPath("multipass")
	if err != nil {
		return err
	}
	if err := runGuest(ctx, multipass, []string{"transfer", local, m.name + ":" + guest}, nil); err != nil {
		return err
	}
	return runGuest(ctx, multipass, []string{"exec", m.name, "--", "sudo", "chmod", "0755", guest}, nil)
}

func (m multipass) Run(ctx context.Context, argv, env []string) error {
	multipass, err := exec.LookPath("multipass")
	if err != nil {
		return err
	}
	args := []string{"exec", m.name, "--", "sudo", "env"}
	args = append(args, env...)
	args = append(args, argv...)
	return runGuest(ctx, multipass, args, nil)
}

func (m multipass) Cleanup(ctx context.Context) error {
	if m.keep {
		return nil
	}
	multipass, err := exec.LookPath("multipass")
	if err != nil {
		return err
	}
	return runGuest(ctx, multipass, []string{"delete", "--purge", m.name}, nil)
}
