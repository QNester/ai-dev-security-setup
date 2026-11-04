package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

type recordingRunner struct {
	command runner.Command
	err     error
}

func (r *recordingRunner) Run(_ context.Context, command runner.Command) (runner.Result, error) {
	r.command = command
	return runner.Result{}, r.err
}

func options(stdout *bytes.Buffer, runner *recordingRunner) Options {
	return Options{
		GOOS: "darwin", EUID: 1000,
		LookPath: func(name string) (string, error) {
			if name == "brew" {
				return "/opt/homebrew/bin/brew", nil
			}
			return "", errors.New("missing")
		},
		Getenv: func(name string) string {
			switch name {
			case "HOME":
				return "/Users/alice"
			case "USER":
				return "alice"
			default:
				return ""
			}
		},
		Runner: runner,
		Stdout: stdout,
	}
}

func TestFixDarwinDryRunInstallsLima(t *testing.T) {
	var stdout bytes.Buffer
	value := options(&stdout, &recordingRunner{})
	value.DryRun = true
	if err := Fix(context.Background(), value, "auto"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "brew install lima") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestFixDarwinRequiresHomebrew(t *testing.T) {
	var stdout bytes.Buffer
	value := options(&stdout, &recordingRunner{})
	value.LookPath = func(string) (string, error) { return "", errors.New("missing") }
	err := Fix(context.Background(), value, "auto")
	if err == nil || !strings.Contains(err.Error(), "homebrew") {
		t.Fatalf("err=%v", err)
	}
}

func TestFixDarwinExistingProviderIsNoOp(t *testing.T) {
	var stdout bytes.Buffer
	value := options(&stdout, &recordingRunner{})
	value.LookPath = func(name string) (string, error) {
		if name == "limactl" {
			return "/opt/homebrew/bin/limactl", nil
		}
		return "", errors.New("missing")
	}
	if err := Fix(context.Background(), value, "vm"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "already installed") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestFixDarwinNativeNeedsNoVM(t *testing.T) {
	var stdout bytes.Buffer
	if err := Fix(context.Background(), options(&stdout, &recordingRunner{}), "native"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "no VM provider") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func TestFixDarwinRunsHomebrew(t *testing.T) {
	var stdout bytes.Buffer
	value := options(&stdout, &recordingRunner{})
	installed := false
	value.LookPath = func(name string) (string, error) {
		if name == "brew" {
			return "/opt/homebrew/bin/brew", nil
		}
		if name == "limactl" && installed {
			return "/opt/homebrew/bin/limactl", nil
		}
		return "", errors.New("missing")
	}
	value.Runner = &callbackRunner{onRun: func() { installed = true }}
	if err := Fix(context.Background(), value, "auto"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Lima installed") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

type callbackRunner struct{ onRun func() }

func (r *callbackRunner) Run(_ context.Context, command runner.Command) (runner.Result, error) {
	if command.Path != "/opt/homebrew/bin/brew" || strings.Join(command.Args, " ") != "install lima" {
		return runner.Result{}, errors.New("unexpected command")
	}
	if r.onRun != nil {
		r.onRun()
	}
	return runner.Result{}, nil
}
