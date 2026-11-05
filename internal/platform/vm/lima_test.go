package vm

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

type fakeRunner struct {
	commands [][]string
	run      func(runner.Command) (runner.Result, error)
}

func (f *fakeRunner) Run(_ context.Context, command runner.Command) (runner.Result, error) {
	f.commands = append(f.commands, append([]string{command.Path}, command.Args...))
	if f.run != nil {
		return f.run(command)
	}
	return runner.Result{}, nil
}

func limaDeps(fake *fakeRunner) Lima {
	return Lima{
		Runner: fake,
		LookPath: func(name string) (string, error) {
			if name == "limactl" {
				return "/opt/homebrew/bin/limactl", nil
			}
			return "", errors.New("missing")
		},
	}
}

func TestLimaEnsureCreatesInstanceConfig(t *testing.T) {
	var config string
	fake := &fakeRunner{run: func(command runner.Command) (runner.Result, error) {
		switch command.Args[0] {
		case "list":
			return runner.Result{Stdout: "[]\n"}, nil
		case "create":
			data, err := os.ReadFile(command.Args[len(command.Args)-1])
			if err != nil {
				t.Fatal(err)
			}
			config = string(data)
		}
		return runner.Result{}, nil
	}}
	cfg := Config{SharedDir: "/Users/alice/Developer", Arch: "arm64", CPUs: 2}
	if err := (limaDeps(fake)).Ensure(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "/Users/alice/Developer") || strings.Contains(config, "location: \"~\"") {
		t.Fatalf("unexpected lima config:\n%s", config)
	}
	if len(fake.commands) != 2 || fake.commands[1][1] != "create" {
		t.Fatalf("commands=%v", fake.commands)
	}
}

func TestLimaStartSkipsCreateForExistingInstance(t *testing.T) {
	fake := &fakeRunner{run: func(command runner.Command) (runner.Result, error) {
		if command.Args[0] == "list" {
			return runner.Result{Stdout: `[{"name":"sandboxctl"}]`}, nil
		}
		return runner.Result{}, nil
	}}
	if err := (limaDeps(fake)).Start(context.Background(), Config{SharedDir: "/shared"}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/opt/homebrew/bin/limactl", "list", "--json"},
		{"/opt/homebrew/bin/limactl", "start", "--name", "sandboxctl", "--tty=false"},
	}
	if !reflect.DeepEqual(fake.commands, want) {
		t.Fatalf("commands=%v want=%v", fake.commands, want)
	}
}

func TestLimaShellUsesCleanEnvironment(t *testing.T) {
	fake := &fakeRunner{run: func(command runner.Command) (runner.Result, error) {
		if command.Args[0] == "list" {
			return runner.Result{Stdout: `[{"name":"sandboxctl"}]`}, nil
		}
		return runner.Result{}, nil
	}}
	err := (limaDeps(fake)).Shell(context.Background(), Config{SharedDir: "/shared"}, "/tmp", []string{"HOME=/home/ai-dev"}, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	last := fake.commands[len(fake.commands)-1]
	if !strings.Contains(strings.Join(last, "\x00"), "shell\x00--workdir\x00/tmp\x00sandboxctl\x00--\x00/usr/bin/env\x00-i\x00HOME=/home/ai-dev\x00/usr/bin/true") {
		t.Fatalf("unexpected shell argv: %v", last)
	}
}

func TestLimaDeleteUsesForce(t *testing.T) {
	fake := &fakeRunner{}
	if err := (limaDeps(fake)).Delete(context.Background(), Config{}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/opt/homebrew/bin/limactl", "delete", "--force", "sandboxctl"}}
	if !reflect.DeepEqual(fake.commands, want) {
		t.Fatalf("commands=%v", fake.commands)
	}
}

func TestLimaRequiresLimactl(t *testing.T) {
	value := Lima{LookPath: func(string) (string, error) { return "", errors.New("missing") }}
	if err := value.Available(context.Background()); err == nil {
		t.Fatal("missing limactl was accepted")
	}
}
