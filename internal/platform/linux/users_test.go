package linux

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

type scriptedRunner struct {
	calls [][]string
	run   func(runner.Command) (runner.Result, error)
}

func (s *scriptedRunner) Run(_ context.Context, command runner.Command) (runner.Result, error) {
	s.calls = append(s.calls, append([]string{command.Path}, command.Args...))
	return s.run(command)
}

func fakeDeps(script *scriptedRunner) Deps {
	return Deps{
		Runner: script,
		LookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
	}
}

func TestEnsureGroupCreatesOnlyMissingGroups(t *testing.T) {
	script := &scriptedRunner{run: func(command runner.Command) (runner.Result, error) {
		if command.Path == "/usr/bin/getent" && command.Args[1] == "ai-dev-share" {
			return runner.Result{}, errors.New("missing")
		}
		return runner.Result{Stdout: "ok\n"}, nil
	}}
	cfg := config.Default("linux", "alice", "/home/alice")
	created, err := (Users{Deps: fakeDeps(script)}).EnsureGroup(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("missing group was not reported as created")
	}
	joined := make([]string, 0, len(script.calls))
	for _, call := range script.calls {
		joined = append(joined, strings.Join(call, " "))
	}
	text := strings.Join(joined, "\n")
	if !strings.Contains(text, "/usr/bin/groupadd --system ai-dev-share") {
		t.Fatalf("shared group was not created:\n%s", text)
	}
	if !strings.Contains(text, "/usr/bin/groupadd --system ai-dev") {
		t.Fatalf("primary group was not created:\n%s", text)
	}
}

func TestDeleteGroupUsesGetentAndGroupdel(t *testing.T) {
	script := &scriptedRunner{run: func(command runner.Command) (runner.Result, error) {
		return runner.Result{}, nil
	}}
	cfg := config.Default("linux", "alice", "/home/alice")
	if err := (Users{Deps: fakeDeps(script)}).DeleteGroup(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, call := range script.calls {
		if call[0] == "/usr/bin/groupdel" {
			names = append(names, call[1])
		}
	}
	if !reflect.DeepEqual(names, []string{"ai-dev", "ai-dev-share"}) {
		t.Fatalf("groupdel calls=%v", names)
	}
}
