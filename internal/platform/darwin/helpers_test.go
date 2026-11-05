package darwin

import (
	"context"
	"errors"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

type fakeRunner struct {
	result runner.Result
	err    error
}

func (f fakeRunner) Run(context.Context, runner.Command) (runner.Result, error) {
	return f.result, f.err
}

func TestACLIndexFindsEntry(t *testing.T) {
	output := "drwxr-xr-x  2 alice staff 64 Jan 1 00:00 home\n" +
		" 0: user:ai-dev allow execute\n" +
		" 1: group:staff allow read\n"
	index, ok := aclIndex(output, "user:ai-dev")
	if !ok || index != 0 {
		t.Fatalf("index=%d ok=%v", index, ok)
	}
	if _, ok := aclIndex(output, "user:missing"); ok {
		t.Fatal("missing ACL entry was found")
	}
}

func TestNextIDSkipsUsedIDs(t *testing.T) {
	deps := Deps{
		Runner: fakeRunner{result: runner.Result{Stdout: "_trustd 501\n_driverkit 502\n"}},
		LookPath: func(string) (string, error) {
			return "/usr/bin/dscl", nil
		},
	}
	id, err := nextID(context.Background(), deps, "/Users", "UniqueID")
	if err != nil {
		t.Fatal(err)
	}
	if id != 503 {
		t.Fatalf("id=%d", id)
	}
}

func TestNextIDFailsWhenDSClFails(t *testing.T) {
	deps := Deps{
		Runner:   fakeRunner{err: errors.New("denied")},
		LookPath: func(string) (string, error) { return "/usr/bin/dscl", nil },
	}
	if _, err := nextID(context.Background(), deps, "/Users", "UniqueID"); err == nil {
		t.Fatal("expected dscl failure")
	}
}
