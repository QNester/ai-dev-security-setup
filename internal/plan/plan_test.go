package plan

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDryRunDoesNotApply(t *testing.T) {
	called := false
	value := Plan{Operation: "install", Actions: []Action{FuncAction{
		Description: "must not run",
		ApplyFunc: func(context.Context) error {
			called = true
			return nil
		},
	}}}
	result, err := Execute(context.Background(), value, true)
	if err != nil {
		t.Fatal(err)
	}
	if called || !result.DryRun || len(result.Steps) != 1 {
		t.Fatalf("unexpected dry run: %+v, called=%v", result, called)
	}
}

func TestFailureRollsBackInReverseOrder(t *testing.T) {
	var events []string
	action := func(name string, applyErr error) Action {
		return FuncAction{
			Description: name,
			ApplyFunc: func(context.Context) error {
				events = append(events, "apply "+name)
				return applyErr
			},
			RollbackFunc: func(context.Context) error {
				events = append(events, "rollback "+name)
				return nil
			},
		}
	}
	failure := errors.New("failed")
	_, err := Execute(context.Background(), Plan{Actions: []Action{
		action("one", nil), action("two", nil), action("three", failure),
	}}, false)
	if !errors.Is(err, failure) {
		t.Fatalf("expected failure, got %v", err)
	}
	want := []string{"apply one", "apply two", "apply three", "rollback three", "rollback two", "rollback one"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%v want=%v", events, want)
	}
}

func TestVerificationFailureRollsBack(t *testing.T) {
	rolledBack := false
	value := Plan{Actions: []Action{FuncAction{
		Description: "change",
		VerifyFunc:  func(context.Context) error { return errors.New("unsafe") },
		RollbackFunc: func(context.Context) error {
			rolledBack = true
			return nil
		},
	}}}
	if _, err := Execute(context.Background(), value, false); err == nil || !rolledBack {
		t.Fatalf("err=%v rolledBack=%v", err, rolledBack)
	}
}
