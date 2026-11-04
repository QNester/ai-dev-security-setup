// Package plan builds and executes reversible system changes.
package plan

import (
	"context"
	"errors"
	"fmt"
)

var ErrNotImplemented = errors.New("system changes are not implemented in Phase 1; use --dry-run")

type Action interface {
	Name() string
	Apply(context.Context) error
	Rollback(context.Context) error
	Verify(context.Context) error
}

type FuncAction struct {
	Description  string
	ApplyFunc    func(context.Context) error
	RollbackFunc func(context.Context) error
	VerifyFunc   func(context.Context) error
}

func (a FuncAction) Name() string { return a.Description }

func (a FuncAction) Apply(ctx context.Context) error {
	if a.ApplyFunc == nil {
		return nil
	}
	return a.ApplyFunc(ctx)
}

func (a FuncAction) Rollback(ctx context.Context) error {
	if a.RollbackFunc == nil {
		return nil
	}
	return a.RollbackFunc(ctx)
}

func (a FuncAction) Verify(ctx context.Context) error {
	if a.VerifyFunc == nil {
		return nil
	}
	return a.VerifyFunc(ctx)
}

type Plan struct {
	Operation string
	Actions   []Action
}

type Result struct {
	Operation string   `json:"operation"`
	DryRun    bool     `json:"dry_run"`
	Steps     []string `json:"steps"`
}

func Execute(ctx context.Context, value Plan, dryRun bool) (Result, error) {
	result := Result{Operation: value.Operation, DryRun: dryRun}
	for _, action := range value.Actions {
		result.Steps = append(result.Steps, action.Name())
	}
	if dryRun {
		return result, nil
	}
	var applied []Action
	rollback := func(cause error) (Result, error) {
		problems := []error{cause}
		for i := len(applied) - 1; i >= 0; i-- {
			if err := applied[i].Rollback(ctx); err != nil {
				problems = append(problems, fmt.Errorf("rollback %s: %w", applied[i].Name(), err))
			}
		}
		return result, errors.Join(problems...)
	}
	for _, action := range value.Actions {
		applied = append(applied, action)
		if err := action.Apply(ctx); err != nil {
			return rollback(fmt.Errorf("apply %s: %w", action.Name(), err))
		}
	}
	for _, action := range applied {
		if err := action.Verify(ctx); err != nil {
			return rollback(fmt.Errorf("verify %s: %w", action.Name(), err))
		}
	}
	return result, nil
}
