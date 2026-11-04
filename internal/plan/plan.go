// Package plan builds and executes reversible system changes.
package plan

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNotImplemented = errors.New("system mutation is disabled for this backend; use --dry-run")

const RollbackTimeout = 2 * time.Minute

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

// ProgressFunc receives a short phase ("apply", "verify", "rollback") and the
// action name. It must be fast and must not block; the CLI uses it to update a
// terminal spinner.
type ProgressFunc func(phase, name string)

func Execute(ctx context.Context, value Plan, dryRun bool) (Result, error) {
	return ExecuteWithProgress(ctx, value, dryRun, nil)
}

func ExecuteWithProgress(ctx context.Context, value Plan, dryRun bool, progress ProgressFunc) (Result, error) {
	result := Result{Operation: value.Operation, DryRun: dryRun}
	for _, action := range value.Actions {
		result.Steps = append(result.Steps, action.Name())
	}
	if dryRun {
		return result, nil
	}
	report := func(phase, name string) {
		if progress != nil {
			progress(phase, name)
		}
	}
	var applied []Action
	rollback := func(cause error) (Result, error) {
		if len(applied) == 0 {
			return result, cause
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RollbackTimeout)
		defer cancel()
		problems := []error{cause}
		for i := len(applied) - 1; i >= 0; i-- {
			report("rollback", applied[i].Name())
			if err := invoke(rollbackCtx, applied[i].Rollback); err != nil {
				problems = append(problems, fmt.Errorf("rollback %s: %w", applied[i].Name(), err))
			}
		}
		return result, errors.Join(problems...)
	}
	for _, action := range value.Actions {
		if err := ctx.Err(); err != nil {
			return rollback(fmt.Errorf("before apply %s: %w", action.Name(), err))
		}
		applied = append(applied, action)
		report("apply", action.Name())
		if err := invoke(ctx, action.Apply); err != nil {
			return rollback(fmt.Errorf("apply %s: %w", action.Name(), err))
		}
	}
	for _, action := range applied {
		if err := ctx.Err(); err != nil {
			return rollback(fmt.Errorf("before verify %s: %w", action.Name(), err))
		}
		report("verify", action.Name())
		if err := invoke(ctx, action.Verify); err != nil {
			return rollback(fmt.Errorf("verify %s: %w", action.Name(), err))
		}
	}
	return result, nil
}

func invoke(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("action panic: %v", recovered)
		}
	}()
	return fn(ctx)
}
