// Package cli implements the sandboxctl command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/plan"
	"github.com/QNester/ai-dev-security-setup/internal/platform/detect"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

const (
	ExitOK          = 0
	ExitFailure     = 1
	ExitUsage       = 2
	ExitUnavailable = 3
)

type App struct {
	Stdout   io.Writer
	Stderr   io.Writer
	Getenv   func(string) string
	Platform string
	Arch     string
}

type commonFlags struct {
	dryRun     bool
	yes        bool
	json       bool
	verbose    bool
	backend    string
	backendSet bool
	configPath string
	statePath  string
}

func New(stdout, stderr io.Writer) *App {
	return &App{
		Stdout: stdout, Stderr: stderr, Getenv: os.Getenv,
		Platform: runtime.GOOS, Arch: runtime.GOARCH,
	}
}

func (a *App) Run(ctx context.Context, argv0 string, args []string) int {
	args = dispatchSymlink(filepath.Base(argv0), args)
	if len(args) == 0 {
		a.printUsage()
		return ExitUsage
	}
	var err error
	switch args[0] {
	case "help", "-h", "--help":
		a.printUsage()
		return ExitOK
	case "doctor":
		err = a.runDoctor(args[1:])
	case "install":
		err = a.runInstall(ctx, args[1:])
	case "update":
		err = a.runUpdate(ctx, args[1:])
	case "uninstall":
		err = a.runUninstall(ctx, args[1:])
	case "status":
		err = a.runStatus(args[1:])
	case "review":
		err = a.runReview(args[1:])
	case "enter":
		err = a.runEnter(args[1:])
	default:
		err = fmt.Errorf("unknown command %q", args[0])
		return a.fail(ExitUsage, err)
	}
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, plan.ErrNotImplemented) {
		return a.fail(ExitUnavailable, err)
	}
	var exitErr *exitError
	if errors.As(err, &exitErr) {
		return a.fail(exitErr.code, exitErr.err)
	}
	return a.fail(ExitFailure, err)
}

func dispatchSymlink(name string, args []string) []string {
	if strings.HasSuffix(name, "-secure") {
		tool := strings.TrimSuffix(name, "-secure")
		switch tool {
		case "claude", "kimi", "pi", "opencode":
			return append([]string{"enter", "--tool", tool}, args...)
		}
	}
	if name == "ai-review-file" {
		return append([]string{"review"}, args...)
	}
	return args
}

func (a *App) runDoctor(args []string) error {
	var common commonFlags
	fs := newFlagSet("doctor")
	addCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 0 {
		return usageError(errors.New("doctor takes no positional arguments"))
	}
	detector := detect.NewDetector()
	detector.GOOS = a.Platform
	detector.GOARCH = a.Arch
	report, err := detector.Inspect(common.backend)
	if err != nil {
		return err
	}
	if common.json {
		if err := writeJSON(a.Stdout, report); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.Stdout, "OS: %s/%s\nBackend: %s\n", report.OS, report.Arch, report.Backend)
		for _, check := range report.Checks {
			fmt.Fprintf(a.Stdout, "%-7s %s: %s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
		}
		for _, warning := range report.Warnings {
			fmt.Fprintf(a.Stdout, "WARNING %s\n", warning)
		}
	}
	if !report.Healthy() {
		return &exitError{code: ExitFailure, err: errors.New("doctor found required capabilities that are unavailable")}
	}
	return nil
}

func (a *App) runInstall(ctx context.Context, args []string) error {
	var common commonFlags
	var cliList, ownerUser, ownerHome, sharedDir string
	fs := newFlagSet("install")
	addCommonFlags(fs, &common)
	fs.StringVar(&cliList, "cli", "", "comma-separated CLIs: claude,kimi,pi,opencode")
	fs.StringVar(&ownerUser, "owner-user", "", "workstation owner account")
	fs.StringVar(&ownerHome, "owner-home", "", "workstation owner home")
	fs.StringVar(&sharedDir, "shared-dir", "", "shared project tree")
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 0 {
		return usageError(errors.New("install takes no positional arguments"))
	}
	cfg, err := a.loadConfig(common)
	if err != nil {
		return err
	}
	if cliList != "" {
		cfg.CLIs, err = config.ParseCLIList(cliList)
		if err != nil {
			return usageError(err)
		}
	}
	if ownerUser != "" {
		cfg.OwnerUser = ownerUser
	}
	if ownerHome != "" {
		cfg.OwnerHome = filepath.Clean(ownerHome)
		if sharedDir == "" {
			cfg.SharedDir = filepath.Join(cfg.OwnerHome, "Developer")
		}
		cfg.OwnerSSHKey = filepath.Join(cfg.OwnerHome, ".ssh", "ai-dev-deploy")
	}
	if sharedDir != "" {
		cfg.SharedDir = filepath.Clean(sharedDir)
	}
	if _, err := detect.ResolveBackend(a.Platform, cfg.Backend); err != nil {
		return usageError(err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	_, err = plan.Execute(ctx, plan.Install(cfg), common.dryRun)
	if err != nil {
		return err
	}
	return a.printPlan(plan.Install(cfg), common)
}

func (a *App) runUpdate(ctx context.Context, args []string) error {
	return a.runStatePlan(ctx, "update", args)
}

func (a *App) runUninstall(ctx context.Context, args []string) error {
	return a.runStatePlan(ctx, "uninstall", args)
}

func (a *App) runStatePlan(ctx context.Context, operation string, args []string) error {
	var common commonFlags
	fs := newFlagSet(operation)
	addCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 0 {
		return usageError(fmt.Errorf("%s takes no positional arguments", operation))
	}
	store := state.Store{Path: a.statePath(common)}
	st, err := store.Load()
	if err != nil {
		return fmt.Errorf("load state for %s: %w", operation, err)
	}
	var value plan.Plan
	if operation == "update" {
		value = plan.Update(st)
	} else {
		value = plan.Uninstall(st)
	}
	if _, err := plan.Execute(ctx, value, common.dryRun); err != nil {
		return err
	}
	return a.printPlan(value, common)
}

func (a *App) runStatus(args []string) error {
	var common commonFlags
	fs := newFlagSet("status")
	addCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 0 {
		return usageError(errors.New("status takes no positional arguments"))
	}
	st, err := (state.Store{Path: a.statePath(common)}).Load()
	if errors.Is(err, os.ErrNotExist) {
		if common.json {
			return writeJSON(a.Stdout, map[string]bool{"installed": false})
		}
		fmt.Fprintln(a.Stdout, "not installed")
		return nil
	}
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(a.Stdout, map[string]any{"installed": true, "state": st})
	}
	fmt.Fprintf(a.Stdout, "installed: platform=%s backend=%s clis=%s\n",
		st.Platform, st.Backend, strings.Join(st.Runtime.CLIs, ","))
	return nil
}

func (a *App) runReview(args []string) error {
	var common commonFlags
	fs := newFlagSet("review")
	addCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 1 || !filepath.IsAbs(fs.Arg(0)) {
		return usageError(errors.New("review requires one absolute file path"))
	}
	return fmt.Errorf("review is scheduled for Phase 3: %w", plan.ErrNotImplemented)
}

func (a *App) runEnter(args []string) error {
	var common commonFlags
	var tool, startDir string
	fs := newFlagSet("enter")
	addCommonFlags(fs, &common)
	fs.StringVar(&tool, "tool", "", "claude, kimi, pi, or opencode")
	fs.StringVar(&startDir, "start-dir", "", "starting directory inside the shared tree")
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 0 {
		return usageError(errors.New("enter takes no positional arguments"))
	}
	if _, err := config.ParseCLIList(tool); err != nil {
		return usageError(err)
	}
	if startDir != "" && !filepath.IsAbs(startDir) {
		return usageError(errors.New("start-dir must be absolute"))
	}
	return fmt.Errorf("sandbox entry is scheduled for Phase 2: %w", plan.ErrNotImplemented)
}

func (a *App) loadConfig(common commonFlags) (config.Config, error) {
	var cfg config.Config
	var err error
	if common.configPath != "" {
		cfg, err = config.Load(common.configPath)
	} else {
		var owner, home string
		owner, home, err = a.owner()
		cfg = config.Default(a.Platform, owner, home)
	}
	if err != nil {
		return config.Config{}, err
	}
	if common.backendSet || common.configPath == "" {
		cfg.Backend = common.backend
	}
	if common.statePath != "" || common.configPath == "" {
		cfg.StatePath = a.statePath(common)
	}
	return cfg, nil
}

func (a *App) owner() (string, string, error) {
	name := a.Getenv("SUDO_USER")
	if name == "" {
		name = a.Getenv("USER")
	}
	if name == "" {
		return "", "", errors.New("cannot determine owner; set USER or use --config")
	}
	account, err := user.Lookup(name)
	if err != nil {
		return "", "", fmt.Errorf("look up owner %s: %w", name, err)
	}
	return name, account.HomeDir, nil
}

func (a *App) statePath(common commonFlags) string {
	if common.statePath != "" {
		return common.statePath
	}
	if a.Platform == "darwin" {
		return "/Library/Application Support/ai-sandbox/state.json"
	}
	return "/var/lib/ai-sandbox/state.json"
}

func (a *App) printPlan(value plan.Plan, common commonFlags) error {
	result := plan.Result{Operation: value.Operation, DryRun: common.dryRun}
	for _, action := range value.Actions {
		result.Steps = append(result.Steps, action.Name())
	}
	if common.json {
		return writeJSON(a.Stdout, result)
	}
	fmt.Fprintf(a.Stdout, "%s (%s)\n", value.Operation, map[bool]string{true: "dry-run", false: "applied"}[common.dryRun])
	for _, action := range value.Actions {
		fmt.Fprintf(a.Stdout, "  - %s\n", action.Name())
	}
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func addCommonFlags(fs *flag.FlagSet, common *commonFlags) {
	if common.backend == "" {
		common.backend = "auto"
	}
	fs.BoolVar(&common.dryRun, "dry-run", common.dryRun, "show planned actions without changing the system")
	fs.BoolVar(&common.yes, "yes", common.yes, "apply without confirmation")
	fs.BoolVar(&common.yes, "y", common.yes, "alias for --yes")
	fs.BoolVar(&common.json, "json", common.json, "emit JSON")
	fs.BoolVar(&common.verbose, "verbose", common.verbose, "enable verbose diagnostics")
	fs.Func("backend", "native, vm, or auto", func(value string) error {
		common.backend = value
		common.backendSet = true
		return nil
	})
	fs.StringVar(&common.configPath, "config", common.configPath, "load a JSON configuration")
	fs.StringVar(&common.statePath, "state", common.statePath, "override the state file path")
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageError(err error) error {
	return &exitError{code: ExitUsage, err: err}
}

func (a *App) fail(code int, err error) int {
	fmt.Fprintf(a.Stderr, "sandboxctl: %v\n", err)
	return code
}

func (a *App) printUsage() {
	fmt.Fprintln(a.Stdout, `Usage: sandboxctl COMMAND [OPTIONS]

Commands:
  doctor                 inspect host capabilities (read-only)
  install --cli LIST     plan or install selected coding CLIs
  update                 update from saved state
  uninstall              remove integration recorded in saved state
  status                 show saved installation state
  review FILE            review one file (Phase 3)
  enter --tool NAME      internal sandbox entry (Phase 2)

Common options: --dry-run, --yes, --json, --verbose,
                --backend native|vm|auto, --config FILE, --state FILE`)
}
