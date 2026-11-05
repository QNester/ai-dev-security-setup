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
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/QNester/ai-dev-security-setup/internal/bootstrap"
	"github.com/QNester/ai-dev-security-setup/internal/config"
	coreruntime "github.com/QNester/ai-dev-security-setup/internal/core/runtime"
	"github.com/QNester/ai-dev-security-setup/internal/core/shared"
	"github.com/QNester/ai-dev-security-setup/internal/plan"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/platform/darwin"
	"github.com/QNester/ai-dev-security-setup/internal/platform/detect"
	"github.com/QNester/ai-dev-security-setup/internal/platform/linux"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

const (
	ExitOK          = 0
	ExitFailure     = 1
	ExitUsage       = 2
	ExitUnavailable = 3
)

type App struct {
	Stdout       io.Writer
	Stderr       io.Writer
	Stdin        io.Reader
	Getenv       func(string) string
	Platform     string
	Arch         string
	EUID         int
	Detector     *detect.Detector
	jsonErrors   bool
	noColor      bool
	forceColor   bool
	forceSpinner bool
}

type commonFlags struct {
	dryRun     bool
	yes        bool
	json       bool
	noColor    bool
	verbose    bool
	backend    string
	backendSet bool
	configPath string
	statePath  string
}

func New(stdout, stderr io.Writer) *App {
	return &App{
		Stdout: stdout, Stderr: stderr, Stdin: os.Stdin, Getenv: os.Getenv,
		Platform: runtime.GOOS, Arch: runtime.GOARCH, EUID: os.Geteuid(),
	}
}

func (a *App) Run(ctx context.Context, argv0 string, args []string) int {
	a.jsonErrors = false
	a.noColor = false
	for _, arg := range args {
		if arg == "--json" {
			a.jsonErrors = true
		} else if value, ok := strings.CutPrefix(arg, "--json="); ok {
			enabled, err := strconv.ParseBool(value)
			a.jsonErrors = err == nil && enabled
		} else if arg == "--no-color" {
			a.noColor = true
		} else if value, ok := strings.CutPrefix(arg, "--no-color="); ok {
			enabled, err := strconv.ParseBool(value)
			a.noColor = err == nil && enabled
		}
	}
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
		err = a.runDoctor(ctx, args[1:])
	case "install":
		err = a.runInstall(ctx, args[1:])
	case "update":
		err = a.runUpdate(ctx, args[1:])
	case "uninstall":
		err = a.runUninstall(ctx, args[1:])
	case "status":
		err = a.runStatus(args[1:])
	case "review":
		err = a.runReview(ctx, args[1:])
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
			return append([]string{"enter", "--tool", tool, "--"}, args...)
		}
	}
	if name == "ai-review-file" {
		return append([]string{"review"}, args...)
	}
	return args
}

func (a *App) runDoctor(ctx context.Context, args []string) error {
	var common commonFlags
	var fix bool
	fs := newFlagSet("doctor")
	addCommonFlags(fs, &common)
	fs.BoolVar(&fix, "fix", false, "install missing prerequisites")
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 0 {
		return usageError(errors.New("doctor takes no positional arguments"))
	}
	detector := detect.NewDetector()
	if a.Detector != nil {
		detector = *a.Detector
	}
	detector.GOOS = a.Platform
	detector.GOARCH = a.Arch
	if _, err := detect.ResolveBackend(a.Platform, common.backend); err != nil {
		return usageError(err)
	}
	if fix {
		if common.json {
			return usageError(errors.New("doctor --fix cannot be combined with --json"))
		}
		if !common.dryRun && !common.yes {
			return usageError(errors.New("doctor --fix requires --yes (or --dry-run)"))
		}
		var fixSpinner *spinner
		if a.Platform != "darwin" {
			// Homebrew prints its own progress; apt is silent, so only the
			// Linux package step gets a spinner.
			fixSpinner = a.startSpinner("installing missing prerequisites...")
		}
		err := bootstrap.Fix(ctx, bootstrap.Options{
			GOOS: a.Platform, EUID: a.EUID, LookPath: exec.LookPath, Getenv: a.Getenv,
			Stdout: a.Stdout, Stderr: a.Stderr, DryRun: common.dryRun,
		}, common.backend)
		fixSpinner.Stop()
		if err != nil {
			return err
		}
	}
	spin := a.startSpinner("inspecting host capabilities...")
	report, err := detector.Inspect(common.backend)
	spin.Stop()
	if err != nil {
		return err
	}
	if common.json {
		if err := writeJSON(a.Stdout, report); err != nil {
			return err
		}
	} else {
		color := a.colored(a.Stdout)
		if color {
			fmt.Fprintf(a.Stdout, "%ssandboxctl doctor%s\n", ansiBold, ansiReset)
			fmt.Fprintf(a.Stdout, "%s%s%s\n", ansiDim, strings.Repeat("─", 52), ansiReset)
			fmt.Fprintf(a.Stdout, "  %sOS       %s/%s%s\n", ansiDim, report.OS, report.Arch, ansiReset)
			fmt.Fprintf(a.Stdout, "  %sBackend  %s%s\n\n", ansiDim, report.Backend, ansiReset)
			for _, check := range report.Checks {
				fmt.Fprintf(a.Stdout, "  %s%s%s %-20s %s\n",
					doctorColor(check.Status), doctorIcon(check.Status), ansiReset, check.Name, check.Detail)
			}
			for _, warning := range report.Warnings {
				fmt.Fprintf(a.Stdout, "  %s!%s %s\n", ansiYellow, ansiReset, warning)
			}
			if report.Healthy() {
				fmt.Fprintf(a.Stdout, "\n  %s✔ host is ready%s\n", ansiGreen, ansiReset)
			}
		} else {
			fmt.Fprintf(a.Stdout, "OS: %s/%s\nBackend: %s\n", report.OS, report.Arch, report.Backend)
			for _, check := range report.Checks {
				fmt.Fprintf(a.Stdout, "%-7s %s: %s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
			}
			for _, warning := range report.Warnings {
				fmt.Fprintf(a.Stdout, "WARNING %s\n", warning)
			}
			if report.Healthy() {
				fmt.Fprintln(a.Stdout, "host is ready")
			}
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
	if common.dryRun {
		if err := cfg.Validate(); err != nil {
			return err
		}
	} else if err := cfg.ValidateSystem(a.Platform); err != nil {
		return err
	}
	if !common.dryRun {
		if a.EUID != 0 {
			return errors.New("installing requires root; run with sudo")
		}
		if !common.yes {
			return usageError(errors.New("refusing to change the system without --yes"))
		}
	}
	backends, err := a.backends()
	if err != nil {
		return err
	}
	value := plan.Install(cfg, plan.Deps{Backends: backends, Store: state.Store{Path: cfg.StatePath}})
	if _, err := a.executePlan(ctx, value, common.dryRun); err != nil {
		return err
	}
	return a.printPlan(value, common)
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
	store, err := a.stateStore(common)
	if err != nil {
		return err
	}
	st, err := store.Load()
	if err != nil {
		return fmt.Errorf("load state for %s: %w", operation, err)
	}
	if st.Platform != a.Platform {
		return fmt.Errorf("state platform %q does not match current platform %q", st.Platform, a.Platform)
	}
	if !common.dryRun {
		if a.EUID != 0 {
			return fmt.Errorf("%s requires root; run with sudo", operation)
		}
		if !common.yes {
			return usageError(fmt.Errorf("refusing to change the system without --yes"))
		}
	}
	backends, err := a.backends()
	if err != nil {
		return err
	}
	deps := plan.Deps{Backends: backends, Store: store}
	var value plan.Plan
	if operation == "update" {
		value = plan.Update(st, deps)
	} else {
		value = plan.Uninstall(st, deps)
	}
	if _, err := a.executePlan(ctx, value, common.dryRun); err != nil {
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
	store, err := a.stateStore(common)
	if err != nil {
		return err
	}
	st, err := store.Load()
	if errors.Is(err, os.ErrNotExist) {
		if common.json {
			return writeJSON(a.Stdout, map[string]bool{"installed": false})
		}
		if a.colored(a.Stdout) {
			fmt.Fprintf(a.Stdout, "%ssandboxctl status%s\n", ansiBold, ansiReset)
			fmt.Fprintf(a.Stdout, "%s%s%s\n", ansiDim, strings.Repeat("─", 52), ansiReset)
			fmt.Fprintf(a.Stdout, "  %s● not installed%s\n", ansiYellow, ansiReset)
		} else {
			fmt.Fprintln(a.Stdout, "not installed")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if st.Platform != a.Platform {
		return fmt.Errorf("state platform %q does not match current platform %q", st.Platform, a.Platform)
	}
	if common.json {
		return writeJSON(a.Stdout, map[string]any{"installed": true, "state": st})
	}
	if a.colored(a.Stdout) {
		fmt.Fprintf(a.Stdout, "%ssandboxctl status%s\n", ansiBold, ansiReset)
		fmt.Fprintf(a.Stdout, "%s%s%s\n", ansiDim, strings.Repeat("─", 52), ansiReset)
		fmt.Fprintf(a.Stdout, "  %s✔ installed%s\n", ansiGreen, ansiReset)
		fmt.Fprintf(a.Stdout, "  %splatform  %s%s\n", ansiDim, st.Platform, ansiReset)
		fmt.Fprintf(a.Stdout, "  %sbackend   %s%s\n", ansiDim, st.Backend, ansiReset)
		fmt.Fprintf(a.Stdout, "  %sclis      %s%s\n", ansiDim, strings.Join(st.Runtime.CLIs, ", "), ansiReset)
	} else {
		fmt.Fprintf(a.Stdout, "installed: platform=%s backend=%s clis=%s\n",
			st.Platform, st.Backend, strings.Join(st.Runtime.CLIs, ","))
	}
	return nil
}

func (a *App) runReview(ctx context.Context, args []string) error {
	var common commonFlags
	fs := newFlagSet("review")
	addCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return usageError(err)
	}
	if fs.NArg() != 1 || !filepath.IsAbs(fs.Arg(0)) {
		return usageError(errors.New("review requires one absolute file path"))
	}
	if common.json {
		return usageError(errors.New("review emits model text; --json is not supported"))
	}
	if a.Platform != "linux" {
		return fmt.Errorf("sandboxed review is not available on %s yet: %w", a.Platform, plan.ErrNotImplemented)
	}
	if a.EUID != 0 {
		return a.reexecWithSudo("review", args)
	}
	store, err := a.stateStore(common)
	if err != nil {
		return err
	}
	st, err := store.Load()
	if err != nil {
		return fmt.Errorf("load state for review: %w", err)
	}
	if st.Platform != a.Platform {
		return fmt.Errorf("state platform %q does not match current platform %q", st.Platform, a.Platform)
	}
	if !containsCLI(st.Runtime.CLIs, "claude") {
		return errors.New("review requires the claude CLI to be installed")
	}
	backends, err := a.backends()
	if err != nil {
		return err
	}
	prepared, err := backends.Review.Prepare(ctx, st.Config, fs.Arg(0))
	if err != nil {
		return err
	}
	if prepared.Cleanup != nil {
		defer prepared.Cleanup()
	}
	argv, err := backends.Sandbox.Wrap(ctx, prepared.Spec)
	if err != nil {
		return err
	}
	credential, err := credentialFor(st.Config.AIUser)
	if err != nil {
		return err
	}
	_, err = (runner.OSRunner{}).Run(ctx, runner.Command{
		Path:       argv[0],
		Args:       argv[1:],
		Env:        []string{},
		ExtraFiles: prepared.Files,
		Credential: credential,
		Stdout:     a.Stdout,
		Stderr:     a.Stderr,
	})
	if err != nil {
		return fmt.Errorf("review failed: %w", err)
	}
	return nil
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
	tools, err := config.ParseCLIList(tool)
	if err != nil || len(tools) != 1 {
		return usageError(errors.New("enter requires exactly one --tool"))
	}
	tool = tools[0]
	if startDir != "" && !filepath.IsAbs(startDir) {
		return usageError(errors.New("start-dir must be absolute"))
	}
	if a.Platform != "linux" {
		return fmt.Errorf("sandbox entry is not available on %s: %w", a.Platform, plan.ErrNotImplemented)
	}
	if a.EUID != 0 {
		return a.reexecWithSudo("enter", args)
	}
	store, err := a.stateStore(common)
	if err != nil {
		return err
	}
	st, err := store.Load()
	if err != nil {
		return fmt.Errorf("load state for enter: %w", err)
	}
	if st.Platform != a.Platform {
		return fmt.Errorf("state platform %q does not match current platform %q", st.Platform, a.Platform)
	}
	if !containsCLI(st.Runtime.CLIs, tool) {
		return fmt.Errorf("%s is not installed", tool)
	}
	if startDir == "" {
		if wd, err := os.Getwd(); err == nil {
			if resolved, err := resolveStartDir(st.Config, wd); err == nil {
				startDir = resolved
			}
		}
	}
	resolvedStart, err := resolveStartDir(st.Config, startDir)
	if err != nil {
		return err
	}
	spec, err := buildEnterSpec(st, tool, resolvedStart, fs.Args())
	if err != nil {
		return err
	}
	backends, err := a.backends()
	if err != nil {
		return err
	}
	argv, err := backends.Sandbox.Wrap(context.Background(), spec)
	if err != nil {
		return err
	}
	return execAsAI(st.Config.AIUser, argv)
}

func (a *App) reexecWithSudo(command string, args []string) error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("%s must be started through sudo or as root", command)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	argv := append([]string{sudo, self, command}, args...)
	return syscall.Exec(sudo, argv, os.Environ())
}

func credentialFor(username string) (*syscall.Credential, error) {
	account, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("look up %s: %w", username, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse UID for %s: %w", username, err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse GID for %s: %w", username, err)
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("read groups for %s: %w", username, err)
	}
	groups := make([]uint32, 0, len(groupIDs))
	for _, value := range groupIDs {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse group ID %q: %w", value, err)
		}
		groups = append(groups, uint32(parsed))
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, nil
}

func execAsAI(user string, argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty sandbox command")
	}
	dropper := ""
	if path, err := exec.LookPath("runuser"); err == nil {
		dropper = path
	} else if path, err := exec.LookPath("sudo"); err == nil {
		dropper = path
	} else {
		return errors.New("runuser or sudo is required to drop privileges")
	}
	args := []string{dropper}
	if filepath.Base(dropper) == "runuser" {
		args = append(args, "-u", user, "--")
	} else {
		args = append(args, "-u", user, "--")
	}
	args = append(args, argv...)
	return syscall.Exec(dropper, args, os.Environ())
}

func buildEnterSpec(st state.State, tool, startDir string, args []string) (base.Spec, error) {
	cfg := st.Config
	program := filepath.Join(cfg.RuntimeRoot, "bin", tool)
	if info, err := os.Stat(program); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return base.Spec{}, fmt.Errorf("missing executable: %s", program)
	}
	readOnly := coreruntime.ReadOnlyPaths(cfg)
	mounts := []base.BindMount{{
		Source: cfg.SharedSource, Target: cfg.SharedDir, ReadOnly: false,
	}}
	if resolved, ok := coreruntime.ResolvConf(); ok {
		mounts = append(mounts, base.BindMount{
			Source: resolved, Target: "/etc/resolv.conf", ReadOnly: true,
		})
	}
	env := coreruntime.SandboxEnv(cfg)
	if _, err := os.Stat(coreruntime.OpenCodeConfigPath(cfg)); err == nil {
		env["OPENCODE_CONFIG"] = coreruntime.OpenCodeConfigPath(cfg)
	}
	argv := sandboxEntrypoint(cfg, program, args)
	return base.Spec{
		Argv:          argv,
		Cwd:           startDir,
		Env:           env,
		ReadOnlyPaths: readOnly,
		BindMounts:    mounts,
		Home:          cfg.AIHome,
		Tmp:           cfg.TmpRoot,
		Network:       base.NetworkOpen,
		ReviewFD:      -1,
	}, nil
}

func sandboxEntrypoint(cfg config.Config, program string, args []string) []string {
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/usr/bin/bash"
	}
	script := `load=$1
secrets=$2
shift 2
if [[ $load == 1 && -f $secrets ]]; then
    set -a
    . "$secrets" || {
        printf "Cannot load secrets file: %s\n" "$secrets" >&2
        exit 1
    }
    set +a
fi
if [[ -z ${LITELLM_API_KEY:-} && -n ${LITTLE_LLM_API_KEY:-} ]]; then
    LITELLM_API_KEY=$LITTLE_LLM_API_KEY
    export LITELLM_API_KEY
fi
exec "$@"`
	argv := []string{shell, "--noprofile", "--norc", "-c", script, "sandboxctl", "1", coreruntime.SecretsPath(cfg), program}
	return append(argv, args...)
}

func resolveStartDir(cfg config.Config, raw string) (string, error) {
	if raw == "" {
		return cfg.SharedDir, nil
	}
	if !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
		return "", errors.New("start-dir must be a clean absolute path")
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", fmt.Errorf("resolve start-dir: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("start-dir must be a directory")
	}
	switch {
	case shared.InsideShared(cfg, resolved):
		rel, err := filepath.Rel(cfg.SharedDir, resolved)
		if err != nil {
			return "", err
		}
		return filepath.Join(cfg.SharedDir, rel), nil
	case resolved == cfg.SharedSource || strings.HasPrefix(resolved, cfg.SharedSource+string(filepath.Separator)):
		rel, err := filepath.Rel(cfg.SharedSource, resolved)
		if err != nil {
			return "", err
		}
		return filepath.Join(cfg.SharedDir, rel), nil
	default:
		return "", errors.New("start-dir must be inside the shared tree")
	}
}

func containsCLI(clis []string, wanted string) bool {
	for _, cli := range clis {
		if cli == wanted {
			return true
		}
	}
	return false
}

func (a *App) backends() (base.Backends, error) {
	switch a.Platform {
	case "linux":
		return linux.BackendsWithDeps(linux.Deps{}), nil
	case "darwin":
		return darwin.Backends(), nil
	default:
		return base.Backends{}, fmt.Errorf("unsupported platform %q", a.Platform)
	}
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

func (a *App) stateStore(common commonFlags) (state.Store, error) {
	if common.statePath == "" && common.configPath != "" {
		cfg, err := config.Load(common.configPath)
		if err != nil {
			return state.Store{}, fmt.Errorf("load config for state path: %w", err)
		}
		return state.Store{Path: cfg.StatePath}, nil
	}
	return state.Store{Path: a.statePath(common)}, nil
}

func (a *App) executePlan(ctx context.Context, value plan.Plan, dryRun bool) (plan.Result, error) {
	if dryRun {
		return plan.Execute(ctx, value, true)
	}
	spin := a.startSpinner(value.Operation + ": starting")
	defer spin.Stop()
	return plan.ExecuteWithProgress(ctx, value, false, func(phase, name string) {
		if phase == "rollback" {
			spin.Set(value.Operation + " · rollback: " + name)
			return
		}
		spin.Set(value.Operation + " · " + name)
	})
}

func (a *App) printPlan(value plan.Plan, common commonFlags) error {
	result := plan.Result{Operation: value.Operation, DryRun: common.dryRun}
	for _, action := range value.Actions {
		result.Steps = append(result.Steps, action.Name())
	}
	if common.json {
		return writeJSON(a.Stdout, result)
	}
	status := "applied"
	if common.dryRun {
		status = "dry-run"
	}
	if a.colored(a.Stdout) {
		fmt.Fprintf(a.Stdout, "%ssandboxctl%s\n", ansiBold, ansiReset)
		fmt.Fprintf(a.Stdout, "%s%s%s\n", ansiDim, strings.Repeat("─", 52), ansiReset)
		fmt.Fprintf(a.Stdout, "%s✔%s %s %s\n", ansiGreen, ansiReset, value.Operation, status)
		for index, action := range value.Actions {
			fmt.Fprintf(a.Stdout, "  %s%2d.%s %s\n", ansiDim, index+1, ansiReset, action.Name())
		}
		label := "actions"
		if common.dryRun {
			label = "planned actions"
		}
		fmt.Fprintf(a.Stdout, "\n  %s%d %s%s\n", ansiDim, len(value.Actions), label, ansiReset)
		return nil
	}
	fmt.Fprintf(a.Stdout, "%s (%s)\n", value.Operation, status)
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
	fs.BoolVar(&common.json, "json", common.json, "machine-readable JSON output")
	fs.BoolVar(&common.noColor, "no-color", common.noColor, "disable ANSI colors")
	fs.BoolVar(&common.verbose, "verbose", common.verbose, "enable verbose diagnostics")
	fs.Func("backend", "native, vm, or auto", func(value string) error {
		common.backend = value
		common.backendSet = true
		return nil
	})
	fs.StringVar(&common.configPath, "config", common.configPath, "load a JSON configuration")
	fs.StringVar(&common.statePath, "state", common.statePath, "override the state file path")
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

func (a *App) colored(writer io.Writer) bool {
	if a.noColor {
		return false
	}
	if a.forceColor {
		return true
	}
	if a.Getenv != nil && a.Getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func doctorColor(status string) string {
	switch status {
	case detect.Pass:
		return ansiGreen
	case detect.Warn:
		return ansiYellow
	default:
		return ansiRed
	}
}

func doctorIcon(status string) string {
	switch status {
	case detect.Pass:
		return "✔"
	case detect.Warn:
		return "!"
	default:
		return "✖"
	}
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
	if a.jsonErrors {
		if jsonErr := writeJSON(a.Stderr, map[string]any{
			"error": err.Error(), "exit_code": code,
		}); jsonErr == nil {
			return code
		}
	}
	if a.colored(a.Stderr) {
		color := ansiRed
		symbol := "✖"
		if code == ExitUnavailable {
			color = ansiYellow
			symbol = "●"
		}
		fmt.Fprintf(a.Stderr, "%s%s sandboxctl: %v%s\n", color, symbol, err, ansiReset)
		return code
	}
	fmt.Fprintf(a.Stderr, "sandboxctl: %v\n", err)
	return code
}

func (a *App) printUsage() {
	if a.colored(a.Stdout) {
		fmt.Fprintf(a.Stdout, "%ssandboxctl%s\n", ansiBold, ansiReset)
		fmt.Fprintf(a.Stdout, "%s%s%s\n", ansiDim, strings.Repeat("─", 52), ansiReset)
	}
	fmt.Fprintln(a.Stdout, `Usage: sandboxctl COMMAND [OPTIONS]

Commands:
  doctor                 inspect host capabilities (read-only)
  doctor --fix --yes     install missing prerequisites
  install --cli LIST     plan or install selected coding CLIs
  update                 update from saved state (requires root + --yes)
  uninstall              remove integration recorded in saved state
  status                 show saved installation state
  review FILE            read-only single-file review
  enter --tool NAME      internal Linux sandbox entry

Mutating commands require root and --yes.
Common options: --dry-run, --yes, --json, --no-color, --verbose,
                --backend native|vm|auto, --config FILE, --state FILE`)
}
