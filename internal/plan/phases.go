package plan

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/core/shared"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

// Deps supplies the selected platform backend and the state store.
type Deps struct {
	Backends    base.Backends
	Store       state.Store
	Platform    string
	Backend     string
	SkipRuntime bool
}

func Install(cfg config.Config, options ...Deps) Plan {
	return installPlan("install", cfg, state.State{}, dependency(options))
}

func Update(st state.State, options ...Deps) Plan {
	return installPlan("update", st.Config, st, dependency(options))
}

func dependency(options []Deps) Deps {
	if len(options) == 0 {
		return Deps{}
	}
	return options[0]
}

func installPlan(operation string, cfg config.Config, previous state.State, deps Deps) Plan {
	runtimeStep := runtimeAction(cfg, deps.Backends.Runtime)
	if deps.SkipRuntime {
		runtimeStep = runtimeVerifyAction(cfg, deps.Backends.Runtime)
	}
	actions := []Action{
		hostPrepareAction(cfg, deps.Backends.Host),
		groupAction(cfg, deps.Backends.Users),
		userAction(cfg, deps.Backends.Users),
		denyOwnerAction(cfg, deps.Backends.ACL),
		runtimeStep,
		sharedAction(cfg, deps.Backends.ACL),
		networkAction(cfg, deps.Backends.Network),
		serviceAction(cfg, deps.Backends.Services),
		launcherAction(cfg, deps.Backends.Launchers),
		saveStateAction(cfg, previous, deps),
	}
	return Plan{Operation: operation, Actions: actions}
}

func Uninstall(st state.State, options ...Deps) Plan {
	cfg := st.Config
	deps := dependency(options)
	return Plan{Operation: "uninstall", Actions: []Action{
		cleanupHostAction(cfg, deps.Backends.Host),
		removeServicesAction(cfg, deps.Backends.Services),
		removeNetworkAction(cfg, deps.Backends.Network),
		removeLaunchersAction(cfg, deps.Backends.Launchers),
		removeRuntimeAction(cfg, deps.Backends.Runtime),
		removeTemporaryAction(cfg, deps.Backends.Host),
		revokeSharedAction(cfg, deps.Backends.ACL),
		verifyRemovedAction(cfg, deps.Backends),
		removeStateAction(deps.Store),
	}}
}

func hostPrepareAction(cfg config.Config, backend base.HostBackend) Action {
	written := false
	return FuncAction{
		Description: "prepare host, packages, and user namespaces",
		ApplyFunc: func(ctx context.Context) error {
			var err error
			written, err = backend.Prepare(ctx, cfg)
			return err
		},
		RollbackFunc: func(ctx context.Context) error {
			if !written {
				return nil
			}
			return backend.Cleanup(ctx, cfg)
		},
		VerifyFunc: func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func cleanupHostAction(cfg config.Config, backend base.HostBackend) Action {
	return FuncAction{
		Description:  "remove AppArmor profile and verify no sandbox processes",
		ApplyFunc:    func(ctx context.Context) error { return backend.Cleanup(ctx, cfg) },
		VerifyFunc:   nil,
		RollbackFunc: nil,
	}
}

func groupAction(cfg config.Config, backend base.UserBackend) Action {
	created := false
	return FuncAction{
		Description: "ensure AI groups",
		ApplyFunc: func(ctx context.Context) error {
			var err error
			created, err = backend.EnsureGroup(ctx, cfg)
			return err
		},
		RollbackFunc: func(ctx context.Context) error {
			if !created {
				return nil
			}
			return backend.DeleteGroup(ctx, cfg)
		},
		VerifyFunc: func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func userAction(cfg config.Config, backend base.UserBackend) Action {
	created := false
	return FuncAction{
		Description: "ensure locked AI user, home, and temporary directory",
		ApplyFunc: func(ctx context.Context) error {
			var err error
			created, err = backend.EnsureUser(ctx, cfg)
			return err
		},
		RollbackFunc: func(ctx context.Context) error {
			if !created {
				return nil
			}
			return backend.DeleteUser(ctx, cfg)
		},
		VerifyFunc: func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func denyOwnerAction(cfg config.Config, backend base.ACLBackend) Action {
	return FuncAction{
		Description:  "deny AI traversal of the owner home before installers run",
		ApplyFunc:    func(ctx context.Context) error { return backend.DenyOwner(ctx, cfg) },
		RollbackFunc: func(ctx context.Context) error { return backend.RevokeOwnerDeny(ctx, cfg) },
	}
}

func runtimeAction(cfg config.Config, backend base.RuntimeBackend) Action {
	return FuncAction{
		Description:  fmt.Sprintf("install and seal CLI runtime: %v", cfg.CLIs),
		ApplyFunc:    func(ctx context.Context) error { return backend.Install(ctx, cfg) },
		RollbackFunc: func(ctx context.Context) error { return backend.Rollback(ctx, cfg) },
		VerifyFunc:   func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func runtimeVerifyAction(cfg config.Config, backend base.RuntimeBackend) Action {
	return FuncAction{
		Description: fmt.Sprintf("verify existing CLI runtime: %v", cfg.CLIs),
		ApplyFunc:   func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
		VerifyFunc:  func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func sharedAction(cfg config.Config, backend base.ACLBackend) Action {
	return FuncAction{
		Description:  "configure shared-tree ACLs and bind alias",
		ApplyFunc:    func(ctx context.Context) error { return backend.GrantShared(ctx, cfg) },
		RollbackFunc: func(ctx context.Context) error { return backend.RevokeShared(ctx, cfg) },
		VerifyFunc:   func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func revokeSharedAction(cfg config.Config, backend base.ACLBackend) Action {
	return FuncAction{
		Description: "remove shared alias and revoke recorded ACLs",
		ApplyFunc:   func(ctx context.Context) error { return backend.RevokeShared(ctx, cfg) },
	}
}

func networkAction(cfg config.Config, backend base.NetworkBackend) Action {
	return FuncAction{
		Description:  "apply UID-scoped network policy",
		ApplyFunc:    func(ctx context.Context) error { return backend.Apply(ctx, cfg) },
		RollbackFunc: func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
		VerifyFunc:   func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func removeNetworkAction(cfg config.Config, backend base.NetworkBackend) Action {
	return FuncAction{
		Description: "remove recorded firewall policy",
		ApplyFunc:   func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
	}
}

func serviceAction(cfg config.Config, backend base.ServiceBackend) Action {
	return FuncAction{
		Description:  "install and enable isolation services",
		ApplyFunc:    func(ctx context.Context) error { return backend.Install(ctx, cfg) },
		RollbackFunc: func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
		VerifyFunc:   func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func removeServicesAction(cfg config.Config, backend base.ServiceBackend) Action {
	return FuncAction{
		Description: "disable and remove recorded isolation services",
		ApplyFunc:   func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
	}
}

func launcherAction(cfg config.Config, backend base.LauncherBackend) Action {
	return FuncAction{
		Description:  "install root-owned launcher symlinks",
		ApplyFunc:    func(ctx context.Context) error { return backend.Install(ctx, cfg) },
		RollbackFunc: func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
		VerifyFunc:   func(ctx context.Context) error { return backend.Verify(ctx, cfg) },
	}
}

func removeLaunchersAction(cfg config.Config, backend base.LauncherBackend) Action {
	return FuncAction{
		Description: "remove launcher symlinks",
		ApplyFunc:   func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
	}
}

func removeTemporaryAction(cfg config.Config, backend base.HostBackend) Action {
	return FuncAction{
		Description: "remove private temporary directory",
		ApplyFunc:   func(ctx context.Context) error { return backend.RemoveTemporary(ctx, cfg) },
	}
}

func removeRuntimeAction(cfg config.Config, backend base.RuntimeBackend) Action {
	return FuncAction{
		Description: fmt.Sprintf("remove runtime %s", cfg.RuntimeRoot),
		ApplyFunc:   func(ctx context.Context) error { return backend.Remove(ctx, cfg) },
	}
}

func verifyRemovedAction(cfg config.Config, backends base.Backends) Action {
	return FuncAction{
		Description: "verify removal",
		ApplyFunc:   func(context.Context) error { return nil },
		VerifyFunc:  func(ctx context.Context) error { return backends.Host.VerifyRemoved(ctx, cfg) },
	}
}

func saveStateAction(cfg config.Config, previous state.State, deps Deps) Action {
	var backup state.Backup
	hadState := false
	store := deps.Store
	return FuncAction{
		Description: "save installation state",
		ApplyFunc: func(context.Context) error {
			if _, err := os.Lstat(store.Path); err == nil {
				hadState = true
				value, err := store.Backup()
				if err != nil {
					return err
				}
				backup = value
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return store.Save(snapshot(cfg, previous, deps))
		},
		RollbackFunc: func(context.Context) error {
			if hadState && backup.Path != "" {
				return store.Restore(backup.Path)
			}
			if !hadState {
				if err := os.Remove(store.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			return nil
		},
	}
}

func removeStateAction(store state.Store) Action {
	var backup state.Backup
	hadState := false
	return FuncAction{
		Description: "remove saved state",
		ApplyFunc: func(context.Context) error {
			if _, err := os.Lstat(store.Path); err == nil {
				hadState = true
				value, err := store.Backup()
				if err != nil {
					return err
				}
				backup = value
			} else if errors.Is(err, os.ErrNotExist) {
				return nil
			} else {
				return err
			}
			if err := os.Remove(store.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		},
		RollbackFunc: func(context.Context) error {
			if hadState && backup.Path != "" {
				return store.Restore(backup.Path)
			}
			return nil
		},
	}
}

func snapshot(cfg config.Config, previous state.State, deps Deps) state.State {
	platform := deps.Platform
	if platform == "" {
		platform = "linux"
	}
	backend := deps.Backend
	if backend == "" {
		if platform == "darwin" {
			backend = "seatbelt"
		} else {
			backend = "bwrap"
		}
	}
	launchers := make([]state.Launcher, 0, len(cfg.CLIs)+1)
	for _, cli := range cfg.CLIs {
		launchers = append(launchers, state.Launcher{
			Name: services.LauncherName(cli), Path: services.LauncherPath(cli), Target: services.LibexecPath,
		})
		if cli == "claude" {
			launchers = append(launchers, state.Launcher{
				Name: "ai-review-file", Path: services.ReviewLauncher, Target: services.LibexecPath,
			})
		}
	}
	result := state.State{
		Version:   state.Version,
		Platform:  platform,
		Backend:   backend,
		Config:    cfg,
		Created:   state.Created{User: cfg.AIUser, Group: users.SharedGroup},
		Runtime:   state.Runtime{Path: cfg.RuntimeRoot, CLIs: cfg.CLIs},
		Launchers: launchers,
		Backups:   previous.Backups,
	}
	if platform == "darwin" {
		result.Shared = state.Shared{Path: cfg.SharedDir, ACL: "chmod"}
		return result
	}
	records := services.ServiceRecords()
	serviceRecords := make([]state.Service, 0, len(records))
	for _, record := range records {
		serviceRecords = append(serviceRecords, state.Service{Name: record.Name, Path: record.Path})
	}
	result.Shared = state.Shared{Path: cfg.SharedDir, ACL: "setfacl", Alias: cfg.SharedSource}
	result.Services = serviceRecords
	result.Firewall = &state.Firewall{Type: services.FirewallType, Table: services.FirewallTable}
	result.Mounts = []state.Mount{{
		Source: cfg.SharedDir, Target: cfg.SharedSource, Options: shared.AliasOptions(),
	}}
	return result
}
