package plan

import (
	"context"
	"fmt"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

func Install(cfg config.Config) Plan {
	return Plan{Operation: "install", Actions: []Action{
		unavailable("validate host and resolved backend"),
		unavailable("ensure AI user and groups"),
		unavailable("configure shared tree ACLs and alias"),
		unavailable(fmt.Sprintf("install and seal CLI runtime: %v", cfg.CLIs)),
		unavailable("apply network policy"),
		unavailable("install services and launcher symlinks"),
		unavailable("verify isolation and save state"),
	}}
}

func Update(st state.State) Plan {
	value := Install(st.Config)
	value.Operation = "update"
	return value
}

func Uninstall(st state.State) Plan {
	return Plan{Operation: "uninstall", Actions: []Action{
		unavailable("disable launchers and services recorded in state"),
		unavailable(fmt.Sprintf("remove %s firewall recorded in state", firewallType(st))),
		unavailable("remove shared alias and revoke recorded ACLs"),
		unavailable(fmt.Sprintf("remove runtime %s recorded in state", st.Runtime.Path)),
		unavailable("remove generated configuration and verify removal"),
	}}
}

func unavailable(name string) Action {
	return FuncAction{
		Description: name,
		ApplyFunc: func(context.Context) error {
			return ErrNotImplemented
		},
	}
}
