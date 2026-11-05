package darwin

import (
	"context"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

// Network is intentionally per-execution on native macOS: restrictions belong
// to the generated Seatbelt profile, not to a system-wide nftables service.
type Network struct{ Deps Deps }

func (n Network) Apply(context.Context, config.Config) error {
	if _, err := n.Deps.lookPath("sandbox-exec"); err != nil {
		return err
	}
	return nil
}

func (n Network) Verify(context.Context, config.Config) error {
	if _, err := n.Deps.lookPath("sandbox-exec"); err != nil {
		return err
	}
	return nil
}

func (Network) Remove(context.Context, config.Config) error { return nil }

// Services are empty for the native backend: Seatbelt is applied per launch,
// so there is no daemon or firewall unit to install.
type Services struct{}

func (Services) Install(context.Context, config.Config) error { return nil }
func (Services) Verify(context.Context, config.Config) error  { return nil }
func (Services) Remove(context.Context, config.Config) error  { return nil }
