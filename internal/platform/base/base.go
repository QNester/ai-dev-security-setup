// Package base contains platform-neutral backend contracts.
package base

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

var ErrNotImplemented = errors.New("backend operation is not implemented")

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

type NetworkPolicy string

const (
	NetworkOpen  NetworkPolicy = "open"
	NetworkProxy NetworkPolicy = "proxy"
	NetworkDeny  NetworkPolicy = "deny"
)

type Endpoint struct {
	Host     string
	Port     uint16
	Protocol string
}

type Spec struct {
	Argv             []string
	Cwd              string
	Env              map[string]string
	ReadOnlyPaths    []string
	WritablePaths    []string
	Home             string
	Tmp              string
	Network          NetworkPolicy
	DNSServers       []string
	AllowedEndpoints []Endpoint
	ReviewFD         int
}

func (s Spec) Validate() error {
	if len(s.Argv) == 0 || s.Argv[0] == "" {
		return errors.New("sandbox argv is required")
	}
	if err := config.ValidatePath(s.Argv[0]); err != nil {
		return fmt.Errorf("sandbox executable must be a clean absolute path: %w", err)
	}
	switch s.Network {
	case NetworkOpen, NetworkProxy, NetworkDeny:
	default:
		return fmt.Errorf("invalid network policy %q", s.Network)
	}
	if s.ReviewFD < -1 {
		return errors.New("review fd must be -1 or a valid descriptor")
	}
	paths := []string{s.Cwd, s.Home, s.Tmp}
	paths = append(paths, s.ReadOnlyPaths...)
	paths = append(paths, s.WritablePaths...)
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := config.ValidatePath(path); err != nil {
			return fmt.Errorf("invalid sandbox path %q: %w", path, err)
		}
	}
	for _, server := range s.DNSServers {
		if _, err := netip.ParseAddr(server); err != nil {
			return fmt.Errorf("invalid DNS server %q", server)
		}
	}
	for _, endpoint := range s.AllowedEndpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
	}
	if s.Network == NetworkDeny && (len(s.DNSServers) != 0 || len(s.AllowedEndpoints) != 0) {
		return errors.New("deny network policy cannot contain exceptions")
	}
	return nil
}

func (e Endpoint) Validate() error {
	if e.Port == 0 || (e.Protocol != "tcp" && e.Protocol != "udp") {
		return errors.New("endpoint requires a nonzero port and tcp/udp protocol")
	}
	if _, err := netip.ParseAddr(e.Host); err != nil && !hostnamePattern.MatchString(e.Host) {
		return fmt.Errorf("invalid endpoint host %q", e.Host)
	}
	return nil
}

type UserBackend interface {
	EnsureUser(context.Context, Config) error
	EnsureGroup(context.Context, Config) error
	DeleteUser(context.Context, Config) error
}

type ACLBackend interface {
	GrantShared(context.Context, Config) error
	RevokeShared(context.Context, Config) error
	Verify(context.Context, Config) error
}

type Sandbox interface {
	Name() string
	Available(context.Context) error
	Wrap(context.Context, Spec) ([]string, error)
}

type NetworkBackend interface {
	Apply(context.Context, Config) error
	Verify(context.Context, Config) error
	Remove(context.Context, Config) error
}

type ServiceBackend interface {
	Install(context.Context, Config) error
	Remove(context.Context, Config) error
}

type ReviewBackend interface {
	Prepare(context.Context, string) (Spec, func(), error)
}

type Backends struct {
	Users    UserBackend
	ACL      ACLBackend
	Sandbox  Sandbox
	Network  NetworkBackend
	Services ServiceBackend
	Review   ReviewBackend
}
