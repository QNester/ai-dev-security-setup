// Package base contains platform-neutral backend contracts.
package base

import (
	"context"
	"errors"
	"fmt"
)

var ErrNotImplemented = errors.New("backend operation is not implemented")

type NetworkPolicy string

const (
	NetworkOpen  NetworkPolicy = "open"
	NetworkProxy NetworkPolicy = "proxy"
	NetworkDeny  NetworkPolicy = "deny"
)

type Spec struct {
	Argv          []string
	Cwd           string
	Env           map[string]string
	ReadOnlyPaths []string
	WritablePaths []string
	Home          string
	Tmp           string
	Network       NetworkPolicy
	ReviewFD      int
}

func (s Spec) Validate() error {
	if len(s.Argv) == 0 || s.Argv[0] == "" {
		return errors.New("sandbox argv is required")
	}
	switch s.Network {
	case NetworkOpen, NetworkProxy, NetworkDeny:
	default:
		return fmt.Errorf("invalid network policy %q", s.Network)
	}
	if s.ReviewFD < -1 {
		return errors.New("review fd must be -1 or a valid descriptor")
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
