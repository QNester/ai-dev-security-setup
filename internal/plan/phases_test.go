package plan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/state"
)

type fakeBackend struct {
	events []string
	fail   string
}

func (f *fakeBackend) add(name string) error {
	f.events = append(f.events, name)
	if f.fail == name {
		return errors.New("injected failure")
	}
	return nil
}

func (f *fakeBackend) Host() base.HostBackend        { return fakeHost{f} }
func (f *fakeBackend) Users() base.UserBackend       { return fakeUsers{f} }
func (f *fakeBackend) ACL() base.ACLBackend          { return fakeACL{f} }
func (f *fakeBackend) Runtime() base.RuntimeBackend  { return fakeRuntime{f} }
func (f *fakeBackend) Network() base.NetworkBackend  { return fakeNetwork{f} }
func (f *fakeBackend) Services() base.ServiceBackend { return fakeServices{f} }
func (f *fakeBackend) Launchers() base.LauncherBackend {
	return fakeLaunchers{f}
}

func (f *fakeBackend) backends() base.Backends {
	return base.Backends{
		Host: f.Host(), Users: f.Users(), ACL: f.ACL(), Runtime: f.Runtime(),
		Network: f.Network(), Services: f.Services(), Launchers: f.Launchers(),
	}
}

type fakeHost struct{ f *fakeBackend }

func (h fakeHost) Prepare(context.Context, base.Config) (bool, error) {
	return false, h.f.add("host.prepare")
}
func (h fakeHost) Verify(context.Context, base.Config) error { return h.f.add("host.verify") }
func (h fakeHost) VerifyRemoved(context.Context, base.Config) error {
	return h.f.add("host.verify-removed")
}
func (h fakeHost) RemoveTemporary(context.Context, base.Config) error {
	return h.f.add("host.remove-temporary")
}
func (h fakeHost) Cleanup(context.Context, base.Config) error { return h.f.add("host.cleanup") }

type fakeUsers struct{ f *fakeBackend }

func (u fakeUsers) EnsureGroup(context.Context, base.Config) (bool, error) {
	return true, u.f.add("users.group")
}
func (u fakeUsers) EnsureUser(context.Context, base.Config) (bool, error) {
	return true, u.f.add("users.user")
}
func (u fakeUsers) DeleteUser(context.Context, base.Config) error {
	return u.f.add("users.delete-user")
}
func (u fakeUsers) DeleteGroup(context.Context, base.Config) error {
	return u.f.add("users.delete-group")
}
func (u fakeUsers) Verify(context.Context, base.Config) error { return u.f.add("users.verify") }

type fakeACL struct{ f *fakeBackend }

func (a fakeACL) DenyOwner(context.Context, base.Config) error { return a.f.add("acl.deny-owner") }
func (a fakeACL) RevokeOwnerDeny(context.Context, base.Config) error {
	return a.f.add("acl.revoke-owner")
}
func (a fakeACL) GrantShared(context.Context, base.Config) error  { return a.f.add("acl.grant") }
func (a fakeACL) RevokeShared(context.Context, base.Config) error { return a.f.add("acl.revoke") }
func (a fakeACL) Verify(context.Context, base.Config) error       { return a.f.add("acl.verify") }

type fakeRuntime struct{ f *fakeBackend }

func (r fakeRuntime) Install(context.Context, base.Config) error  { return r.f.add("runtime.install") }
func (r fakeRuntime) Verify(context.Context, base.Config) error   { return r.f.add("runtime.verify") }
func (r fakeRuntime) Remove(context.Context, base.Config) error   { return r.f.add("runtime.remove") }
func (r fakeRuntime) Rollback(context.Context, base.Config) error { return r.f.add("runtime.rollback") }

type fakeNetwork struct{ f *fakeBackend }

func (n fakeNetwork) Apply(context.Context, base.Config) error  { return n.f.add("network.apply") }
func (n fakeNetwork) Verify(context.Context, base.Config) error { return n.f.add("network.verify") }
func (n fakeNetwork) Remove(context.Context, base.Config) error { return n.f.add("network.remove") }

type fakeServices struct{ f *fakeBackend }

func (s fakeServices) Install(context.Context, base.Config) error { return s.f.add("services.install") }
func (s fakeServices) Verify(context.Context, base.Config) error  { return s.f.add("services.verify") }
func (s fakeServices) Remove(context.Context, base.Config) error  { return s.f.add("services.remove") }

type fakeLaunchers struct{ f *fakeBackend }

func (l fakeLaunchers) Install(context.Context, base.Config) error {
	return l.f.add("launchers.install")
}
func (l fakeLaunchers) Verify(context.Context, base.Config) error { return l.f.add("launchers.verify") }
func (l fakeLaunchers) Remove(context.Context, base.Config) error { return l.f.add("launchers.remove") }

func testDeps(t *testing.T) (config.Config, Deps, *fakeBackend, state.Store) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("linux", "alice", "/home/alice")
	cfg.StatePath = filepath.Join(dir, "state.json")
	fake := new(fakeBackend)
	store := state.Store{Path: cfg.StatePath, Root: dir}
	return cfg, Deps{Backends: fake.backends(), Store: store}, fake, store
}

func TestInstallPlanAppliesEverythingAndSavesState(t *testing.T) {
	cfg, deps, fake, store := testDeps(t)
	value := Install(cfg, deps)
	if _, err := Execute(context.Background(), value, false); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Platform != "linux" || st.Runtime.Path != cfg.RuntimeRoot || len(st.Launchers) != len(cfg.CLIs)+1 {
		t.Fatalf("unexpected state: %+v", st)
	}
	text := strings.Join(fake.events, ",")
	for _, fragment := range []string{
		"host.prepare", "users.group", "users.user", "runtime.install", "acl.grant",
		"network.apply", "services.install", "launchers.install", "runtime.verify",
		"launchers.verify",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing event %s in %s", fragment, text)
		}
	}
}

func TestDarwinInstallSavesNativeState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("darwin", "John.Doe", "/Users/John Doe")
	cfg.StatePath = filepath.Join(dir, "state.json")
	fake := new(fakeBackend)
	store := state.Store{Path: cfg.StatePath, Root: dir}
	deps := Deps{Backends: fake.backends(), Store: store, Platform: "darwin", Backend: "seatbelt"}
	if _, err := Execute(context.Background(), Install(cfg, deps), false); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Platform != "darwin" || st.Backend != "seatbelt" || st.Shared.ACL != "chmod" {
		t.Fatalf("unexpected darwin state: %+v", st)
	}
	if st.Firewall != nil || len(st.Services) != 0 || len(st.Mounts) != 0 {
		t.Fatalf("darwin state contains Linux resources: %+v", st)
	}
	if len(st.Launchers) != len(cfg.CLIs)+1 {
		t.Fatalf("launchers=%v", st.Launchers)
	}
}

func TestInstallFailureRollsBackRuntimeAndDoesNotSaveState(t *testing.T) {
	cfg, deps, fake, store := testDeps(t)
	fake.fail = "network.apply"
	if _, err := Execute(context.Background(), Install(cfg, deps), false); err == nil {
		t.Fatal("expected failure")
	}
	text := strings.Join(fake.events, ",")
	for _, fragment := range []string{
		"network.remove", "acl.revoke", "runtime.rollback", "users.delete-user", "users.delete-group",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing rollback %s in %s", fragment, text)
		}
	}
	if _, err := os.Lstat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state survived a failed install: %v", err)
	}
}

func TestUninstallFollowsSavedState(t *testing.T) {
	cfg, deps, fake, store := testDeps(t)
	if _, err := Execute(context.Background(), Install(cfg, deps), false); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	fake.events = nil
	if _, err := Execute(context.Background(), Uninstall(st, deps), false); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(fake.events, ",")
	for _, fragment := range []string{
		"host.cleanup", "services.remove", "network.remove", "launchers.remove",
		"runtime.remove", "acl.revoke", "host.verify-removed",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing uninstall step %s in %s", fragment, text)
		}
	}
	if _, err := os.Lstat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state was not removed: %v", err)
	}
}
