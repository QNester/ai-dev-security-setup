//go:build e2e && linux

package e2eguest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	ownerUser = "alice"
	ownerHome = "/home/alice"
	sharedDir = "/home/alice/Developer"
	statePath = "/var/lib/ai-sandbox/state.json"
)

func TestLifecycle(t *testing.T) {
	if os.Getenv("SANDBOXCTL_E2E") != "1" {
		t.Skip("set SANDBOXCTL_E2E=1 inside a disposable VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("e2e must run as root")
	}
	if _, err := os.Stat("/etc/sandboxctl-e2e"); err != nil {
		t.Fatal("missing /etc/sandboxctl-e2e sentinel; refusing to mutate this host")
	}
	bin := os.Getenv("SANDBOXCTL_BIN")
	if bin == "" || !filepath.IsAbs(bin) {
		t.Fatal("SANDBOXCTL_BIN must be an absolute path")
	}
	info, err := os.Stat(bin)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("invalid sandboxctl binary %q: %v", bin, err)
	}
	ctx := context.Background()
	ensureOwner(t)
	setupFakeRuntime(t)
	defer func() {
		_, _ = output(ctx, bin, "uninstall", "--yes", "--no-color")
	}()

	runOK(t, ctx, bin, "install",
		"--cli", "claude", "--skip-cli", "--yes", "--no-color",
		"--owner-user", ownerUser, "--owner-home", ownerHome,
		"--shared-dir", sharedDir,
	)
	assertInstall(t, ctx)
	assertEnterAndReview(t, ctx, bin)
	runOK(t, ctx, bin, "update", "--skip-cli", "--yes", "--no-color")
	runOK(t, ctx, bin, "uninstall", "--yes", "--no-color")
	assertUninstall(t)
}

func ensureOwner(t *testing.T) {
	t.Helper()
	if _, err := try(context.Background(), "id", "-u", ownerUser); err != nil {
		runOK(t, context.Background(), "useradd", "-m", "-s", "/bin/bash", ownerUser)
	}
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runOK(t, context.Background(), "chown", "-R", ownerUser+":"+ownerUser, ownerHome)
}

func setupFakeRuntime(t *testing.T) {
	t.Helper()
	_ = os.RemoveAll("/opt/ai-tools")
	binary := "/opt/ai-tools/runtime/.local/bin/claude"
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
if [ -r /review/input ]; then
    cat /review/input
    exit $?
fi
printf 'fake-claude'
for arg in "$@"; do printf ' %s' "$arg"; done
printf '\nHOME=%s\nPWD=%s\n' "$HOME" "$PWD"
`
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/opt/ai-tools/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, "/opt/ai-tools/bin/claude"); err != nil {
		t.Fatal(err)
	}
}

func assertInstall(t *testing.T, ctx context.Context) {
	t.Helper()
	uid, err := output(ctx, "id", "-u", "ai-dev")
	if err != nil || strings.TrimSpace(uid) == "0" || strings.TrimSpace(uid) == "" {
		t.Fatalf("ai-dev UID is unsafe: %q err=%v", uid, err)
	}
	groups, err := output(ctx, "id", "-nG", "ai-dev")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(groups, "ai-dev-share") {
		t.Fatalf("ai-dev-share missing from groups: %q", groups)
	}
	if _, err := output(ctx, "runuser", "-u", "ai-dev", "--", "ls", ownerHome); err == nil {
		t.Fatal("AI user can list the owner home")
	}
	if _, err := output(ctx, "runuser", "-u", "ai-dev", "--", "test", "-e", filepath.Join(ownerHome, ".ssh")); err == nil {
		t.Fatal("AI user can see the owner .ssh path")
	}
	runOK(t, ctx, "runuser", "-u", "ai-dev", "--", "touch", "/srv/ai-dev-shared/e2e-acl")
	runOK(t, ctx, "runuser", "-u", ownerUser, "--", "test", "-r", "/srv/ai-dev-shared/e2e-acl")
	_ = os.Remove("/srv/ai-dev-shared/e2e-acl")
	options, err := output(ctx, "findmnt", "-n", "-M", "/srv/ai-dev-shared", "-o", "OPTIONS")
	if err != nil {
		t.Fatalf("shared alias missing: %v", err)
	}
	for _, option := range []string{"nosuid", "nodev"} {
		if !strings.Contains(options, option) {
			t.Fatalf("shared alias missing %s: %q", option, options)
		}
	}
	runOK(t, ctx, "nft", "list", "table", "ip", "ai_dev_isolation")
	runOK(t, ctx, "systemctl", "is-active", "ai-dev-isolation.service")
	link, err := os.Readlink("/usr/local/bin/claude-secure")
	if err != nil || link != "/usr/local/libexec/sandboxctl" {
		t.Fatalf("unexpected launcher: target=%q err=%v", link, err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state was not saved: %v", err)
	}
}

func assertEnterAndReview(t *testing.T, ctx context.Context, bin string) {
	t.Helper()
	entered, err := output(ctx, bin, "enter", "--tool", "claude", "--no-color", "--", "--version")
	if err != nil {
		t.Fatalf("enter failed: %v\n%s", err, entered)
	}
	for _, fragment := range []string{"fake-claude", "HOME=/home/ai-dev"} {
		if !strings.Contains(entered, fragment) {
			t.Fatalf("enter output missing %q:\n%s", fragment, entered)
		}
	}
	if strings.Contains(entered, ownerHome) {
		t.Fatalf("enter exposed owner home:\n%s", entered)
	}
	input := filepath.Join(sharedDir, "review.txt")
	content := "e2e review input\n"
	if err := os.WriteFile(input, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	reviewed, err := output(ctx, bin, "review", "--no-color", input)
	if err != nil {
		t.Fatalf("review failed: %v\n%s", err, reviewed)
	}
	if reviewed != content {
		t.Fatalf("review output=%q want=%q", reviewed, content)
	}
	link := filepath.Join(sharedDir, "review-link.txt")
	if err := os.Symlink(input, link); err != nil {
		t.Fatal(err)
	}
	if _, err := output(ctx, bin, "review", "--no-color", link); err == nil {
		t.Fatal("review accepted a symlink")
	}
	outside := filepath.Join(ownerHome, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := output(ctx, bin, "review", "--no-color", outside); err == nil {
		t.Fatal("review accepted a file outside the shared tree")
	}
}

func assertUninstall(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state survived uninstall: %v", err)
	}
	for _, path := range []string{
		"/usr/local/libexec/sandboxctl",
		"/usr/local/bin/claude-secure",
		"/opt/ai-tools",
		"/var/lib/ai-sandbox/tmp",
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived uninstall: %v", path, err)
		}
	}
	if _, err := output(context.Background(), "id", "-u", "ai-dev"); err != nil {
		t.Fatalf("uninstall removed the AI account: %v", err)
	}
}

func runOK(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	value, err := output(ctx, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, value)
	}
}

func output(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	data, err := command.CombinedOutput()
	return string(data), err
}

func try(ctx context.Context, name string, args ...string) (string, error) {
	return output(ctx, name, args...)
}
