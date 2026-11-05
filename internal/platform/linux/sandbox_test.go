package linux

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
	"github.com/QNester/ai-dev-security-setup/internal/runner"
)

type recordingRunner struct {
	command runner.Command
	result  runner.Result
	err     error
}

func (r *recordingRunner) Run(_ context.Context, command runner.Command) (runner.Result, error) {
	r.command = command
	return r.result, r.err
}

func TestSandboxAvailableRunsRealUserNamespaceCheck(t *testing.T) {
	recorder := new(recordingRunner)
	sandbox := Sandbox{CommandRunner: recorder}
	if err := sandbox.Available(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"--unshare-user", "--ro-bind", "/", "/", "/usr/bin/true"}
	if recorder.command.Path != "/usr/bin/bwrap" || !reflect.DeepEqual(recorder.command.Args, want) {
		t.Fatalf("unexpected command: %+v", recorder.command)
	}
	if len(recorder.command.Env) != 1 || recorder.command.Env[0] != "PATH=/usr/bin:/bin" {
		t.Fatalf("unexpected env: %v", recorder.command.Env)
	}
}

func TestSandboxAvailableFailsClosed(t *testing.T) {
	recorder := &recordingRunner{err: errors.New("denied")}
	if err := (Sandbox{CommandRunner: recorder}).Available(context.Background()); err == nil {
		t.Fatal("expected namespace error")
	}
}

func TestWrapBuildsBubblewrapArgv(t *testing.T) {
	spec := base.Spec{
		Argv: []string{"/opt/ai-tools/bin/claude", "--version"},
		Cwd:  "/home/alice/Developer", Home: "/home/ai-dev", Tmp: "/var/lib/ai-sandbox/tmp",
		Env:           map[string]string{"Z_LAST": "z", "HOME": "/home/ai-dev", "A_FIRST": "a"},
		ReadOnlyPaths: []string{"/etc/resolv.conf", "/opt/ai-tools"},
		WritablePaths: []string{"/home/alice/Developer", "/home/ai-dev"},
		Network:       base.NetworkOpen, ReviewFD: -1,
	}
	argv, err := (Sandbox{}).Wrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "/usr/bin/bwrap" {
		t.Fatalf("argv[0]=%q", argv[0])
	}
	joined := strings.Join(argv, "\x00")
	for _, fragment := range []string{
		"--unshare-user", "--cap-drop\x00ALL", "--ro-bind\x00/opt/ai-tools\x00/opt/ai-tools",
		"--bind\x00/home/alice/Developer\x00/home/alice/Developer", "--bind\x00/var/lib/ai-sandbox/tmp\x00/tmp",
		"--setenv\x00A_FIRST\x00a", "--setenv\x00HOME\x00/home/ai-dev", "--setenv\x00Z_LAST\x00z",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("missing %q in %v", fragment, argv)
		}
	}
	if strings.Index(joined, "A_FIRST") > strings.Index(joined, "Z_LAST") {
		t.Fatal("environment is not sorted")
	}
	gotTail := argv[len(argv)-2:]
	if !reflect.DeepEqual(gotTail, spec.Argv) {
		t.Fatalf("command tail=%v", gotTail)
	}
}

func TestWrapBindsReviewDescriptorWithoutSharedTree(t *testing.T) {
	spec := base.Spec{
		Argv:     []string{"/opt/ai-tools/bin/claude", "--print"},
		Cwd:      "/review",
		Env:      map[string]string{"HOME": "/home/ai-dev"},
		Home:     "/home/ai-dev",
		Network:  base.NetworkOpen,
		ReviewFD: 3,
	}
	argv, err := (Sandbox{}).Wrap(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, "\x00")
	for _, fragment := range []string{
		"--dir\x00/review", "--ro-bind-data\x003\x00/review/input", "--chdir\x00/review",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("missing %q in %v", fragment, argv)
		}
	}
	if strings.Contains(joined, "/home/alice/Developer") {
		t.Fatalf("review argv leaked the shared tree: %v", argv)
	}
}

func TestWrapRejectsUnsafeSpecs(t *testing.T) {
	valid := base.Spec{Argv: []string{"/usr/bin/true"}, Network: base.NetworkOpen, ReviewFD: -1}
	for name, mutate := range map[string]func(*base.Spec){
		"mount conflict": func(s *base.Spec) {
			s.ReadOnlyPaths = []string{"/shared"}
			s.WritablePaths = []string{"/shared"}
		},
		"invalid env": func(s *base.Spec) { s.Env = map[string]string{"BAD-NAME": "x"} },
	} {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if _, err := (Sandbox{}).Wrap(context.Background(), spec); err == nil {
				t.Fatal("expected wrap error")
			}
		})
	}
}

func TestWrapHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spec := base.Spec{Argv: []string{"/usr/bin/true"}, Network: base.NetworkOpen, ReviewFD: -1}
	if _, err := (Sandbox{}).Wrap(ctx, spec); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}
