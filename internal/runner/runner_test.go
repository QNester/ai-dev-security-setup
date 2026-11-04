package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SANDBOXCTL_TEST_HELPER") != "1" {
		return
	}
	switch os.Getenv("SANDBOXCTL_HELPER_MODE") {
	case "exit":
		fmt.Fprint(os.Stderr, "failed deliberately")
		os.Exit(5)
	case "large":
		fmt.Print(strings.Repeat("x", 2048))
	default:
		fmt.Printf("args=%s inherited=%s", strings.Join(os.Args, ","), os.Getenv("MUST_NOT_INHERIT"))
	}
}

func TestRunnerUsesArgvAndExplicitEnvironment(t *testing.T) {
	t.Setenv("MUST_NOT_INHERIT", "leaked")
	result, err := (OSRunner{}).Run(context.Background(), Command{
		Path: os.Args[0],
		Args: []string{"-test.run=TestHelperProcess", "value with spaces;touch nope"},
		Env:  []string{"SANDBOXCTL_TEST_HELPER=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Stdout, "value with spaces;touch nope") {
		t.Fatalf("argument was not preserved: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "inherited=") || strings.Contains(result.Stdout, "inherited=leaked") {
		t.Fatalf("environment was inherited: %q", result.Stdout)
	}
}

func TestRunnerReportsNonzeroExit(t *testing.T) {
	result, err := (OSRunner{}).Run(context.Background(), Command{
		Path: os.Args[0], Args: []string{"-test.run=TestHelperProcess"},
		Env: []string{"SANDBOXCTL_TEST_HELPER=1", "SANDBOXCTL_HELPER_MODE=exit"},
	})
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || result.ExitCode != 5 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.Stderr != "failed deliberately" {
		t.Fatalf("stderr=%q", result.Stderr)
	}
}

func TestRunnerBoundsCapturedOutput(t *testing.T) {
	result, err := (OSRunner{}).Run(context.Background(), Command{
		Path: os.Args[0], Args: []string{"-test.run=TestHelperProcess"},
		Env:            []string{"SANDBOXCTL_TEST_HELPER=1", "SANDBOXCTL_HELPER_MODE=large"},
		MaxOutputBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Stdout) != 32 || !result.StdoutTruncated {
		t.Fatalf("output length=%d truncated=%v", len(result.Stdout), result.StdoutTruncated)
	}
}

func TestRunnerRejectsRelativeExecutable(t *testing.T) {
	_, err := (OSRunner{}).Run(context.Background(), Command{Path: "true"})
	if err == nil {
		t.Fatal("relative executable was accepted")
	}
}
