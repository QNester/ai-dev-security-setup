package runner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SANDBOXCTL_TEST_HELPER") != "1" {
		return
	}
	fmt.Printf("args=%s inherited=%s", strings.Join(os.Args, ","), os.Getenv("MUST_NOT_INHERIT"))
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
