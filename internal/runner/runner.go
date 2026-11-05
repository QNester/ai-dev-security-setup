// Package runner executes subprocesses without a shell or inherited environment.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const DefaultMaxOutputBytes = 1024 * 1024

type Command struct {
	Path           string
	Args           []string
	Env            []string
	Dir            string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	ExtraFiles     []*os.File
	Credential     *syscall.Credential
	MaxOutputBytes int64
}

type Result struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	StdoutTruncated bool
	StderrTruncated bool
}

type Runner interface {
	Run(context.Context, Command) (Result, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, command Command) (Result, error) {
	if command.Path == "" || !filepath.IsAbs(command.Path) || filepath.Clean(command.Path) != command.Path {
		return Result{}, errors.New("command path must be clean and absolute")
	}
	if command.MaxOutputBytes < 0 {
		return Result{}, errors.New("max output bytes cannot be negative")
	}
	limit := command.MaxOutputBytes
	if limit == 0 {
		limit = DefaultMaxOutputBytes
	}
	cmd := exec.CommandContext(ctx, command.Path, command.Args...)
	cmd.Env = command.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Dir = command.Dir
	cmd.Stdin = command.Stdin
	cmd.ExtraFiles = command.ExtraFiles
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: command.Credential}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	stdout := &limitedBuffer{remaining: limit}
	stderr := &limitedBuffer{remaining: limit}
	if command.Stdout != nil {
		cmd.Stdout = command.Stdout
	} else {
		cmd.Stdout = stdout
	}
	if command.Stderr != nil {
		cmd.Stderr = command.Stderr
	} else {
		cmd.Stderr = stderr
	}
	err := cmd.Run()
	result := Result{
		Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: 0,
		StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated,
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		return result, fmt.Errorf("run %s: %w", command.Path, err)
	}
	return result, nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int64
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.remaining > 0 {
		if int64(len(p)) <= b.remaining {
			_, _ = b.buffer.Write(p)
			b.remaining -= int64(len(p))
		} else {
			keep := int(b.remaining)
			_, _ = b.buffer.Write(p[:keep])
			b.remaining = 0
			b.truncated = true
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return original, nil
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}
