// Package vm defines VM providers that delegate enforcement to a Linux guest.
package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"text/template"

	"github.com/QNester/ai-dev-security-setup/internal/runner"
	"github.com/QNester/ai-dev-security-setup/internal/templates"
)

const DefaultInstance = "sandboxctl"

// Config describes a Lima guest. It is intentionally small: the guest runs the
// existing Linux backend once the Linux artifact is available.
type Config struct {
	Instance   string
	Arch       string
	CPUs       int
	Memory     string
	Disk       string
	SharedDir  string
	MountHome  bool
	GuestReady bool
}

type Provider interface {
	Name() string
	Available(context.Context) error
	Ensure(context.Context, Config) error
	Start(context.Context, Config) error
	Stop(context.Context, Config) error
	Delete(context.Context, Config) error
	Shell(context.Context, Config, string, []string, []string) error
	Copy(context.Context, Config, string, string) error
}

// Lima implements Provider through limactl. All commands are argv based; no
// shell wrapper is generated.
type Lima struct {
	Runner   runner.Runner
	LookPath func(string) (string, error)
}

func (Lima) Name() string { return "lima" }

func (l Lima) Available(ctx context.Context) error {
	if _, err := l.limactl(); err != nil {
		return err
	}
	return nil
}

func (l Lima) Ensure(ctx context.Context, cfg Config) error {
	if err := l.Available(ctx); err != nil {
		return err
	}
	if cfg.SharedDir == "" || !filepath.IsAbs(cfg.SharedDir) {
		return errors.New("VM shared directory must be absolute")
	}
	if l.exists(ctx, instance(cfg)) {
		return nil
	}
	data, err := renderLimaConfig(cfg)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp("", "sandboxctl-lima-*.yaml")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return l.run(ctx, "create", "--name", instance(cfg), path)
}

func (l Lima) Start(ctx context.Context, cfg Config) error {
	if err := l.Ensure(ctx, cfg); err != nil {
		return err
	}
	return l.run(ctx, "start", "--name", instance(cfg), "--tty=false")
}

func (l Lima) Stop(ctx context.Context, cfg Config) error {
	return l.run(ctx, "stop", instance(cfg))
}

func (l Lima) Delete(ctx context.Context, cfg Config) error {
	return l.run(ctx, "delete", "--force", instance(cfg))
}

func (l Lima) Shell(ctx context.Context, cfg Config, dir string, env []string, argv []string) error {
	if len(argv) == 0 {
		return errors.New("guest command is required")
	}
	if dir == "" {
		dir = "/"
	}
	if err := l.Start(ctx, cfg); err != nil {
		return err
	}
	args := []string{"shell", "--workdir", dir, instance(cfg), "--"}
	if len(env) > 0 {
		args = append(args, "/usr/bin/env", "-i")
		args = append(args, env...)
	}
	args = append(args, argv...)
	return l.run(ctx, args...)
}

func (l Lima) Copy(ctx context.Context, cfg Config, source, target string) error {
	if !filepath.IsAbs(source) || !filepath.IsAbs(target) {
		return errors.New("VM copy paths must be absolute")
	}
	if err := l.Start(ctx, cfg); err != nil {
		return err
	}
	return l.run(ctx, "copy", source, instance(cfg)+":"+target)
}

func (l Lima) exists(ctx context.Context, name string) bool {
	result, err := l.runResult(ctx, "list", "--json")
	if err != nil {
		return false
	}
	var values []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal([]byte(result.Stdout), &values) != nil {
		return false
	}
	for _, value := range values {
		if value.Name == name {
			return true
		}
	}
	return false
}

func (l Lima) limactl() (string, error) {
	look := l.LookPath
	if look == nil {
		look = exec.LookPath
	}
	path, err := look("limactl")
	if err != nil {
		return "", fmt.Errorf("limactl is unavailable: %w", err)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("limactl resolved to an unsafe path %q", path)
	}
	return path, nil
}

func (l Lima) run(ctx context.Context, args ...string) error {
	_, err := l.runResult(ctx, args...)
	return err
}

func (l Lima) runResult(ctx context.Context, args ...string) (runner.Result, error) {
	path, err := l.limactl()
	if err != nil {
		return runner.Result{}, err
	}
	r := l.Runner
	if r == nil {
		r = runner.OSRunner{}
	}
	result, err := r.Run(ctx, runner.Command{
		Path: path, Args: args,
		Env:            []string{"PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"},
		MaxOutputBytes: 1024 * 1024,
	})
	if err != nil {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.Stdout)
		}
		if detail != "" {
			return result, fmt.Errorf("limactl %s: %w: %s", args[0], err, detail)
		}
		return result, fmt.Errorf("limactl %s: %w", args[0], err)
	}
	return result, nil
}

func instance(cfg Config) string {
	if cfg.Instance != "" {
		return cfg.Instance
	}
	return DefaultInstance
}

func renderLimaConfig(cfg Config) ([]byte, error) {
	data, err := templates.FS.ReadFile("vm/lima.yaml")
	if err != nil {
		return nil, err
	}
	return renderTemplate(string(data), map[string]any{
		"Instance":  instance(cfg),
		"Arch":      defaultArch(cfg.Arch),
		"CPUs":      defaultInt(cfg.CPUs, 4),
		"Memory":    defaultString(cfg.Memory, "8GiB"),
		"Disk":      defaultString(cfg.Disk, "60GiB"),
		"SharedDir": cfg.SharedDir,
		"MountHome": cfg.MountHome,
	})
}

func defaultArch(value string) string {
	if value == "amd64" || value == "x86_64" {
		return "x86_64"
	}
	if value == "arm64" || value == "aarch64" {
		return "aarch64"
	}
	if value == "" {
		if goruntime.GOARCH == "amd64" {
			return "x86_64"
		}
		return "aarch64"
	}
	return value
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func renderTemplate(source string, values map[string]any) ([]byte, error) {
	tmpl, err := template.New("lima.yaml").Option("missingkey=error").Parse(source)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, values); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
