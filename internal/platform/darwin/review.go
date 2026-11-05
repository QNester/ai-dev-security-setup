package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/review"
	coreruntime "github.com/QNester/ai-dev-security-setup/internal/core/runtime"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

type Review struct{}

// Review validates the input and copies it into a root-owned staging
// directory. The Seatbelt profile can then expose only that file instead of
// the shared tree.
func (Review) Prepare(ctx context.Context, cfg config.Config, path string) (base.ReviewResult, error) {
	if err := ctx.Err(); err != nil {
		return base.ReviewResult{}, err
	}
	if os.Geteuid() != 0 {
		return base.ReviewResult{}, errors.New("macOS review staging requires root")
	}
	source, data, err := review.OpenText(cfg, path)
	if err != nil {
		return base.ReviewResult{}, err
	}
	_ = source.Close()
	claude := filepath.Join(cfg.RuntimeRoot, "bin", "claude")
	binary, err := os.Stat(claude)
	if err != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0o111 == 0 {
		return base.ReviewResult{}, errors.New("review requires the claude CLI to be installed")
	}
	parent := filepath.Dir(cfg.TmpRoot)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return base.ReviewResult{}, fmt.Errorf("create review staging parent: %w", err)
	}
	stage, err := os.MkdirTemp(parent, "review-")
	if err != nil {
		return base.ReviewResult{}, fmt.Errorf("create review staging directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(stage) }
	if err := os.Chmod(stage, 0o755); err != nil {
		cleanup()
		return base.ReviewResult{}, err
	}
	input := filepath.Join(stage, "input")
	if err := os.WriteFile(input, data, 0o444); err != nil {
		cleanup()
		return base.ReviewResult{}, fmt.Errorf("stage review input: %w", err)
	}
	env := coreruntime.SandboxEnv(cfg)
	env["TMPDIR"] = cfg.TmpRoot
	spec := base.Spec{
		Argv:          review.CommandArgv(claude, input),
		Cwd:           stage,
		Env:           env,
		ReadOnlyPaths: coreruntime.ReadOnlyPaths(cfg),
		Home:          cfg.AIHome,
		Tmp:           cfg.TmpRoot,
		Network:       base.NetworkOpen,
		Review:        true,
		ReviewFD:      -1,
		ReviewPath:    input,
	}
	if err := spec.Validate(); err != nil {
		cleanup()
		return base.ReviewResult{}, err
	}
	return base.ReviewResult{Spec: spec, Cleanup: cleanup}, nil
}
