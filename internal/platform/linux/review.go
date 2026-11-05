package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	"github.com/QNester/ai-dev-security-setup/internal/core/review"
	coreruntime "github.com/QNester/ai-dev-security-setup/internal/core/runtime"
	"github.com/QNester/ai-dev-security-setup/internal/platform/base"
)

type Review struct{ Deps Deps }

func (r Review) Prepare(ctx context.Context, cfg config.Config, path string) (base.ReviewResult, error) {
	if err := ctx.Err(); err != nil {
		return base.ReviewResult{}, err
	}
	file, _, err := review.OpenText(cfg, path)
	if err != nil {
		return base.ReviewResult{}, err
	}
	cleanup := func() { _ = file.Close() }
	claude := filepath.Join(cfg.RuntimeRoot, "bin", "claude")
	binary, err := os.Stat(claude)
	if err != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0o111 == 0 {
		cleanup()
		return base.ReviewResult{}, errors.New("review requires the claude CLI to be installed")
	}
	mounts := make([]base.BindMount, 0, 1)
	if resolved, ok := coreruntime.ResolvConf(); ok {
		mounts = append(mounts, base.BindMount{
			Source: resolved, Target: "/etc/resolv.conf", ReadOnly: true,
		})
	}
	spec := base.Spec{
		Argv:          review.CommandArgv(claude, "/review/input"),
		Cwd:           "/review",
		Env:           coreruntime.SandboxEnv(cfg),
		ReadOnlyPaths: coreruntime.ReadOnlyPaths(cfg),
		BindMounts:    mounts,
		Home:          cfg.AIHome,
		Network:       base.NetworkOpen,
		Review:        true,
		ReviewFD:      3,
	}
	if err := spec.Validate(); err != nil {
		cleanup()
		return base.ReviewResult{}, err
	}
	return base.ReviewResult{Spec: spec, Files: []*os.File{file}, Cleanup: cleanup}, nil
}
