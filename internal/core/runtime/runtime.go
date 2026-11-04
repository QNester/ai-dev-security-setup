// Package runtime contains portable CLI installation and sealing policy.
package runtime

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/QNester/ai-dev-security-setup/internal/config"
)

// HomeSuffix is the AI-owned subtree installers may write to before sealing.
const HomeSuffix = "runtime"

// NodeSuffix is the verified Node.js runtime used by Pi.
const NodeSuffix = "node"

// PreviousSuffix keeps the last sealed runtime until the next successful
// activation so a failed update can restore it.
const PreviousSuffix = ".runtime-previous"

// StageSuffix is the root-owned staging tree used while sealing.
const StageSuffix = ".runtime-stage"

// Home returns the AI-owned installer tree and the sealed runtime root.
func Home(cfg config.Config) string { return filepath.Join(cfg.RuntimeRoot, HomeSuffix) }

// NodeRoot returns the verified Node.js root.
func NodeRoot(cfg config.Config) string { return filepath.Join(cfg.RuntimeRoot, NodeSuffix) }

// OpenCodeConfigPath is the generated, non-secret OpenCode LiteLLM config.
func OpenCodeConfigPath(cfg config.Config) string {
	return filepath.Join(cfg.AIHome, ".config", "opencode", "ai-sandbox-litellm.json")
}

// SecretsPath is the AI-owned file sourced by the sandbox entrypoint.
func SecretsPath(cfg config.Config) string {
	return filepath.Join(cfg.AIHome, ".secrets", "env")
}

// Previous returns the rollback copy of the sealed runtime.
func Previous(cfg config.Config) string { return filepath.Join(cfg.RuntimeRoot, PreviousSuffix) }

// Stage returns the root-owned staging tree.
func Stage(cfg config.Config) string { return filepath.Join(cfg.RuntimeRoot, StageSuffix) }

// CandidatePaths lists the known install locations relative to an installer
// home. The first executable match wins.
func CandidatePaths(tool string) []string {
	switch tool {
	case "claude":
		return []string{".local/bin/claude"}
	case "kimi":
		return []string{".kimi-code/bin/kimi", ".local/bin/kimi"}
	case "pi":
		return []string{".pi/agent/bin/pi", ".local/bin/pi"}
	case "opencode":
		return []string{".opencode/bin/opencode", ".local/bin/opencode"}
	default:
		return nil
	}
}

// CandidatePath returns the clean absolute candidate path. Callers must still
// check that the file exists and is executable.
func CandidatePath(root, relative string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("runtime root must be a clean absolute path")
	}
	if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "..") {
		return "", fmt.Errorf("invalid runtime candidate %q", relative)
	}
	return filepath.Join(root, relative), nil
}

// Installer describes one trusted vendor installer.
type Installer struct {
	URL      string
	Shell    string
	NeedsTTY bool
}

// InstallerFor returns the fixed installer for a supported CLI.
func InstallerFor(tool string) (Installer, error) {
	switch tool {
	case "claude":
		return Installer{URL: "https://claude.ai/install.sh", Shell: "/bin/bash"}, nil
	case "kimi":
		return Installer{URL: "https://code.kimi.com/kimi-code/install.sh", Shell: "/bin/bash"}, nil
	case "pi":
		return Installer{URL: "https://pi.dev/install.sh", Shell: "/bin/sh"}, nil
	case "opencode":
		return Installer{URL: "https://opencode.ai/v2/install", Shell: "/bin/bash"}, nil
	default:
		return Installer{}, fmt.Errorf("unsupported CLI %q", tool)
	}
}

// InstallerEnv is the clean environment handed to vendor installers. It
// deliberately has no access to the owner's home or the shared tree.
func InstallerEnv(cfg config.Config, home, nodeRoot string) []string {
	path := filepath.Join(nodeRoot, "bin") + ":/usr/local/bin:/usr/bin:/bin"
	return []string{
		"HOME=" + home,
		"USER=" + cfg.AIUser,
		"LOGNAME=" + cfg.AIUser,
		"SHELL=/bin/bash",
		"PATH=" + path,
		"LANG=C.UTF-8",
		"TERM=dumb",
		"TMPDIR=" + home,
	}
}

// SandboxEnv is the minimal environment for a launched CLI.
func SandboxEnv(cfg config.Config) map[string]string {
	path := filepath.Join(NodeRoot(cfg), "bin") + ":" + filepath.Join(cfg.RuntimeRoot, "bin") + ":/usr/local/bin:/usr/bin:/bin"
	return map[string]string{
		"HOME":                cfg.AIHome,
		"USER":                cfg.AIUser,
		"LOGNAME":             cfg.AIUser,
		"SHELL":               "/bin/bash",
		"PATH":                path,
		"LANG":                "C.UTF-8",
		"TERM":                "xterm-256color",
		"TMPDIR":              "/tmp",
		"DISABLE_AUTOUPDATER": "1",
		"DISABLE_TELEMETRY":   "1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
	}
}

// SecretNames are installer-created credential paths that must never be sealed
// into the root-owned runtime.
func SecretNames() []string {
	return []string{
		".ssh", ".gnupg", ".aws", ".config", ".cache", ".netrc", ".npmrc",
		".pypirc", ".git-credentials", ".docker", ".npm",
	}
}

// WritableRoots lists agent-writable locations that a runtime symlink must
// never resolve into.
func WritableRoots(cfg config.Config) []string {
	roots := []string{
		cfg.AIHome, cfg.SharedDir, cfg.SharedSource, cfg.TmpRoot,
		"/tmp", "/var/tmp", "/dev/shm", "/run/user", "/proc", "/sys",
	}
	sort.Strings(roots)
	return roots
}

// ValidateCLIList checks a list of selected CLIs.
func ValidateCLIList(clis []string) error {
	seen := make(map[string]bool, len(clis))
	for _, cli := range clis {
		if len(CandidatePaths(cli)) == 0 {
			return fmt.Errorf("unsupported CLI %q", cli)
		}
		if seen[cli] {
			return fmt.Errorf("duplicate CLI %q", cli)
		}
		seen[cli] = true
	}
	if len(clis) == 0 {
		return fmt.Errorf("at least one CLI is required")
	}
	return nil
}
