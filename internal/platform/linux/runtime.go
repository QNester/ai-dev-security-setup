package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QNester/ai-dev-security-setup/internal/config"
	coreruntime "github.com/QNester/ai-dev-security-setup/internal/core/runtime"
	"github.com/QNester/ai-dev-security-setup/internal/core/services"
	"github.com/QNester/ai-dev-security-setup/internal/core/users"
	"github.com/QNester/ai-dev-security-setup/internal/fsx"
)

const nodeDist = "https://nodejs.org/dist/latest-v22.x/"

var nodeArchivePattern = regexp.MustCompile(`^node-v[0-9A-Za-z._-]+-linux-(x64|arm64|armv7l|ppc64le|s390x)\.tar\.xz$`)

type Runtime struct{ Deps Deps }

func (r Runtime) Install(ctx context.Context, cfg config.Config) (err error) {
	if err := coreruntime.ValidateCLIList(cfg.CLIs); err != nil {
		return err
	}
	if err := r.ensureRoot(cfg); err != nil {
		return err
	}
	if err := r.prepareAIHome(cfg); err != nil {
		return err
	}
	for _, tool := range config.SupportedCLIs {
		_ = os.Remove(filepath.Join(cfg.RuntimeRoot, "bin", tool))
	}
	if !contains(cfg.CLIs, "pi") {
		_ = os.RemoveAll(coreruntime.NodeRoot(cfg))
	}
	home := coreruntime.Home(cfg)
	previous := coreruntime.Previous(cfg)
	pending := runtimeMarkerPending(cfg)
	committed := runtimeMarkerCommitted(cfg)
	if r.Deps.ok(ctx, "findmnt", "-M", home) {
		return fmt.Errorf("runtime home is a mountpoint: %s", home)
	}
	if _, statErr := os.Lstat(pending); statErr == nil {
		// A previous install was interrupted after moving the old runtime
		// aside. Put it back before starting a new transaction.
		if err := r.Rollback(ctx, cfg); err != nil {
			return fmt.Errorf("recover interrupted runtime install: %w", err)
		}
	} else if !isNotExist(statErr) {
		return statErr
	}
	_ = os.Remove(committed)
	if _, statErr := os.Lstat(home); isNotExist(statErr) {
		if _, previousErr := os.Lstat(previous); previousErr == nil {
			if err := os.Rename(previous, home); err != nil {
				return fmt.Errorf("recover interrupted runtime rename: %w", err)
			}
		}
	}
	if err := assertNoMounts(ctx, r.Deps, previous); err != nil {
		return err
	}
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("remove stale runtime backup: %w", err)
	}
	hadPrevious := false
	if _, statErr := os.Lstat(home); statErr == nil {
		if err := os.Rename(home, previous); err != nil {
			return fmt.Errorf("back up existing runtime: %w", err)
		}
		hadPrevious = true
	} else if !isNotExist(statErr) {
		return statErr
	}
	defer func() {
		if err == nil {
			return
		}
		if assertNoMounts(ctx, r.Deps, home) == nil {
			_ = os.RemoveAll(home)
		}
		if hadPrevious {
			_ = os.Rename(previous, home)
		}
		_ = os.Remove(pending)
		_ = os.Remove(committed)
	}()
	if err := os.WriteFile(pending, []byte("pending\n"), 0o600); err != nil {
		return fmt.Errorf("record runtime transaction: %w", err)
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return fmt.Errorf("create runtime home: %w", err)
	}
	ids, err := r.Deps.LookupIDs(cfg)
	if err != nil {
		return err
	}
	if err := os.Chown(home, int(ids.User), int(ids.Group)); err != nil {
		return fmt.Errorf("give runtime home to AI account: %w", err)
	}
	if err := os.Chmod(home, 0o755); err != nil {
		return err
	}
	if contains(cfg.CLIs, "pi") {
		if err := r.ensureNode(ctx, cfg); err != nil {
			return err
		}
	}
	for _, tool := range cfg.CLIs {
		if err := r.installCLI(ctx, cfg, home, tool); err != nil {
			return err
		}
	}
	if err := r.stopLeftovers(ctx, cfg); err != nil {
		return err
	}
	binaries := make(map[string]string, len(cfg.CLIs))
	for _, tool := range cfg.CLIs {
		path, err := resolveRuntimeBinary(home, tool)
		if err != nil {
			return err
		}
		binaries[tool] = path
	}
	stage := coreruntime.Stage(cfg)
	if err := sealTree(cfg, home, stage); err != nil {
		return err
	}
	if err := assertNoMounts(ctx, r.Deps, home); err != nil {
		return err
	}
	if err := os.RemoveAll(home); err != nil {
		return fmt.Errorf("replace runtime: %w", err)
	}
	if err := os.Rename(stage, home); err != nil {
		return fmt.Errorf("activate sealed runtime: %w", err)
	}
	if err := chownRuntime(r.Deps, cfg); err != nil {
		return err
	}
	binDir := filepath.Join(cfg.RuntimeRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	for _, tool := range cfg.CLIs {
		link := filepath.Join(binDir, tool)
		target := strings.Replace(binaries[tool], home, coreruntime.Home(cfg), 1)
		if err := replaceSymlink(link, target); err != nil {
			return err
		}
	}
	if contains(cfg.CLIs, "opencode") {
		if err := r.configureOpenCode(ctx, cfg); err != nil {
			return err
		}
	}
	if err := r.stopLeftovers(ctx, cfg); err != nil {
		return err
	}
	if err := r.Verify(ctx, cfg); err != nil {
		return err
	}
	if err := os.Remove(pending); err != nil {
		return err
	}
	if err := os.WriteFile(committed, []byte("committed\n"), 0o600); err != nil {
		return err
	}
	return nil
}

func (r Runtime) prepareAIHome(cfg config.Config) error {
	ids, err := r.Deps.LookupIDs(cfg)
	if err != nil {
		return err
	}
	for _, name := range []string{".ssh", ".config", ".cache", ".tmp"} {
		if err := ensureAIDirectory(filepath.Join(cfg.AIHome, name), ids); err != nil {
			return err
		}
	}
	sshDir := filepath.Join(cfg.AIHome, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(sshDir, entry.Name())); err != nil {
			return fmt.Errorf("remove SSH material from AI home: %w", err)
		}
	}
	secretsDir := filepath.Join(cfg.AIHome, ".secrets")
	if err := ensureAIDirectory(secretsDir, ids); err != nil {
		return err
	}
	secretsPath := filepath.Join(secretsDir, "env")
	if info, err := os.Lstat(secretsPath); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("secrets file must be a regular file")
		}
		if err := os.Chown(secretsPath, int(ids.User), int(ids.Group)); err != nil {
			return err
		}
		return os.Chmod(secretsPath, 0o600)
	} else if !isNotExist(err) {
		return err
	}
	return writeAIFile(secretsPath, []byte(secretsTemplate), 0o600, ids)
}

func (r Runtime) configureOpenCode(ctx context.Context, cfg config.Config) error {
	ids, err := r.Deps.LookupIDs(cfg)
	if err != nil {
		return err
	}
	configPath := openCodeConfigPath(cfg)
	content, err := openCodeConfig(cfg)
	if err != nil {
		return err
	}
	if err := writeAIFile(configPath, content, 0o600, ids); err != nil {
		return err
	}
	binary := filepath.Join(cfg.RuntimeRoot, "bin", "opencode")
	env := coreruntime.SandboxEnv(cfg)
	env["OPENCODE_CONFIG"] = configPath
	for _, args := range [][]string{
		{"service", "set", "hostname", services.OpenCodeHost},
		{"service", "set", "port", strconv.Itoa(services.OpenCodePort)},
		{"service", "set", "env", "OPENCODE_CONFIG", configPath},
	} {
		if _, err := r.Deps.runAsDir(ctx, cfg, cfg.AIHome, binary, envList(env), args); err != nil {
			return fmt.Errorf("pin OpenCode service: %w", err)
		}
	}
	return nil
}

func openCodeConfigPath(cfg config.Config) string {
	return coreruntime.OpenCodeConfigPath(cfg)
}

func openCodeConfig(cfg config.Config) ([]byte, error) {
	models := make(map[string]any, len(cfg.LiteLLMModels))
	for _, model := range cfg.LiteLLMModels {
		entry := map[string]any{"name": model}
		if strings.HasPrefix(model, "anthropic/") || strings.Contains(strings.ToLower(model), "claude") {
			entry["compatibility"] = map[string]string{"cacheFormat": "anthropic"}
		}
		models[model] = entry
	}
	value := map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"model":   "litellm/" + cfg.LiteLLMDefaultModel,
		"providers": map[string]any{
			"litellm": map[string]any{
				"name":     "LiteLLM (local)",
				"env":      []string{"LITELLM_API_KEY"},
				"package":  "@opencode/ai/providers/openai-compatible",
				"settings": map[string]string{"baseURL": cfg.LiteLLMBaseURL},
				"models":   models,
			},
		},
	}
	return json.MarshalIndent(value, "", "  ")
}

func ensureAIDirectory(path string, ids users.UID) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			if info.IsDir() {
				return fmt.Errorf("%s is not a regular directory", path)
			}
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	} else if !isNotExist(err) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := requireRealPath(path); err != nil {
		return err
	}
	if err := os.Chown(path, int(ids.User), int(ids.Group)); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func writeAIFile(path string, data []byte, mode os.FileMode, ids users.UID) error {
	parent := filepath.Dir(path)
	if err := ensureAIDirectory(parent, ids); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", path)
		}
	} else if !isNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(parent, ".sandboxctl-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Chown(int(ids.User), int(ids.Group)); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func envList(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

const secretsTemplate = `# Sourced by sandboxctl before a CLI starts. Keep this file owned by the
# AI account with mode 600 and never commit it.
#
# Prefer a scoped LiteLLM virtual key over the master key.
LITELLM_API_KEY=''
LITTLE_LLM_API_KEY=''
`

func (r Runtime) ensureRoot(cfg config.Config) error {
	if err := config.ValidatePath(cfg.RuntimeRoot); err != nil {
		return err
	}
	if cfg.RuntimeRoot == "/" || filepath.Dir(cfg.RuntimeRoot) == "/" {
		return fmt.Errorf("runtime root is too broad: %s", cfg.RuntimeRoot)
	}
	info, err := os.Lstat(cfg.RuntimeRoot)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime root must be a real directory")
		}
	} else if isNotExist(err) {
		if err := os.MkdirAll(cfg.RuntimeRoot, 0o755); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Chown(cfg.RuntimeRoot, 0, 0); err != nil {
		return err
	}
	if err := requireRealPath(cfg.RuntimeRoot); err != nil {
		return err
	}
	return os.Chmod(cfg.RuntimeRoot, 0o755)
}

func (r Runtime) installCLI(ctx context.Context, cfg config.Config, home, tool string) error {
	installer, err := coreruntime.InstallerFor(tool)
	if err != nil {
		return err
	}
	curl, err := r.Deps.lookPath("curl")
	if err != nil {
		return err
	}
	path := filepath.Join(home, "."+tool+".installer")
	args := []string{
		"--disable", "--proto", "=https", "--proto-redir", "=https",
		"--retry", "3", "--connect-timeout", "10", "--max-time", "300",
		"-fsSL", installer.URL, "-o", path,
	}
	env := coreruntime.InstallerEnv(cfg, home, coreruntime.NodeRoot(cfg))
	if _, err := r.Deps.runAsDir(ctx, cfg, home, curl, env, args); err != nil {
		return fmt.Errorf("download %s installer: %w", tool, err)
	}
	shell, err := r.Deps.lookPath(installer.Shell)
	if err != nil {
		return err
	}
	if _, err := r.Deps.runAsDir(ctx, cfg, home, shell, env, []string{path}); err != nil {
		return fmt.Errorf("run %s installer: %w", tool, err)
	}
	_ = os.Remove(path)
	return nil
}

func (r Runtime) stopLeftovers(ctx context.Context, cfg config.Config) error {
	if !r.Deps.ok(ctx, "pgrep", "-u", cfg.AIUser) {
		return nil
	}
	_, _ = r.Deps.run(ctx, "pkill", "-TERM", "-u", cfg.AIUser)
	time.Sleep(500 * time.Millisecond)
	_, _ = r.Deps.run(ctx, "pkill", "-KILL", "-u", cfg.AIUser)
	for i := 0; i < 20; i++ {
		if !r.Deps.ok(ctx, "pgrep", "-u", cfg.AIUser) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("CLI installer left processes running as %s", cfg.AIUser)
}

func (r Runtime) ensureNode(ctx context.Context, cfg config.Config) (err error) {
	nodeRoot := coreruntime.NodeRoot(cfg)
	previous := nodeRoot + ".previous"
	stage := nodeRoot + ".stage"
	hadPrevious := false
	if !exists(nodeRoot) && exists(previous) {
		if err := os.Rename(previous, nodeRoot); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(previous); err != nil {
		return err
	}
	_ = os.RemoveAll(stage)
	defer func() {
		if err == nil {
			return
		}
		_ = os.RemoveAll(stage)
		if hadPrevious {
			_ = os.RemoveAll(nodeRoot)
			_ = os.Rename(previous, nodeRoot)
		}
	}()
	temp, err := os.MkdirTemp(services.BackupRoot, "node-")
	if err != nil {
		temp, err = os.MkdirTemp("", "sandboxctl-node-")
	}
	if err != nil {
		return fmt.Errorf("create Node.js staging area: %w", err)
	}
	defer os.RemoveAll(temp)
	curl, err := r.Deps.lookPath("curl")
	if err != nil {
		return err
	}
	sumsPath := filepath.Join(temp, "SHASUMS256.txt")
	if _, err := r.Deps.run(ctx, curl,
		"--disable", "--proto", "=https", "--proto-redir", "=https",
		"--retry", "3", "--connect-timeout", "10", "--max-time", "120",
		"-fsSL", nodeDist+"SHASUMS256.txt", "-o", sumsPath,
	); err != nil {
		return fmt.Errorf("download Node.js checksums: %w", err)
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	arch := nodeArch(goruntime.GOARCH)
	if arch == "" {
		return fmt.Errorf("unsupported architecture for Node.js: %s", goruntime.GOARCH)
	}
	suffix := "-linux-" + arch + ".tar.xz"
	archive, expected, err := findNodeArchive(string(sums), suffix)
	if err != nil {
		return err
	}
	archivePath := filepath.Join(temp, archive)
	if _, err := r.Deps.run(ctx, curl,
		"--disable", "--proto", "=https", "--proto-redir", "=https",
		"--retry", "3", "--connect-timeout", "10", "--max-time", "300",
		"-fsSL", nodeDist+archive, "-o", archivePath,
	); err != nil {
		return fmt.Errorf("download Node.js: %w", err)
	}
	if err := verifySHA256(archivePath, expected); err != nil {
		return err
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	tarPath, err := r.Deps.lookPath("tar")
	if err != nil {
		return err
	}
	if _, err := r.Deps.run(ctx, tarPath, "-xJf", archivePath, "-C", stage, "--strip-components=1"); err != nil {
		return fmt.Errorf("extract Node.js: %w", err)
	}
	if _, statErr := os.Lstat(nodeRoot); statErr == nil {
		if err := os.Rename(nodeRoot, previous); err != nil {
			return err
		}
		hadPrevious = true
	} else if !isNotExist(statErr) {
		return statErr
	}
	if err := os.Rename(stage, nodeRoot); err != nil {
		return err
	}
	if err := chownTree(nodeRoot, 0, 0); err != nil {
		return err
	}
	node := filepath.Join(nodeRoot, "bin", "node")
	if _, err := r.Deps.run(ctx, node, "-e",
		`const [maj,min]=process.versions.node.split(".").map(Number); process.exit(maj > 22 || (maj === 22 && min >= 19) ? 0 : 1)`); err != nil {
		return fmt.Errorf("node.js 22 verification failed: %w", err)
	}
	return nil
}

func nodeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7l"
	case "ppc64le":
		return "ppc64le"
	case "s390x":
		return "s390x"
	default:
		return ""
	}
}

func findNodeArchive(sums, suffix string) (string, string, error) {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if !strings.HasSuffix(name, suffix) || !nodeArchivePattern.MatchString(name) {
			continue
		}
		if len(fields[0]) != sha256.Size*2 {
			continue
		}
		return name, strings.ToLower(fields[0]), nil
	}
	return "", "", fmt.Errorf("no Node.js build found for %s", suffix)
}

func verifySHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("node.js checksum mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

func sealTree(cfg config.Config, source, stage string) error {
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	forbidden := coreruntime.WritableRoots(cfg)
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		destination := filepath.Join(stage, rel)
		switch {
		case entry.IsDir():
			if err := os.Mkdir(destination, 0o755); err != nil {
				return err
			}
			return os.Chown(destination, 0, 0)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := validateSymlinkTarget(source, path, target, forbidden); err != nil {
				return err
			}
			if err := os.Symlink(target, destination); err != nil {
				return err
			}
			return os.Lchown(destination, 0, 0)
		case info.Mode().IsRegular():
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return fmt.Errorf("runtime contains a setuid/setgid file: %s", path)
			}
			capable, err := hasSecurityCapability(path)
			if err != nil {
				return fmt.Errorf("inspect file capabilities on %s: %w", path, err)
			}
			if capable {
				return fmt.Errorf("runtime contains file capabilities: %s", path)
			}
			return copyRegular(path, destination, info.Mode().Perm())
		default:
			return fmt.Errorf("runtime contains an unsupported file type: %s", path)
		}
	})
	if err != nil {
		return err
	}
	for _, name := range coreruntime.SecretNames() {
		_ = os.RemoveAll(filepath.Join(stage, name))
	}
	if err := chownTree(stage, 0, 0); err != nil {
		return err
	}
	err = filepath.WalkDir(stage, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o755)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return fmt.Errorf("staged runtime contains a privilege bit: %s", path)
		}
		return os.Chmod(path, info.Mode().Perm()&^0o022)
	})
	if err != nil {
		return err
	}
	return nil
}

func copyRegular(source, destination string, mode os.FileMode) error {
	input, err := fsx.SafeOpenRegular(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Chmod(destination, mode&^0o022)
}

func validateSymlinkTarget(source, path, target string, forbidden []string) error {
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(path), target)
	}
	resolved = filepath.Clean(resolved)
	if withinPath(source, resolved) {
		return nil
	}
	for _, root := range forbidden {
		if withinPath(root, resolved) {
			return fmt.Errorf("runtime symlink %s points into writable path %s", path, resolved)
		}
	}
	return nil
}

func withinPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func chownTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return os.Lchown(path, uid, gid)
		}
		return os.Chown(path, uid, gid)
	})
}

func chownRuntime(deps Deps, cfg config.Config) error {
	if err := chownTree(cfg.RuntimeRoot, 0, 0); err != nil {
		return err
	}
	return filepath.WalkDir(cfg.RuntimeRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			if err := os.Chmod(path, info.Mode().Perm()&^0o6000); err != nil {
				return err
			}
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, info.Mode().Perm()&^0o022)
	})
}

func resolveRuntimeBinary(home, tool string) (string, error) {
	for _, relative := range coreruntime.CandidatePaths(tool) {
		candidate, err := coreruntime.CandidatePath(home, relative)
		if err != nil {
			return "", err
		}
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if !withinPath(home, resolved) {
			return "", fmt.Errorf("%s resolves outside the runtime: %s", tool, resolved)
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%s installation path is unexpected", tool)
}

func replaceSymlink(path, target string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("refusing to replace directory with launcher: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !isNotExist(err) {
		return err
	}
	if err := os.Symlink(target, path); err != nil {
		return err
	}
	return os.Lchown(path, 0, 0)
}

func (r Runtime) Verify(ctx context.Context, cfg config.Config) error {
	home := coreruntime.Home(cfg)
	info, err := os.Lstat(home)
	if err != nil {
		return fmt.Errorf("inspect runtime: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("runtime home has unsafe permissions")
	}
	if err := verifySealedTree(cfg, home); err != nil {
		return err
	}
	for _, tool := range cfg.CLIs {
		binary, err := resolveRuntimeBinary(home, tool)
		if err != nil {
			return err
		}
		info, err := os.Stat(binary)
		if err != nil {
			return err
		}
		stat, ok := fileInfoOwner(info)
		if !ok || stat != 0 {
			return fmt.Errorf("%s is not owned by root", binary)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return fmt.Errorf("%s has a privilege bit", binary)
		}
		link := filepath.Join(cfg.RuntimeRoot, "bin", tool)
		linkInfo, err := os.Lstat(link)
		if err != nil {
			return fmt.Errorf("%s launcher target is missing: %w", tool, err)
		}
		if linkInfo.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s must be a symlink", link)
		}
		target, err := os.Readlink(link)
		if err != nil {
			return err
		}
		if target != binary {
			return fmt.Errorf("%s symlink target changed", tool)
		}
	}
	return nil
}

func verifySealedTree(cfg config.Config, root string) error {
	forbidden := coreruntime.WritableRoots(cfg)
	for _, name := range coreruntime.SecretNames() {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			return fmt.Errorf("runtime contains installer secret path %s", name)
		}
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		uid, ok := fileInfoOwner(info)
		if !ok || uid != 0 {
			return fmt.Errorf("runtime path is not owned by root: %s", path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return validateSymlinkTarget(root, path, target, forbidden)
		}
		switch {
		case entry.IsDir():
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("runtime directory is group/other writable: %s", path)
			}
		case info.Mode().IsRegular():
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return fmt.Errorf("runtime contains a privilege bit: %s", path)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("runtime file is group/other writable: %s", path)
			}
			capable, err := hasSecurityCapability(path)
			if err != nil {
				return err
			}
			if capable {
				return fmt.Errorf("runtime contains file capabilities: %s", path)
			}
		default:
			return fmt.Errorf("runtime contains an unsupported file type: %s", path)
		}
		return nil
	})
}

func (r Runtime) Remove(ctx context.Context, cfg config.Config) error {
	if contains(cfg.CLIs, "opencode") {
		binary := filepath.Join(cfg.RuntimeRoot, "bin", "opencode")
		if _, err := os.Stat(binary); err == nil {
			env := coreruntime.SandboxEnv(cfg)
			env["OPENCODE_CONFIG"] = openCodeConfigPath(cfg)
			_, _ = r.Deps.runAsDir(ctx, cfg, cfg.AIHome, binary, envList(env), []string{"service", "unset", "env", "OPENCODE_CONFIG"})
		}
		if err := os.Remove(openCodeConfigPath(cfg)); err != nil && !isNotExist(err) {
			return fmt.Errorf("remove OpenCode LiteLLM config: %w", err)
		}
	}
	if err := safeRemoveRoot(ctx, r.Deps, cfg.RuntimeRoot); err != nil {
		return err
	}
	return os.RemoveAll(cfg.RuntimeRoot)
}

// Rollback restores the runtime saved by the most recent Install. The marker
// keeps rollback a no-op when Install failed before it changed anything.
func (r Runtime) Rollback(ctx context.Context, cfg config.Config) error {
	pending := runtimeMarkerPending(cfg)
	committed := runtimeMarkerCommitted(cfg)
	hasPending := exists(pending)
	hasCommitted := exists(committed)
	if !hasPending && !hasCommitted {
		return nil
	}
	home := coreruntime.Home(cfg)
	previous := coreruntime.Previous(cfg)
	if err := assertNoMounts(ctx, r.Deps, home); err != nil {
		return err
	}
	if err := os.RemoveAll(home); err != nil {
		return err
	}
	if _, err := os.Lstat(previous); err == nil {
		if err := os.Rename(previous, home); err != nil {
			return err
		}
	}
	if err := os.Remove(pending); err != nil && !isNotExist(err) {
		return err
	}
	if err := os.Remove(committed); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func runtimeMarkerPending(cfg config.Config) string {
	return filepath.Join(cfg.RuntimeRoot, ".sandboxctl-runtime-pending")
}

func runtimeMarkerCommitted(cfg config.Config) string {
	return filepath.Join(cfg.RuntimeRoot, ".sandboxctl-runtime-committed")
}

func assertNoMounts(ctx context.Context, deps Deps, path string) error {
	result, err := deps.run(ctx, "findmnt", "-R", "-n", "-o", "TARGET", path)
	if err != nil {
		return nil
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return fmt.Errorf("refusing to remove %s because it contains a mountpoint", path)
	}
	return nil
}

func safeRemoveRoot(ctx context.Context, deps Deps, path string) error {
	if err := config.ValidatePath(path); err != nil {
		return err
	}
	if path == "/" || filepath.Dir(path) == "/" {
		return fmt.Errorf("refusing to remove too-broad path %s", path)
	}
	if err := assertNoMounts(ctx, deps, path); err != nil {
		return err
	}
	for _, protected := range []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/home", "/root", "/proc", "/sys", "/dev", "/run", "/var", "/srv", "/tmp"} {
		if path == protected || withinPath(protected, path) {
			return fmt.Errorf("refusing to remove protected path %s", path)
		}
	}
	return nil
}
