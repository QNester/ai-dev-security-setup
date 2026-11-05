# Architecture

## Phase 1 plan

1. Establish the Go-only repository, CI, formatting, vet, and Staticcheck.
2. Add strict configuration defaults, JSON loading, path validation, and CLI
   selection.
3. Add versioned state with atomic writes, backups, and restore support.
4. Add an apply/verify/rollback planner. Dry-run returns actions without calling
   backend code. Phase 1 apply actions stop with `ErrNotImplemented` before any
   system change.
5. Add read-only Linux/macOS diagnostics and portable backend contracts.
6. Embed declarative templates and test shared contracts. Real isolation,
   uninstall, and review are deliberately left to their respective phases.

## Phase 2 Linux lifecycle

The Linux backend implements the portable backend contracts rather than a
separate orchestrator:

1. `Host` installs missing prerequisites, loads the targeted AppArmor profile
   on restricted Ubuntu kernels, verifies user namespaces, and refuses to
   proceed while AI processes are running.
2. `Users` creates the locked account and dedicated groups, the AI home, the
   temporary root, and the owner-side SSH deploy key.
3. `ACL` denies the AI account at the owner's home before a vendor installer
   runs, then grants the shared tree, installs default ACLs, and creates the
   `nosuid,nodev` bind alias with an `/etc/fstab` entry.
4. `Runtime` downloads trusted vendor installers as the AI account with a clean
   environment, verifies the expected binaries, rejects special files,
   privilege bits, file capabilities, and writable symlink targets, copies the
   payload into a fresh root-owned tree, and activates stable `bin/` symlinks.
5. `Network` renders `nftables` rules from validated spec data. `Services`
   installs the unit and nftables drop-in. `Launchers` copies the running
   `sandboxctl` binary to `/usr/local/libexec` and installs symlink launchers.
6. The plan writes state after applying resources and verifies every stage
   before reporting success. A verification failure restores or removes state
   as part of rollback.

`enter` loads state as root, maps the requested start directory to the shared
tree, builds a `base.Spec`, and replaces itself with `runuser -u <ai> --
bwrap`. The inner Bash entrypoint sources the AI-owned secrets file and executes
the selected CLI, so secrets never become Bubblewrap arguments.

Linux `review` is a separate spec: it validates one regular file inside the
shared tree, rejects symlinks, oversized input, and non-text content, and keeps
the file descriptor open until Bubblewrap copies it with `--ro-bind-data`. The
review sandbox mounts the AI home for authentication, not the shared tree, and
does not source the secrets file. The CLI drops to the AI account with
`SysProcAttr.Credential` and passes the descriptor through `ExtraFiles`.

macOS review uses the same portable validation, copies the input into a
root-owned staging directory, and renders a dedicated Seatbelt profile that
allows only the staged file, runtime, AI home, and network. The lifecycle
backends are still phases 4–5; only review is active on native macOS.

## Phase 4 macOS native lifecycle

The native backend reuses the portable plan and state layers but uses macOS
mechanisms:

1. `Host` checks the macOS command set and probes `sandbox-exec` as the AI
   account; there is no apt/Homebrew package mutation.
2. `Users` creates a locked standard account and dedicated groups through
   `dscl` and `dseditgroup`, creates the home/tmp roots, and creates the
   owner-side SSH deploy key.
3. `ACL` grants execute-only traversal of the owner home and recursive `chmod`
   ACLs on the shared tree, with directory inheritance. Uninstall clears those
   entries and verifies removal.
4. `Runtime` reuses the same sealed-runtime transaction model: vendor installers
   run as the AI account, payloads are copied into a fresh root-owned tree, and
   special files, privilege bits, and writable symlink targets are rejected.
5. `Launchers` installs the root-owned `sandboxctl` and argv0 symlinks.
6. `enter` renders a per-execution Seatbelt profile from `base.Spec`; `review`
   uses the staged profile described above. Both run through `sandbox-exec`.

Native macOS does not install a launchd or pf service yet. Network enforcement
is therefore per-execution and best-effort, and the native backend makes no
claim of Linux parity.

## Phase 5 VM provider scope

Lima remains the default and only automatically installable macOS VM provider;
UTM remains a manual alternative. Docker and Podman are deliberately excluded
from `--backend auto` because they are container runtimes with a different
daemon, mount, network, image-supply, and lifecycle model. They may become
explicit Phase 5 providers only after rootless operation, pinned images, dropped
capabilities, no Docker socket, controlled networking, shared-tree-only mounts,
and state-driven cleanup are implemented and verified. See
[ADR 0004](adr/0004-container-providers-deferred-to-phase-5.md).

## Repository tree

```text
cmd/sandboxctl/              process entry point
internal/cli/                commands, output, and exit codes
internal/bootstrap/          doctor --fix prerequisite installation
internal/config/             defaults, JSON loading, validation
internal/state/              state.json, backup, restore
internal/plan/               install/update/uninstall plans and execution
internal/runner/             context-aware argv/env subprocess execution
internal/fsx/                atomic writes and no-follow regular-file opens
internal/core/
  users/                     account and group policy
  shared/                    ACL, alias, and start-directory policy
  runtime/                   CLI candidates, installer URLs, sandbox environment
  review/                    portable review content and size validation
  services/                  systemd, nftables, and launcher paths
internal/platform/
  detect/                    OS, architecture, and capability reporting
  base/                      backend interfaces and portable Spec
  linux/                     Bubblewrap/nftables/systemd/setfacl adapter
  darwin/                    best-effort Seatbelt/chmod ACL/dscl adapter
  vm/                        Lima/UTM adapter; container providers deferred to Phase 5
internal/templates/
  linux/                     embedded unit and nftables templates
  darwin/                    embedded plist and SBPL templates
tests/
  unit/                      portable test entry package
  contract/                  tests shared by backend implementations
  integration/linux/         future Ubuntu VM tests
  integration/darwin/        future macOS tests
docs/                        behavior, security, platform matrix, and ADRs
```

## Boundaries

Core packages operate on accounts, paths, file permissions, and network policy.
They do not construct Bubblewrap flags, SBPL, nftables syntax, or service-manager
arguments. Those details belong to adapters implementing `platform/base`.

`runner.OSRunner` uses `exec.CommandContext` directly. It never invokes a shell,
requires a clean absolute executable path, and never inherits the parent
environment implicitly. Output capture is bounded, and cancellation kills the
subprocess group with a bounded wait. Vendor installers may be shell programs,
but will be executed as explicit external processes under the AI account.

The Linux Bubblewrap adapter converts portable specs into argv without shell
snippets. It clears the environment, sets sorted explicit variables, separates
read-only and writable mounts, and applies namespaces and capability drops.
The `tests/integration/linux` probe executes the resulting argv without host
mutation.

## Planning and failure

A plan is an ordered list of named actions. Execution refuses to start an action
when the caller context is already canceled. Panics in actions become errors.
An apply or verification error triggers rollback in reverse order, including
the action whose apply failed. Rollback uses a fresh two-minute context derived
with `context.WithoutCancel`, so caller cancellation does not abort cleanup.
Dry-run only materializes names and never invokes apply, rollback, or
verification.

The install plan now executes the Linux lifecycle. Dry-run still only
materializes names and never calls a backend. On a failed apply or verification,
rollback restores the prior sealed runtime, removes generated services,
firewall rules, launchers, ACLs, and aliases, and restores or removes state.

## State and uninstall

State is versioned JSON with strict decoding and mode `0600`. The default paths
are:

- Linux: `/var/lib/ai-sandbox/state.json`
- macOS: `/Library/Application Support/ai-sandbox/state.json`

Writes use a temporary file in the destination directory, file and directory
`fsync`, and atomic rename. Existing symlinks and non-regular destinations are
rejected. Every existing component from the authorized filesystem root must be a
real directory without group/other write or setgid bits and owned by root or the
current user. Store paths must match the `state_path` recorded in their config.
Backup and restore APIs are available for transactional lifecycle actions.

Update and uninstall load the saved state. An explicit `--state` takes priority;
otherwise `--config` supplies its `state_path`. Uninstall planning uses the
saved runtime, firewall, service, ACL, and alias records rather than current
configuration values. State validation checks backend/platform compatibility,
resource paths, runtime CLIs, services, and backups. Secrets have no
representation in the state schema.

## Launcher dispatch

The Linux installation places one root-owned binary at
`/usr/local/libexec/sandboxctl`. `claude-secure`, `kimi-secure`, `pi-secure`,
and `opencode-secure` are symlinks to it. argv0 dispatch selects `enter`; the
launcher first re-executes through `sudo` for the state read, then drops to the
AI account with `runuser` before Bubblewrap. `ai-review-file` is installed when
Claude is selected and dispatches to `review`; it uses the same root state read
and passes a validated descriptor instead of mounting the shared tree. There is
no setuid and no generated shell launcher.
