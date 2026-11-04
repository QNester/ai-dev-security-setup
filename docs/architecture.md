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

## Repository tree

```text
cmd/sandboxctl/              process entry point
internal/cli/                commands, output, and exit codes
internal/config/             defaults, JSON loading, validation
internal/state/              state.json, backup, restore
internal/plan/               install/update/uninstall plans and execution
internal/runner/             context-aware argv/env subprocess execution
internal/fsx/                atomic writes and no-follow regular-file opens
internal/core/
  users/                     portable account policy
  shared/                    portable shared-tree policy
  runtime/                   portable runtime install/sealing policy
  review/                    portable review policy
  services/                  portable service policy
internal/platform/
  detect/                    OS, architecture, and capability reporting
  base/                      backend interfaces and portable Spec
  linux/                     Bubblewrap/nftables/systemd/setfacl adapter
  darwin/                    Seatbelt/chmod ACL/launchd/dscl adapter
  vm/                        Lima/UTM fallback adapter
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

`runner.OSRunner` uses `exec.CommandContext` directly. It never invokes a shell
and never inherits the parent environment implicitly. Output capture is bounded,
and cancellation kills the subprocess group with a bounded wait. Vendor
installers may be shell programs, but will be executed as explicit external
processes under the AI account in Phase 2.

## Planning and failure

A plan is an ordered list of named actions. Execution applies each action and
then verifies all applied actions. An apply or verification error triggers
rollback in reverse order, including the action whose apply failed. Rollback
uses a fresh two-minute context derived with `context.WithoutCancel`, so caller
cancellation does not abort cleanup. Dry-run only materializes names and never
invokes apply, rollback, or verification.

The current plans describe the Phase 2 lifecycle but intentionally have no
system-mutating implementation. This makes the CLI end-to-end behavior testable
without pretending that installation succeeded.

## State and uninstall

State is versioned JSON with strict decoding and mode `0600`. The default paths
are:

- Linux: `/var/lib/ai-sandbox/state.json`
- macOS: `/Library/Application Support/ai-sandbox/state.json`

Writes use a temporary file in the destination directory, file and directory
`fsync`, and atomic rename. Existing symlinks and non-regular destinations are
rejected. The parent must be a real, non-world-writable directory owned by root
or the current user. Backup and restore APIs are available for Phase 2.

Update and uninstall load the saved state. An explicit `--state` takes priority;
otherwise `--config` supplies its `state_path`. Uninstall planning uses the
saved runtime, firewall, service, ACL, and alias records rather than current
configuration values. State validation checks backend/platform compatibility,
resource paths, runtime CLIs, services, and backups. Secrets have no
representation in the state schema.

## Launcher dispatch

The final installation will place one root-owned binary at
`/usr/local/libexec/sandboxctl`. `claude-secure`, `kimi-secure`, `pi-secure`,
`opencode-secure`, and `ai-review-file` are symlinks to it. The existing argv0
dispatch implements this routing; actual sandbox entry is not yet implemented.
There is no setuid and no generated shell wrapper.
