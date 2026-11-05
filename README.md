# sandboxctl

`sandboxctl` is a Go 1.22+ tool for isolated execution of Claude Code, Kimi Code,
Pi, and OpenCode on Linux and macOS. It is the successor to the Bash reference
installer in this repository; the Go binary has no Bash or Python runtime.

> **Phase 3 (review):** `install`, `update`, and `uninstall` perform real
> system changes on Linux behind `--yes` and a root check. The lifecycle covers
> the dedicated account, shared ACLs and bind alias, sealed CLI runtime,
> UID-scoped nftables policy, systemd units, and root-owned launcher symlinks.
> `enter` runs a selected CLI inside Bubblewrap. `review` validates one
> shared-tree file; Linux passes a protected descriptor with `--ro-bind-data`,
> while macOS copies it into root-owned staging and uses a dedicated Seatbelt
> profile. Neither review path mounts the shared tree or loads secrets. macOS
> lifecycle backends remain later phases. The Linux lifecycle and both review
> paths still need on-host testing on Ubuntu 22.04/24.04 and macOS before
> claiming full parity with the reference installer.

## Target model

- A dedicated non-root AI user can access only its home, private temporary
  directory, and the selected shared tree.
- CLIs are installed without project access and sealed in a root-owned runtime.
- Linux uses Bubblewrap, UID-scoped nftables, systemd, and `setfacl`.
- Native macOS uses deprecated Seatbelt, chmod ACLs, and launchd on an explicit
  best-effort basis. `--backend auto` selects the VM backend on macOS. Lima is
  the default and only automatically installable VM provider; Docker/Podman are
  explicit Phase 5 providers and are never selected automatically.
- Launchers are symlinks to one root-owned `sandboxctl`, never shell wrappers.
- State-driven uninstall and verification rollback are architectural requirements.

See [the behavioral specification](docs/behavioral-spec.md),
[architecture](docs/architecture.md), [security model](docs/security.md), and
[platform matrix](docs/platform-matrix.md).

## Build

```bash
go build -trimpath ./cmd/sandboxctl
```

Static cross-compilation requires no CGO:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/sandboxctl
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/sandboxctl
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build ./cmd/sandboxctl
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./cmd/sandboxctl
```

The project currently uses only the Go standard library. The permitted future
`golang.org/x/sys/unix` dependency is not needed yet.

## Commands

```text
sandboxctl doctor [--backend native|vm|auto]
sandboxctl doctor --fix --yes [--backend native|vm|auto]
sandboxctl install --cli claude,opencode --backend auto --dry-run
sandboxctl update --dry-run
sandboxctl uninstall --dry-run
sandboxctl status
sandboxctl review /absolute/path/to/FILE
sandboxctl enter --tool claude --start-dir /absolute/path/to/DIR
```

Human output is formatted text with green success and red error lines. Long
operations show an animated spinner with the current lifecycle step; the spinner
and colors are enabled only on a terminal and are disabled for JSON or piped
output. Colors can also be disabled with `NO_COLOR` or `--no-color`. `--json`
remains an explicit opt-in for automation and turns errors into JSON on stderr.

`doctor --fix --yes` installs missing prerequisites. On Linux it runs the apt
package step; on macOS it installs Lima with Homebrew when neither Lima nor UTM
is present. Homebrew itself is never installed automatically because its
official installer requires an interactive vendor script and sudo. Docker and
Podman are intentionally not treated as automatic VM providers; they remain a
Phase 5 option. `--fix` cannot be combined with `--json`; `--fix --dry-run`
prints the macOS Homebrew command without running it.

Common flags are `--dry-run`, `--yes`, `--json`, `--no-color`, `--verbose`,
`--backend`, `--config`, and `--state`. Place them after the command. `--config`
loads strict JSON; without it, defaults are derived from the owner account and
platform. For `status`, `update`, and `uninstall`, an explicit `--state` wins;
otherwise the state path comes from `--config`, then from the platform default.

Mutating `install`, `update`, and `uninstall` require root and `--yes`; without
`--yes` the command exits with a usage error. `--verbose` is accepted but does
not yet add progress detail. `--dry-run` never invokes backend code.

`review` requires `claude` selected in saved state or configuration. It accepts
only a regular UTF-8 text file inside the shared tree, rejects symlinks and
oversized input, and exposes the file read-only. On Linux the validated
descriptor is passed with `--ro-bind-data`; on macOS the file is copied into
root-owned staging and exposed through a dedicated Seatbelt profile. The shared
tree is not mounted in review mode and the secrets file is not loaded.

Doctor reports OS/architecture, privileges, init system, Bubblewrap and user
namespaces, nftables, ACL tooling, Seatbelt's deprecated status, and Lima/UTM on
macOS. It exits 0 when required capabilities are present, 1 when diagnostics
fail, 2 for invalid usage, and 3 for functionality not implemented.

Example Linux dry-run:

```bash
sandboxctl install --cli claude,opencode --backend native --dry-run \
  --owner-user alice --owner-home /home/alice \
  --shared-dir /home/alice/Developer
```

Dry-run does not create users, state, directories, services, firewall rules,
mounts, ACLs, launchers, or runtime files. A non-dry-run invocation requires
root and `--yes`; on Linux it applies the lifecycle, verifies each stage, and
rolls back if verification fails.

Re-running `install` is idempotent for the same account, home, shared-tree, and
runtime paths. Run `uninstall` before changing those paths so the old ACLs,
bind alias, services, and runtime are removed from saved state.

## Development

```bash
gofmt -w cmd internal tests
go vet ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@2024.1.1 ./...
```

A real but non-mutating Linux Bubblewrap integration probe is available:

```bash
SANDBOXCTL_INTEGRATION=1 go test -tags=integration \
  ./tests/integration/linux -run TestBubblewrapRunsTrue -v
```

CI runs the portable checks and builds all four targets. The Linux adapters are
unit-tested with injected command/file primitives, but the project still needs
Ubuntu 22.04/24.04 VM integration runs to validate real `useradd`, `setfacl`,
`mount`, `nft`, systemd, and vendor installers. Review and the macOS backends
remain later phases.

## Legacy reference

`setup-ai-sandbox.sh` and the LiteLLM helper files remain as reference material
for the existing Ubuntu/Debian setup. They are not imported, generated, or
executed by `sandboxctl`. The new implementation does not claim feature parity
until Phases 2–5 are complete and verified.

## License

See [LICENSE](LICENSE).
