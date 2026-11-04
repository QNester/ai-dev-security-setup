# sandboxctl

`sandboxctl` is a Go 1.22+ tool for isolated execution of Claude Code, Kimi Code,
Pi, and OpenCode on Linux and macOS. It is the successor to the Bash reference
installer in this repository; the Go binary has no Bash or Python runtime.

> **Phase 2 in progress:** the Phase 1 base is hardened, and the Linux
> Bubblewrap adapter now builds sandbox argv and has a real read-only execution
> test. No system-mutating backend is active. For `install`, `update`, and
> `uninstall`, only dry-run planning succeeds; without `--dry-run` they return
> exit code 3 before changing the system. `enter` and `review` remain unavailable.

## Target model

- A dedicated non-root AI user can access only its home, private temporary
  directory, and the selected shared tree.
- CLIs are installed without project access and sealed in a root-owned runtime.
- Linux uses Bubblewrap, UID-scoped nftables, systemd, and `setfacl`.
- Native macOS uses deprecated Seatbelt, chmod ACLs, and launchd on an explicit
  best-effort basis. `--backend auto` selects the VM backend on macOS.
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
sandboxctl doctor [--json] [--backend native|vm|auto]
sandboxctl install --cli claude,opencode --backend auto --dry-run
sandboxctl update --dry-run
sandboxctl uninstall --dry-run
sandboxctl status [--json]
sandboxctl review /absolute/path/to/FILE
sandboxctl enter --tool claude --start-dir /absolute/path/to/DIR
```

Common flags are `--dry-run`, `--yes`, `--json`, `--verbose`, `--backend`,
`--config`, and `--state`. Place them after the command. `--config` loads strict
JSON; without it, defaults are derived from the owner account and platform.
For `status`, `update`, and `uninstall`, an explicit `--state` wins; otherwise
the state path comes from `--config`, then from the platform default.

`--json` also makes errors structured on stderr. Currently `--yes` and
`--verbose` are accepted for interface compatibility but do not alter behavior;
confirmation and verbose execution will be wired to real mutating actions before
those actions are enabled.

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
mounts, ACLs, launchers, or runtime files. A non-dry-run invocation exits before
the first action while mutating plans remain disabled.

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

CI runs the portable checks and builds all four targets. Before lifecycle
mutation is enabled, Phase 2 still needs Ubuntu 22.04/24.04 VM integration,
account/ACL/runtime/network/service adapters, state journaling, launchers, and
state-driven uninstall. Review and the macOS backends remain later phases.

## Legacy reference

`setup-ai-sandbox.sh` and the LiteLLM helper files remain as reference material
for the existing Ubuntu/Debian setup. They are not imported, generated, or
executed by `sandboxctl`. The new implementation does not claim feature parity
until Phases 2–5 are complete and verified.

## License

See [LICENSE](LICENSE).
