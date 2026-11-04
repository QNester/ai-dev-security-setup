# ADR 0001: Go core and explicit backend boundaries

## Status

Accepted

## Context

The reference Bash installer combines portable policy with Linux mechanisms.
The new tool must compile as one static binary on Linux and macOS and must not
generate shell wrappers. Native macOS cannot honestly promise Linux parity.

## Decision

Use Go 1.22 with the standard library. Keep policy in core packages and expose
small platform-neutral interfaces from `platform/base`. Linux uses Bubblewrap,
nftables, and systemd. macOS native uses Seatbelt as an explicitly best-effort
option. macOS auto selects a VM and delegates enforcement to the Linux backend.

Launchers are symlinks to one binary, dispatched through argv0. No backend may
introduce generated shell code or implicit shell execution.

## Consequences

Portable tests can validate plans and specs without host privileges. Platform
code remains isolated and cross-compilable. Strict macOS isolation requires VM
dependencies rather than a silent native fallback.
