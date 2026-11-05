# ADR 0005: VM lifecycle runs a Linux guest artifact

## Status

Accepted, Phase 5 in progress

## Context

The macOS binary cannot execute the Linux lifecycle. A VM backend must therefore
run a Linux `sandboxctl` artifact inside a Lima/UTM guest; the host binary is an
orchestrator, not a second implementation of accounts, ACLs, nftables, or
Bubblewrap.

The guest artifact creates state inside the VM, mounts only the selected shared
tree, and must not receive the owner home, Docker socket, host credentials, or
arbitrary host paths. The host must be able to copy a pinned artifact into the
guest, start/stop/delete the VM, and proxy `install`, `update`, `uninstall`,
`enter`, and `review` without shell wrappers.

## Decision

Phase 5 will use a version-matched Linux guest artifact. The host will:

- manage a named Lima/UTM instance;
- copy the Linux binary and a strict config into the guest through the provider;
- execute it as the guest root/owner with argv-only commands;
- keep guest state inside the VM and remove the instance on uninstall when
  requested;
- mount only the shared tree, not the host home, and use a controlled proxy or
  no-network policy for strict mode.

The guest artifact must be pinned by digest or version. A host binary must refuse
to use an artifact whose version does not match. The VM must be disposable:
deleting it removes guest state.

## Consequences

The Lima provider can be implemented and tested now, but full VM lifecycle
remains disabled until a Linux artifact is distributed and the guest mount,
proxy, enter/PTY, and review paths are verified on real macOS hosts. UTM remains
an explicit alternative provider. No silent fallback to native Seatbelt is
allowed.
