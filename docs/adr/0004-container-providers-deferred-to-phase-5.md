# ADR 0004: Container runtimes are explicit Phase 5 providers

## Status

Accepted, deferred to Phase 5

## Context

Docker and Podman are often already present on developer machines, and on macOS
both use a Linux VM internally. It is tempting to treat them as an automatic
fallback when Lima or UTM is missing.

They are not equivalent to the current VM contract. Phase 2 Linux runs a full
host lifecycle: `useradd`, POSIX ACLs, a persistent bind alias, systemd units,
UID-scoped nftables rules, AppArmor where required, and Bubblewrap user
namespaces. A container normally lacks systemd and AppArmor, nftables requires
extra capabilities, and macOS volume/UID/ACL semantics differ from a Linux VM.

Container runtimes also change the threat model:

- rootful Docker with access to `docker.sock` is effectively root-equivalent;
- Docker Desktop and Podman Machine share a daemon and a Linux VM with other
  workloads;
- bind mounts, network mode, image provenance, and machine lifecycle need
  independent validation;
- the presence of a binary does not imply a running, rootless, correctly
  configured engine.

## Decision

Lima remains the default and the only automatically installable VM provider.
UTM remains a manually installed alternative. `--backend auto` will not select
Docker or Podman, and `doctor` will not silently accept them as a working VM
provider.

Docker and Podman may be added in Phase 5 only as explicit providers, for
example `--vm-provider docker|podman`, after they satisfy the same isolation and
lifecycle requirements as the Lima/UTM backend. Such a provider must at least:

- require explicit opt-in and never fall back silently;
- prefer rootless operation and reject a rootful daemon or exposed Docker socket
  by default;
- never mount the Docker socket into the sandbox;
- use a pinned image digest and an explicit, auditable pull/update path;
- use a read-only root filesystem, dropped capabilities, no host networking, and
  a controlled proxy or `none` network policy;
- expose only the selected shared tree, never the owner home;
- implement state-driven machine/container cleanup and isolation verification.

## Consequences

Lima/UTM stay the supported strict path and `doctor --fix` installs Lima only.
Users who already have Docker or Podman are not silently moved onto an
unvalidated security boundary; they can use `--backend native` explicitly for
reduced isolation until a container provider is implemented and verified.
