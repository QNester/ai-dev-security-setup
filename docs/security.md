# Security model

## Invariants

The implementation must preserve these invariants as backends are activated:

1. The AI account is non-root, locked, and has no supplementary privileges.
2. Only its home, private temporary directory, and the selected shared tree are
   writable. The owner's home and credentials are not exposed.
3. Vendor installers run as the AI account without shared-tree access. Runtime
   activation happens only after the payload is copied to a fresh root-owned
   tree and passes special-file, privilege-bit, capability, symlink, ACL, and
   write-permission checks.
4. Review opens a regular file without following a final symlink, verifies its
   identity and size, and exposes only that input. Linux passes the validated
   descriptor to Bubblewrap. macOS uses root-owned staging. Review never loads
   secrets or mounts the complete shared tree.
5. Linux network rules are UID-scoped, fail closed during setup, and allow DNS
   only to configured nameservers. OpenCode and LiteLLM exceptions are narrow.
6. Every changed object is recorded in state or backed up. Uninstall follows
   state, not current configuration. Verification failure rolls back changes.
7. No secret is embedded, committed, or serialized into state.

## Current guarantees

The Linux Phase 2 lifecycle now mutates the host. `install` and `update` create
one locked account, deny the owner home, grant the shared tree, install and seal
the runtime, apply UID-scoped nftables rules, enable systemd units, and install
root-owned symlink launchers. `uninstall` follows the saved state rather than
current flags. Every mutating command requires root and `--yes`.

`enter` builds a Bubblewrap spec, runs it as the AI account, and sources the
AI-owned secrets file inside the sandbox so credentials do not appear in the
Bubblewrap argument list.

Linux `review` validates one shared-tree file as a regular, non-symlink, sized,
UTF-8 text document, opens it with `O_NOFOLLOW`, rewinds the protected
descriptor, and passes it with `--ro-bind-data`. The review sandbox mounts the
AI home for authentication but not the shared tree and does not source the
secrets file. macOS review remains future work. The Linux lifecycle and review
still need Ubuntu 22.04/24.04 VM runs, so parity with the reference installer is
not claimed.

`doctor --fix --yes` is the only command that installs host prerequisites. On
Linux it runs the apt package step; on macOS it installs Lima with Homebrew when
no VM provider exists. Homebrew itself is never installed automatically because
its official installer is an interactive vendor script requiring sudo.

The atomic state writer rejects symlinks throughout the destination chain,
group/other-writable and setgid components, and unexpected owners. Directory
`fsync` ignores only `EINVAL`/`ENOTSUP` for filesystems such as APFS; other I/O
errors fail. The macOS fallback is unit-tested by error classification but still
requires an on-host APFS test. Safe regular-file opens use `O_NOFOLLOW` and
nonblocking opens; review keeps the validated descriptor open until Bubblewrap
has consumed it, so replacing the path cannot redirect the review input.
Configuration validation rejects traversal, unclean paths, overlapping trees,
root accounts, unknown JSON fields, and unsupported CLIs. Mutating install uses
platform-specific safe roots for state and other system paths.

## Residual risk

The shared tree is fully mutable by the agent. Project hooks, tasks, scripts,
and existing credentials in that tree remain untrusted. Review verdicts are
advisory and do not make code safe to execute. Vendor installers remain trusted
inputs unless a future release supports verified mirrors or pinning.

Linux UID filtering is best-effort because it shares the host kernel and network
namespace. Native macOS relies on deprecated Seatbelt behavior and cannot claim
Linux parity. Use the VM backend and controlled proxy for strict isolation.

The Linux implementation has not yet been exercised end-to-end on a clean
Ubuntu 22.04/24.04 host. Vendor installers, ACL behavior on the owner's
filesystem, systemd ordering, and AppArmor profile loading remain integration
risks until those runs are recorded.
