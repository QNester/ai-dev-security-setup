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

Phase 2 has started, but lifecycle mutation is still disabled. The Linux
Bubblewrap adapter has a real read-only execution probe; this is not yet full
sandbox parity. `install`, `update`, and `uninstall` without `--dry-run` return
exit code 3 before changing the system. `enter` and `review` are unavailable.

The atomic state writer rejects symlinks throughout the destination chain,
group/other-writable and setgid components, and unexpected owners. Directory
`fsync` ignores only `EINVAL`/`ENOTSUP` for filesystems such as APFS; other I/O
errors fail. The macOS fallback is unit-tested by error classification but still
requires an on-host APFS test. Safe regular-file opens use `O_NOFOLLOW` and
nonblocking opens; descriptor-based review identity checks remain Phase 3.
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

No system-mutating backend is implemented in Phase 1, so there is not yet any
runtime protection or uninstall capability to validate on a real host.
