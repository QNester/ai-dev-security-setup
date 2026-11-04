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

## Phase 1 guarantees

Phase 1 is not a sandbox. It provides validation, state, process execution, and
planning primitives. `install`, `update`, and `uninstall` without `--dry-run`
return exit code 3 before changing the system. `enter` and `review` are also
unavailable. Doctor only inspects files and executable presence.

The atomic state writer rejects a symlink at the final path. Safe regular-file
opens use `O_NOFOLLOW`; descriptor-based review identity checks remain Phase 3.
Configuration validation rejects traversal, unclean paths, overlapping trees,
root accounts, unknown JSON fields, and unsupported CLIs.

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
