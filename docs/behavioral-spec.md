# Behavioral specification

This document distills `setup-ai-sandbox.sh` into behavior for `sandboxctl`.
The script is a reference, not part of the Go implementation or runtime.

## Required behavior

- Support Claude Code, Kimi Code, Pi, and OpenCode with an explicit, stable
  selection. Installation and repeated runs must be idempotent.
- Create a dedicated, locked, non-root AI user with a private home, a dedicated
  primary group, and only the shared-tree supplementary group. The AI user must
  not have passwordless sudo or access to the owner's home.
- Expose only the selected shared tree, the AI home, and a private temporary
  directory. On Linux, a root-managed bind alias avoids traverse access to the
  owner's home. The shared tree remains writable by both owner and AI user.
- Install vendor CLIs as the AI user without access to the shared tree. Copy the
  result to a fresh root-owned runtime and reject setuid/setgid files, file
  capabilities, special files, and links into writable locations. Remove
  inherited ACLs and group/other write permission before enabling launchers.
- Launch through one root-owned `sandboxctl` binary and symlinks. Never generate
  shell launchers and never use setuid. Authentication remains in the AI home.
- On Linux, use Bubblewrap with new user, PID, UTS, IPC, and cgroup namespaces,
  dropped capabilities, a minimal filesystem, and an explicit environment.
- Allow internet access while restricting local destinations by AI UID. Permit
  DNS only to configured nameservers. Keep narrowly scoped exceptions for the
  OpenCode IPC listener and configured LiteLLM endpoint. Network filtering is
  best-effort and must not be presented as VM-grade isolation.
- Install and reapply firewall rules through systemd. On restricted Ubuntu
  kernels, use a targeted AppArmor profile for Bubblewrap rather than disabling
  user-namespace protection globally.
- Provide read-only, single-file review with no shared-tree mount and no secret
  loading. Reject symlinks, non-regular files, oversized files, and non-text
  input. Protect the validated file descriptor against path replacement.
- Create only an owner-side SSH deploy key; never expose it to the AI sandbox.
- Persist enough state to remove launchers, services, firewall rules, mounts,
  ACLs, and generated configuration. Uninstall must use this state rather than
  current flags. Back up modified system files before replacement.
- Verify actual isolation after changes: account groups and sudo, filesystem
  boundaries, shared ACL inheritance, network drops and exceptions, and CLI
  startup. Failure must prevent or roll back activation.

## Preserved limits

- The AI can modify everything in the shared tree, including Git hooks and
  project tasks. Existing secrets and Git credentials in that tree are readable.
- Credentials deliberately placed in the AI home are readable and modifiable by
  the agent. Review mode is the exception: it receives no credentials.
- Internet and configured DNS remain available. UID filtering does not isolate
  the kernel, abstract Unix sockets, all IPv6 peers, or every NAT/LAN path.
- Vendor installers are trusted external inputs unless separately mirrored or
  pinned. Go must not add credentials or execute them as root.
- AI review is advisory and vulnerable to model mistakes and prompt injection.
  A `SAFE` verdict is never authorization to execute a file.
- Native macOS Seatbelt is deprecated and best-effort. Strict isolation requires
  the VM backend with the Linux implementation and a controlled proxy.

## Phase boundaries

Phase 1 implements portable validation, state, planning, diagnostics, and
contracts. Phase 2 implements the Linux lifecycle: accounts, prerequisites,
shared ACLs and bind alias, sealed runtime, UID nftables rules, systemd units,
launchers, state-driven uninstall, and interactive sandbox entry. Ubuntu
22.04/24.04 on-host verification remains required before claiming parity.
Phase 3 implements single-file review with a protected Linux descriptor and
root-owned macOS staging plus a dedicated Seatbelt profile. Phase 4 implements a
best-effort native macOS lifecycle with `dscl`/`dseditgroup`, `chmod` ACLs,
sealed runtime activation, symlink launchers, and per-execution Seatbelt. Native
macOS does not yet install pf anchors or launchd services, so network protection
is profile-only. Phase 5 keeps Lima as the default VM provider and may add
Docker/Podman only as explicit, separately validated providers; they are never
auto-selected.
