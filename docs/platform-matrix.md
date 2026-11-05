# Platform matrix

| Capability | Linux native | macOS native | macOS VM |
| --- | --- | --- | --- |
| Supported targets | Ubuntu/Debian, amd64/arm64 | macOS 13–15, amd64/arm64 | macOS 13–15, amd64/arm64 |
| Accounts | `useradd`, `usermod`, `passwd` | `sysadminctl`, `dscl`, `dseditgroup` | Linux account backend in guest |
| Shared access | `setfacl`, bind alias, fstab | `chmod +a/-a`, execute-only traversal, SBPL | virtiofs/9p plus Linux ACLs |
| Sandbox | Bubblewrap namespaces | deprecated `sandbox-exec` Seatbelt | Bubblewrap in Linux guest |
| User namespaces | unrestricted on 22.04; targeted AppArmor 4 profile on 24.04+ | N/A | Linux guest policy |
| Network | UID nftables, configured DNS | SBPL profile-only; pf deferred | Linux rules plus controlled proxy |
| Services | systemd | per-execution Seatbelt; launchd deferred | systemd in guest |
| Review | validated fd, `ro-bind-data` | root-owned staging and SBPL | Linux review backend |
| Isolation claim | host-level, best-effort network | reduced, best-effort | preferred strict mode |
| Current status | Lifecycle and fd-based review implemented; real read-only probes; Ubuntu VM runs pending | Native lifecycle and staged review implemented best-effort; pf/launchd deferred | Lima provider foundation; Linux guest lifecycle pending |

`--backend auto` selects Bubblewrap on Linux and VM on macOS. Selecting
`--backend native` on macOS explicitly accepts reduced isolation. Absence of a
VM provider is a doctor failure in auto/VM mode, not a reason to silently fall
back to native Seatbelt.

Linux native now mutates the host and implements descriptor-based review; both
still need Ubuntu 22.04/24.04 VM runs. macOS native implements a best-effort
lifecycle and staged Seatbelt review; pf/launchd services and the VM lifecycle
are deferred. Integration targets listed above are requirements, not a claim of
tested support today.

Lima is the default and only automatically installable VM provider. UTM remains
a manual alternative. Docker and Podman are not selected by `--backend auto` and
are deferred to Phase 5 as explicit, separately validated providers; see
[ADR 0004](adr/0004-container-providers-deferred-to-phase-5.md).
