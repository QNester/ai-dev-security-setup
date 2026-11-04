# Platform matrix

| Capability | Linux native | macOS native | macOS VM |
| --- | --- | --- | --- |
| Supported targets | Ubuntu/Debian, amd64/arm64 | macOS 13–15, amd64/arm64 | macOS 13–15, amd64/arm64 |
| Accounts | `useradd`, `usermod`, `passwd` | `sysadminctl`, `dscl`, `dseditgroup` | Linux account backend in guest |
| Shared access | `setfacl`, bind alias, fstab | `chmod +a/-a`, execute-only traversal, SBPL | virtiofs/9p plus Linux ACLs |
| Sandbox | Bubblewrap namespaces | deprecated `sandbox-exec` Seatbelt | Bubblewrap in Linux guest |
| Network | UID nftables, configured DNS | SBPL/pf best-effort | Linux rules plus controlled proxy |
| Services | systemd | launchd | systemd in guest |
| Review | validated fd, `ro-bind-data` | root-owned staging and SBPL | Linux review backend |
| Isolation claim | host-level, best-effort network | reduced, best-effort | preferred strict mode |
| Phase 1 status | diagnostics/contracts only | diagnostics/contracts only | detection/contracts only |

`--backend auto` selects Bubblewrap on Linux and VM on macOS. Selecting
`--backend native` on macOS explicitly accepts reduced isolation. Absence of a
VM provider is a doctor failure in auto/VM mode, not a reason to silently fall
back to native Seatbelt.

All backends currently stop before system mutation. Integration targets listed
above are requirements for later phases, not a claim of tested support today.
