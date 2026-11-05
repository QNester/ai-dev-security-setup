# End-to-end tests

These tests mutate a disposable Ubuntu guest. They must never run on a
developer host without the sentinel and `SANDBOXCTL_E2E=1` guard.

## Guest suite

`tests/e2e/guest` is a Go test binary built for Linux and executed as root
inside the guest. It covers:

- account and group creation;
- owner-home isolation and shared-tree ACLs;
- shared bind alias and mount options;
- nftables and systemd activation;
- root-owned launcher symlinks;
- Bubblewrap `enter`;
- descriptor-based `review`;
- update idempotency;
- state-driven uninstall.

The test uses the product-level `--skip-cli` mode plus a fixture runtime, so it
does not depend on vendor installer URLs or network access to Claude/OpenCode.
`--skip-cli` is not a test-only hook: it is the supported `install`/`update`
mode for retaining an operator-managed or offline sealed runtime.

## Runner

```bash
export SANDBOXCTL_E2E=1

# Existing GitHub-hosted Ubuntu runner (the runner is the disposable VM)
go run ./tests/e2e/runner --provider hosted --arch amd64

# Local macOS
go run ./tests/e2e/runner --provider lima --arch arm64

# Local Linux
go run ./tests/e2e/runner --provider multipass --arch amd64
```

The runner builds a static Linux `sandboxctl` and the e2e test binary under
`dist/`, copies them into the guest, creates `/etc/sandboxctl-e2e`, and destroys
the VM unless `--keep` is set.

## Safety

- `SANDBOXCTL_E2E=1` is mandatory.
- `/etc/sandboxctl-e2e` must exist inside the guest.
- The suite requires root and a disposable filesystem.
- It installs `ai-dev`, modifies `/etc`, systemd, nftables, ACLs, and
  `/usr/local`.
- Cleanup is best-effort; hosted runners are discarded, local VMs are deleted.
