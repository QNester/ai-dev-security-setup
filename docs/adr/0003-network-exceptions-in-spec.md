# ADR 0003: Network exceptions belong to the portable spec

## Status

Accepted

## Context

A single `open`, `proxy`, or `deny` policy cannot express the reference behavior:
DNS is limited to configured nameservers, while LiteLLM and OpenCode IPC require
narrow host/port/protocol exceptions. Platform adapters must not infer those
resources from global configuration on their own.

## Decision

`base.Spec` carries `DNSServers` as validated IP addresses and
`AllowedEndpoints` as validated host, port, and protocol tuples in addition to
`NetworkPolicy`. The deny policy rejects all exceptions. Core constructs this
policy; Linux translates it to nftables rules, native macOS to best-effort
Seatbelt/pf rules, and the VM backend to guest Linux rules plus its proxy.

All sandbox paths in `Spec` must be clean absolute paths. Review descriptors use
`-1` when absent.

## Consequences

The portable contract can represent the reference exceptions without exposing
nftables, SBPL, or pf syntax to core. A future controlled-proxy design can add a
validated proxy endpoint without weakening the deny-by-default contract.
