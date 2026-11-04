# ADR 0002: State-driven lifecycle

## Status

Accepted

## Context

An uninstall based on current flags can miss resources created by an older
configuration. Partial installation and verification failures can otherwise
leave active launchers or weakened restrictions.

## Decision

Persist a strict, versioned state document containing created identities,
shared-tree changes, services, firewall, runtime, and backups. Update and
uninstall consume this document. Apply failures and verification failures invoke
rollback in reverse order. State writes are atomic and use mode `0600`.

Do not serialize credentials or accept unknown state fields. Missing or invalid
state is an error for update and uninstall.

## Consequences

Removal can follow historical paths safely, but each future mutating backend
must record ownership before activation. Phase 1 supplies storage and planning
only; real transactional resource adapters arrive in later phases.
