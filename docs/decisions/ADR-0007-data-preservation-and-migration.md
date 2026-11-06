# ADR-0007: Data preservation and migration

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

Existing nodes hold node identities, membership keys/certificates, TLS material, grants, reference metadata, peer state, audit history, recovery snapshots, and managed files. The product is evolving from grant-only access to default broad access with privacy/protection, writable integration, and delegated admission. Upgrades must not destroy user data or silently expose existing files.

## Decision

- Preserve all existing persistent state and user data.
- Use additive, versioned changes; dual-read/single-write during migration; never destructive in-place rewrites.
- Back up the state directory before the first migration write; abort on failure.
- Existing files default to **Normal** (broad access) only after the owner gives one-time consent; they are never silently exposed.
- Existing managed files remain network-wide accessible.
- Existing certificates remain valid; new capability/epoch fields default compatibly.
- Keep legacy `/node/*` routes for one release cycle.
- Root succession is deferred; no forced rotation.
- New data domains (policy, eligible roots, revocations, moves) are additive.
- Rollback must remain possible: old code can ignore new fields.

## Consequences

- Migrations are idempotent and re-runnable.
- Owner consent is a required gate for activating broad access on upgraded devices.
- Documentation must state what is preserved and what changes.
- Cleanup of generated artifacts is separate from user-data preservation and requires a manifest.

## Alternatives considered

- Reinitialize state on upgrade: rejected; destroys identities and trust.
- Silent broad exposure: rejected; violates consent and privacy.
- Big-bang format rewrite: rejected; high risk of data loss.

## References

- `docs/PRODUCT_SPEC.md` §3.3, §9
- `docs/OPERATIONS.md` (target)
- `docs/ROADMAP.md` (target)
