# ADR-0004: Private and protected resources

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

Broad default access must coexist with owner-controlled privacy and safety. Owners need a way to hide resources completely and a way to keep important resources readable while requiring approval for destructive operations. Enforcement must happen at the source device, not at clients, because cached metadata cannot be trusted.

## Decision

Introduce two owner-controlled exception modes:

- **PRIVATE / HIDDEN:** the resource disappears from remote browsing and catalogues; all remote access is denied at the source; active sessions are invalidated or restricted; cached metadata cannot bypass the restriction.
- **PROTECTED:** the resource remains visible and readable; destructive operations (delete, move the original, overwrite/replace, destructive bulk operations) require explicit owner approval bound to the specific operation and resource; when approval is unavailable, fail safely.

Precedence: most specific path rule wins; `PRIVATE` overrides `PROTECTED`; directory rules apply recursively unless a child overrides.

Approval is short-lived, single-use, and bound to the requesting member, operation, resource, and transfer (where applicable).

## Consequences

- A policy store and a single source-side authorization evaluator are required.
- Catalogue/list/search must filter private resources.
- Policy changes require an epoch or equivalent so clients invalidate cached metadata.
- Bulk operations require scoped approval, never a blanket wildcard.
- The user-facing model is explainable as three states: Normal, Private, Protected.

## Alternatives considered

- Client-side filtering only: rejected; cached metadata would bypass privacy.
- Per-file ACLs only: rejected; does not cover recursive directories or approval workflows.
- Deny-all default: rejected; contradicts ADR-0003.

## References

- `docs/PRODUCT_SPEC.md` §4
- `docs/FILESYSTEM_AND_PERMISSIONS.md` (target)
- `docs/SECURITY.md` (target)
