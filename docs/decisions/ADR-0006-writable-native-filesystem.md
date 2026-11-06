# ADR-0006: Writable native filesystem integration

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

The current Linux adapter is read-only and the Android DocumentsProvider supports limited mutations. The final product requires native browsing plus create, write, edit, move, and delete across peers, with the source enforcing permissions.

## Decision

- Provide writable native filesystem integration on desktop Linux (FUSE or equivalent native mount) backed by the authenticated peer protocol.
- Provide the Android equivalent through the platform DocumentsProvider, including create, write, rename, move, and delete.
- Route all reads and mutations through a unified source-side authorization layer.
- Preserve the existing read path, range reads, integrity checks, and no-overwrite commit semantics.
- Keep the integration optional at build time where platform dependencies are unavailable; do not make the core node depend on a mounted filesystem.

## Consequences

- The read-only filesystem boundary must be extended to a read-write abstraction without weakening path/symlink protections.
- Concurrent writes, moves, and deletes require per-path coordination and safe commit ordering.
- Failure behaviour must be explicit: fail closed on policy denial, unavailable approval, offline owner, or integrity failure.
- Live mount and physical-device validation are required before claiming completion.

## Alternatives considered

- Read-only mount plus separate upload: rejected; does not meet the final product.
- Proprietary sync client: rejected; duplicates the filesystem and introduces copies.
- Web UI only: rejected; the product requires native integration.

## References

- `docs/PRODUCT_SPEC.md` §3.4, §8
- `docs/FILESYSTEM_AND_PERMISSIONS.md` (target)
