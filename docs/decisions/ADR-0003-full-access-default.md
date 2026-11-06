# ADR-0003: Full-access default for eligible storage

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

The central product requirement is that a device joining the private network receives broad filesystem access to other active members by default. Users must not need to upload files into PersonalCloud before another device can access them. The prior implementation exposed only explicitly registered reference roots plus the managed storage root, which is the inverse of the required default.

## Decision

- Default permissions for eligible user-data storage are broad: browse, view, open, read, download, create, write, edit, upload/place, move, and delete.
- Eligible storage means owner-authorized user-data volumes and filesystems.
- Operating-system internals, block devices, credential stores, private keys, another OS user's private data, and PersonalCloud's own private state are excluded from automatic exposure.
- New devices explicitly confirm eligible-storage access during enrollment.
- Existing devices require a one-time owner confirmation before broad access is activated. Existing contents are never silently exposed during upgrades.
- Owners may explicitly add or exclude volumes/directories; explicit exclusions always win.

## Consequences

- A unified source-side authorization layer is required for all filesystem operations.
- Explicit per-member reference grants remain as overrides and for compatibility, not as the default gate.
- Privacy and protection are owner-controlled exceptions (see ADR-0004).
- The documentation must describe the default and the exclusions clearly to normal users.

## Alternatives considered

- Keep grant-only access: rejected; contradicts the product's default-access requirement.
- Expose everything including OS internals: rejected; unsafe and outside "user data".
- Opt-in per file: rejected; the product requires broad default access.

## References

- `docs/PRODUCT_SPEC.md` §3, §4
- `docs/FILESYSTEM_AND_PERMISSIONS.md` (target)
