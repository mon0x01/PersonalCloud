# ADR-0001: Private direct peer-to-peer architecture

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

PersonalCloud connects independently owned devices. The product must not depend on a central file-content server, cloud-storage intermediary, third-party relay, or mandatory middleware. File contents must travel directly between the owning source device and the consuming destination device.

## Decision

Use a direct peer-to-peer architecture:

- Every device runs an independent peer node.
- File bytes travel only over an authenticated encrypted connection between the source and destination peers.
- A coordinator may exchange metadata only; it never receives or relays file contents.
- There is no central content store and no relay fallback.

## Consequences

- Each peer must be independently operational.
- Direct connectivity may fail behind CGNAT or restrictive firewalls; this is an accepted limitation.
- NAT traversal may be evaluated, but a file relay is not permitted.
- Endpoint discovery, TLS identity, and address changes must be handled per peer.

## Alternatives considered

- Central relay server: rejected; violates the product identity.
- Third-party transfer middleware: rejected; adds a content intermediary and external dependency.
- Store-and-forward cloud storage: rejected; not a peer-to-peer filesystem.

## References

- `docs/PRODUCT_SPEC.md` §1, §5, §7
- `docs/NETWORKING.md` (target)
