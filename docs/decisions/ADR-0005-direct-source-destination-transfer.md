# ADR-0005: Direct source-to-destination transfer and coordination

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

Any active member must be able to initiate an operation between any two devices. For a transfer initiated by Z from X to Y, the data path must be X → Y. Z may coordinate but must never receive or relay file contents. Existing resumable transfer and integrity mechanisms must be preserved.

## Decision

- Preserve the existing direct, chunked, resumable, integrity-verified transfer engine for source-to-destination data.
- Add metadata-only coordination so a third device Z can initiate an X → Y operation.
- Recommended coordination model: Z issues a signed transfer intent; X and Y validate membership and policy; Y receives a short-lived capability and pulls directly from X. Z receives status metadata only.
- A move is a safe sequence: source validation → destination authorization → direct transfer → integrity verification → destination commit → source deletion → final outcome.
- Never delete the source when destination publication is unconfirmed or the source has changed.
- Persist move/transfer journals for retries, resumability, idempotency, and crash recovery.
- Report partial outcomes honestly (for example, destination committed but source retained).

## Consequences

- The destination-pull model keeps the destination in control and avoids a third party causing a source to open arbitrary outbound connections.
- Coordinators require authenticated status channels but no content access.
- Protection approval applies to the destructive leg (source deletion, destination overwrite).
- Existing sender-initiated transfers remain supported for compatibility.

## Alternatives considered

- Source-push initiated by Z: rejected as the default; a third party could cause a source to connect outward.
- Coordinator relay: rejected; violates ADR-0001.
- Blind copy-then-delete: rejected; risks data loss.

## Implementation note (2026-11-08)

M2.1 realizes coordination as a ticket-authorized source push rather than the destination-pull model recommended above:

- Z fetches source metadata from X, signs a short-lived ticket, and sends the ticket to X. Z never opens the source file or creates a receiver session.
- X independently verifies the ticket against Z's active membership key, requires the ticket to be bound to X and the destination to be an active member, authorizes its own source resource, creates the destination session, and streams chunks directly to Y.
- Y independently verifies the same ticket, requires the authenticated uploader to be the ticket source and the receiver to be the ticket destination, then authorizes its own write.
- X deletes the source only after Y confirms a verified commit and X revalidates that the source is unchanged.

This preserves the ADR's core invariants: Z never receives or relays bytes, both endpoints authorize independently, and a MOVE cannot lose the only copy. The outbound-connection concern from the alternatives section is bounded because X connects only to an active member's advertised endpoint after verifying a signed ticket issued by an active member, and the ticket names the exact source and destination paths. Destination pull remains an alternative if stronger destination-initiated connection control is required later.

## References

- `docs/PRODUCT_SPEC.md` §5
- `docs/TRANSFER_SEMANTICS.md` (target)
