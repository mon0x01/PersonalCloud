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

## References

- `docs/PRODUCT_SPEC.md` §5
- `docs/TRANSFER_SEMANTICS.md` (target)
