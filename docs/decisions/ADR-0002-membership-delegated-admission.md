# ADR-0002: Membership and delegated admission

- **Status:** Accepted (root succession deferred)
- **Date:** 2026-11-06

## Context

Any device can initialize a private network. New devices join with the network ID and password/secret and their own cryptographic identity. The founding device must not remain a permanent central approval authority. All peers must independently verify membership. Revocation must propagate and be enforceable.

## Decision

- Bootstrap creates a unique network ID, password verifier, root identity, and root membership certificate.
- Enrollment uses a short-lived challenge and a password-derived proof; the password is never sent in plaintext.
- The first device approves initial joiners.
- Once at least two devices are active, **any eligible active member** may independently approve another device. Majority approval is not required.
- Membership is represented by chained signed certificates rooted at the network root.
- Every peer verifies the chain, issuer validity, signatures, revocation status, and request replay protection independently.
- Legacy `/node/*` token routes remain for one release cycle and are documented as deprecated.
- Root succession/rotation is deferred; the existing root remains the trust anchor.

## Consequences

- Admission is decentralized and available while the founding device is offline.
- Any-member admission lowers friction but raises insider-risk; mitigations are audit, revocation, and a future admission capability.
- Revocation propagation depends on catalogue synchronization; a peer that has not learned a revocation may accept a request until it does.
- A lost or compromised root cannot currently be rotated without a future approved procedure.

## Alternatives considered

- Permanent root-only approval: rejected; creates a central authority.
- Majority/quorum admission: rejected; the product requires single eligible-member approval.
- Proof-of-work or open admission: rejected; the network is private.

## References

- `docs/PRODUCT_SPEC.md` §2, §6
- `docs/MEMBERSHIP_AND_TRUST.md` (target)
