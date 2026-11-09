# ADR-0002: Membership and delegated admission

- **Status:** Accepted (root succession deferred; M5 hardening implemented)
- **Date:** 2026-11-06 (M5 update 2026-11-09)

## Context

Any device can initialize a private network. New devices join with the network ID and password/secret and their own cryptographic identity. The founding device must not remain a permanent central approval authority. All peers must independently verify membership. Revocation must propagate and be enforceable.

## Decision

- Bootstrap creates a unique network ID, password verifier, root identity, and root membership certificate.
- Enrollment uses a short-lived challenge and a password-derived proof; the password is never sent in plaintext.
- The first device approves initial joiners.
- Once at least two devices are active, **any eligible active member** may independently approve another device. Majority approval is not required.
- Each approval also produces a short-lived Ed25519-signed `AdmissionApproval` bound to the network ID, enrollment request UUID, candidate node ID/name/public key/endpoint, approver node ID, and the exact SHA-256 of the approver's membership certificate.
- The joining device verifies the approval signature, binding, lifetime (default 15 minutes, maximum 60 minutes), certificate identity and one-time use in addition to the certificate chain. Legacy approval results without the signed record remain accepted for compatibility.
- Membership is represented by chained signed certificates rooted at the network root.
- Every peer verifies the chain, issuer validity, signature validity, issue ordering, expected network root, duplicate identities, revocation status, and request replay protection independently.
- Revocation produces an Ed25519-signed `MembershipRevocation` record attributable to an active member. Revocation is monotonic and cannot be reversed by a stale catalogue; chains that pass through a revoked member are rejected.
- A locally inactive or revoked member cannot issue admissions or signed requests. A member revoked by another peer is rejected as soon as that peer's catalogue is applied.
- Broad filesystem consent is explicit: new devices default to no broad access and record owner consent during enrollment; existing devices must opt in during upgrade.
- Legacy `/node/*` token routes remain for one release cycle and are documented as deprecated.
- Root succession/rotation is deferred; the existing root remains the trust anchor.

## Consequences

- Admission is decentralized and available while the founding device is offline.
- Any-member admission lowers friction but raises insider-risk; mitigations are signed attributable approvals, explicit admission authority checks, revocation, and catalogue propagation.
- Revocation propagation depends on catalogue synchronization; a peer that has not learned a revocation may accept a request until it does. Once applied, revocation is monotonic and cannot be reversed by stale state.
- A revoked member that still holds stale local state can sign requests or approvals, but peers that know the revocation reject them and refuse certificate chains passing through the revoked identity.
- A lost or compromised root cannot currently be rotated without a future approved procedure.

## Alternatives considered

- Permanent root-only approval: rejected; creates a central authority.
- Majority/quorum admission: rejected; the product requires single eligible-member approval.
- Proof-of-work or open admission: rejected; the network is private.

## References

- `docs/PRODUCT_SPEC.md` §2, §6
- `docs/MEMBERSHIP_AND_TRUST.md` (target)
