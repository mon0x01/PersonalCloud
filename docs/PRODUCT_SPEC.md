# PersonalCloud Product Specification

**Status:** Canonical source of truth (M0)
**Last updated:** 2026-11-06
**Authority:** This document defines the product. Other documents must agree with it. Where they conflict, this document wins.

---

## 1. Product identity

PersonalCloud is a private, decentralized, authenticated peer-to-peer network that connects independently owned devices and gives network members direct access to one another's filesystems.

It is **not**:

- A conventional cloud-storage application.
- A file-upload platform that requires importing files before sharing.
- A central storage server.
- A system that routes file contents through an intermediary device.
- A system dependent on third-party cloud storage or file-transfer middleware.

Every enrolled device is an independent peer and retains ownership of its physical storage.

### 1.1 Product invariants

1. **Direct peer-to-peer file content.** File bytes travel only between the owning source device and the consuming destination device.
2. **No relay.** No third device, server, or service may receive or forward file contents. A coordinator may exchange metadata only.
3. **No central content store.** There is no central file-content server and no cloud-storage intermediary.
4. **Independent operation.** Each peer remains independently operational; the founding device is not a permanent central server.
5. **Original files stay in place.** Existing files are referenced in their original filesystem locations. Remote viewing does not require a preliminary upload or copy.
6. **Source-side enforcement.** The device that owns a file enforces access, privacy, protection, and integrity.
7. **No mandatory application-level encryption at rest.** The product does not silently introduce an at-rest encryption architecture. Host/OS encryption guidance is documented separately.
8. **Honest status.** Documentation must never describe an unimplemented feature as complete.

---

## 2. Network creation and membership

### 2.1 Network initialization

Any eligible device can initialize a new private network. Initialization creates:

- A unique network ID.
- A network password or high-entropy network secret.
- Network identity and cryptographic trust information.
- The initial admission authority.

The password/secret is never transmitted in plaintext. Enrollment uses a short-lived challenge and a password-derived proof.

### 2.2 Joining

A new device supplies:

- The network ID.
- The network password/secret.
- Its own generated cryptographic device identity.

The device submits an enrollment request and remains pending until approved.

### 2.3 Admission authority (approved)

- Initially, the first device approves joining devices.
- When at least **two devices are active**, **any eligible active member** may independently approve another device.
- Majority approval is **not** required for ordinary admission.
- Each approval is a short-lived Ed25519-signed `AdmissionApproval` record bound to the network, enrollment request, candidate node ID/name/public key/endpoint, approver node ID, and the exact SHA-256 of the approver's membership certificate.
- The joining device verifies the approval signature, binding, lifetime and one-time use in addition to the chained certificate.
- All peers independently verify membership and signed approvals.
- The existing certificate chain is preserved wherever possible.
- Root succession/rotation is **deferred**. The existing root remains the trust anchor. No unapproved succession protocol is implemented.

### 2.4 Verification and revocation

- Every peer verifies membership certificates independently: chain to the network root, issuer validity, signature validity, issue ordering, revocation status, and replay protection.
- Revocation is an Ed25519-signed `MembershipRevocation` record attributable to an active member. Unsigned legacy `REVOKED` catalogue status remains accepted for compatibility.
- Revocation is monotonic: a stale catalogue can never reactivate a revoked identity, and a certificate chain that passes through a revoked member is rejected.
- Revocation must be authenticated, propagated, and enforceable by every peer.
- A revoked member cannot approve new devices or perform authorized protocol operations once the revocation is known.
- Revocation cannot retract bytes already downloaded by a peer.

### 2.5 Compatibility

- Legacy `/node/*` token routes are retained for **one release cycle** for compatibility with older peers.
- They are documented as deprecated and are not the primary membership model.

---

## 3. Filesystem access

### 3.1 Default access

When a device joins the network and explicitly consents, it receives broad filesystem access to other active members' eligible user-data storage by default. The user must not need to upload files into PersonalCloud before another device can access them.

Consent is explicit and is never granted silently:

- A new device starts with broad filesystem access disabled and records the owner's consent during enrollment (`network join ... --consent`, Android enrollment option) or later through `filesystem consent`.
- An existing device upgraded to a build with broad-access consent must opt in explicitly; it never inherits access silently.
- Revoking consent disables broad access immediately and is reflected in membership status as consent required.

Default permissions for eligible storage:

- Browse and list.
- View, open, read, download.
- Create, write, edit, upload/place.
- Move.
- Delete.

### 3.2 Eligible storage

"Full storage access" means all owner-authorized user-data volumes and filesystems by default, subject to explicit exclusions.

**Default exclusions (never automatically exposed):**

- Raw block devices and special files.
- Operating-system internals and kernel pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`, `/etc`, `/var`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`).
- Another operating-system user's private account data.
- Credential stores, private keys, keystores, truststores, token vaults, and browser/secret stores.
- PersonalCloud's own private state directory (`data/`).

Owners may explicitly configure additional eligible volumes or directories. Explicit exclusions always win over defaults.

### 3.3 Consent

- **New devices** explicitly confirm eligible-storage access during enrollment.
- **Existing devices** must receive a one-time owner confirmation before broad filesystem access is activated.
- Existing filesystem contents are **never silently exposed** during upgrades.

### 3.4 Native filesystem integration

PersonalCloud integrates with the underlying filesystem so a user on Device Y can navigate and operate on eligible directories on Device X through native integration.

The system must:

- Read the original file from its existing location.
- Stream content directly from its owning peer.
- Support bounded range reads and seeking.
- Avoid unnecessary duplicates.
- Avoid a preliminary upload into PersonalCloud.
- Enforce permissions at the source device.

Remote modifications operate on the owner's actual file through a safe, authenticated operation protocol. A read-only virtual filesystem alone is not sufficient for the final product.

- **Desktop Linux:** writable filesystem integration (FUSE or equivalent native mount) over the authenticated peer protocol.
- **Android:** the platform-equivalent document provider with create, write, rename, move, and delete support.

The M3 implementation exposes writable eligible storage at `/Devices/<device>/Filesystem/<root>/...` on Linux and `Filesystem/<root>/...` in the Android provider. The existing `References` and `Distributed-Storage` planes remain read-only. Native adapters never write to remote storage directly: every mutation is authorized and executed by the owning peer. Writes are staged locally and published only after a complete SHA-256-verified upload, so an interrupted or failed write does not truncate or corrupt the original file. No-overwrite publication rejects conflicting commits, and rename/move refuses to replace an existing destination. `chmod`, `chown`, `mknod`, links, extended attributes and `fallocate` fail closed on writable paths; `utimens` is a documented no-op because the owner controls metadata.

---

## 4. Privacy and protected resources

Each device owner can change filesystem privacy at any time. There are two exception modes in addition to normal access.

### 4.1 Private / Hidden

When an owner marks a file or directory **PRIVATE**:

- It disappears from remote browsing and catalogues.
- Other devices lose access.
- The source peer enforces the restriction even if clients hold cached metadata.
- Existing active sessions are invalidated or restricted at the next operation.

### 4.2 Protected

When an owner marks a file or directory **PROTECTED**:

- It remains visible and readable.
- Destructive operations require explicit owner approval according to the configured policy.
- Destructive operations include at minimum: delete, move the original, overwrite/replace, and destructive bulk operations.
- Approval is bound to the specific operation and resource (and transfer, where applicable).
- When approval is unavailable, the operation fails safely.

### 4.3 Default behaviour

Ordinary eligible files are accessible with broad permissions by default. Privacy and protection are owner-controlled exceptions, not the default restriction on every file.

### 4.4 Explainable model

The user-facing model is three states:

| State | Visible | Read | Destructive operations |
|---|---|---|---|
| Normal | Yes | Yes | Allowed |
| Private / Hidden | No | No | Denied |
| Protected | Yes | Yes | Require owner approval |

The most specific path rule wins. `PRIVATE` overrides `PROTECTED`. Directory rules apply recursively unless a child overrides them.

---

## 5. Direct peer-to-peer file operations

### 5.1 Any member can initiate

Any active network member may initiate an operation between any two devices. For example, in a network of X, Y, Z, P, Q, Device Z may initiate a transfer from X to Y.

The data path must be:

```
Device X → Device Y
```

Device Z may coordinate the operation but must never receive or relay file contents.

### 5.2 Remote viewing

When Y opens a file stored on X:

```
X filesystem → X peer → authenticated encrypted connection → Y filesystem consumer
```

There is no upload into PersonalCloud followed by a second download.

### 5.3 Remote placement

When X sends a file to Y:

- Transfer directly between X and Y.
- Stage data at the destination.
- Verify chunk and whole-file integrity.
- Publish safely without unintended overwrites.

### 5.4 Remote move

A move is not a blind copy followed by immediate deletion. The required order is:

1. Verify source and destination authorization.
2. Transfer from source directly to destination staging.
3. Verify complete integrity.
4. Commit the destination.
5. Only after confirmed destination publication, request source deletion.
6. Apply protection and owner-approval rules.
7. Report partial outcomes honestly if source deletion fails.

The only copy of a file must never be lost during failure recovery. Retries, resumability, idempotency, and crash recovery are required.

### 5.5 Transfer integrity

- Chunked transfer with per-chunk integrity.
- Full-file integrity verification before publication.
- Durable receiver journal and resume.
- Idempotent retries.
- No-overwrite publication.
- Commit receipt/tombstone to reconcile sender and receiver after a crash.

---

## 6. Security requirements

Every peer connection authenticates the intended device. All remote viewing, reads, downloads, uploads, and transfers use authenticated encrypted transport.

Required:

- Modern TLS.
- Strict certificate and peer identity verification.
- Per-device cryptographic signing identities.
- Secure enrollment and approval.
- Replay protection.
- Membership revocation.
- Source-side authorization.
- Protection against path traversal and symbolic-link attacks.
- Safe concurrent writes and deletes.
- Integrity verification.
- Secure credential management.
- No trust-all TLS.
- No disabling certificate validation for convenience.

Possession of a network ID and password is **not** sufficient authorization for subsequent network requests. Every request carries a signed member identity.

### 6.1 At-rest position

No mandatory application-level encryption of file contents at rest. Use host/OS encryption (LUKS, BitLocker, FileVault, Android platform encryption) where protection against powered-off device theft is required. Android application state uses Keystore-backed AES-GCM. This is not a claim that PersonalCloud encrypts all user file contents at rest.

### 6.2 Threat model summary

- Network attackers: mitigated by TLS and signed requests.
- Malicious members: mitigated by source-side policy, privacy, protection, revocation, and audit.
- Compromised devices: mitigated by revocation; root succession deferred.
- Unauthenticated attackers: enrollment and challenge endpoints are rate-limited and input-bounded.
- Path/symlink attackers: canonicalization, `NOFOLLOW_LINKS`, and traversal rejection.
- Replay attackers: timestamp window, nonce store, body digest.

---

## 7. Connectivity

The system uses direct device-to-device communication for file contents.

- Local LAN connectivity is the primary path.
- Different-network connectivity may require public IPv6, port forwarding, or direct NAT traversal.
- CGNAT and restrictive firewalls may make direct connection impossible.
- IPv4 and IPv6 are both considered.
- Endpoint discovery and address changes are reconciled without changing signed identity.
- TLS certificate renewal must preserve trust.
- Network loss and recovery are handled without data loss.

No file relay, central content server, or mandatory third-party middleware is introduced. Direct connectivity diagnostics are read-only and explicitly report that inbound reachability is unverified.

---

## 8. Platform boundaries

### 8.1 Desktop (Java 21+)

- Headless node with HTTPS peer endpoint.
- Owner-only Unix-domain local control socket and CLI.
- Writable native filesystem integration on Linux.
- Reference and managed storage planes.
- Membership, catalogue, transfers, diagnostics.

### 8.2 Android (peer-core Java 17; app target SDK 35)

- Signed network membership and storage operations.
- Foreground peer service.
- DocumentsProvider for native file access, with create/write/rename/move/delete.
- SAF references and app-owned managed storage.
- Android 13/API 33+ required for platform Ed25519 membership; older versions use the legacy compatibility path.

---

## 9. Implementation status (honest snapshot)

This section records the status at the latest completed milestone and is updated at every milestone. It distinguishes verified functionality from target scope.

### 9.1 Verified implemented

- Direct peer-to-peer transport and no-relay architecture.
- Network bootstrap, password-proved enrollment, explicit approval, chained certificates, signed requests, replay protection, revocation, catalogue sync.
- Reference plane: zero-copy registration, browsing, search, stat, bounded range reads, SHA-256-verified download, owner-side recovery snapshots.
- Managed plane: network-wide listing/stat/download/delete, staging, no-overwrite commit, resumable chunked transfer, commit tombstones.
- Upload/download atomicity, multi-process state consistency, symlink/path-traversal rejection.
- Android peer-core parity and desktop–Android interoperability (simulated).
- Linux writable FUSE adapter source and Dolphin actions (compiled and launch-smoke-tested in CI; live kernel mount pending).
- Android debug APK assembly in CI; writable DocumentsProvider and SAF source contracts.
- Direct connectivity diagnostics.
- Owner policy foundation: persistent NORMAL/PRIVATE/PROTECTED rules, policy epoch, owner-only local control/CLI management, and short-lived single-use protection approvals.
- Eligible-root filesystem access (M2): owner consent, OS-user ownership boundaries, system/credential/PersonalCloud-state exclusions, signed `/network/fs/*` browse/stat/bounded-range/download/create/write/move/delete routes, source-side PRIVATE hiding and PROTECTED approval enforcement, atomic SHA-256-verified writes, no-overwrite publication, and separate source/destination approvals for protected moves.
- Writable native integration (M3): Linux FUSE create/write/read/mkdir/rename/delete/truncate with safe staging and flush/release publication; Android DocumentsProvider create/write/rename/move/delete through signed owner-authorized calls; native-adapter tests for round trips, no-overwrite conflicts, concurrent writers, failed/rejected commits, traversal and symlink escapes, PRIVATE/PROTECTED enforcement and consent revocation.
- Three-peer coordinated transfers (M2.1): a coordinator Z issues a short-lived Ed25519-signed ticket binding source, destination, roots/paths, operation, version, size, digest, expiry, request/transfer identity and optional approvals. X and Y verify independently and durably claim the ticket per role. X streams resumable chunks directly to Y; Z exchanges metadata and status only and never receives bytes. COPY and safe MOVE are implemented with destination commit and source revalidation before deletion, a durable `DELETING` state, honest `COPIED_NOT_MOVED` partial outcomes, idempotent retries and revoked-member rejection. Desktop local control/CLI exposes `coordinated plan/prepare/transfer/status/retry/list`; three-node automated tests cover direct X→Y isolation, invalid/expired/replayed tickets, wrong identities/paths/digests, source mutation, destination failure, interruption recovery, protected approvals and revocation.
- Delegated admission hardening (M5): signed short-lived `AdmissionApproval` records attributable to the exact approving active member and certificate, post-threshold independent approval by any active member, hardened certificate-chain validation (future issue, parent ordering, duplicate identity, expected root), signed monotonic `MembershipRevocation` records with stale-catalogue conflict rejection, refusal of requests and admissions by revoked members, and explicit broad-filesystem consent during new-device enrollment and existing-device upgrade. Desktop and Android peer cores produce and verify the same records; desktop→Android and Android→desktop admission and revocation are covered by interoperability tests.
- Protocol and storage reliability hardening (M6): JSON input is bounded to 16 MiB and 64 nesting levels; per-source request, enrollment-challenge and enrollment-submission windows are rate-limited, and authenticated filesystem operations have a per-member window; signed presence binds an advertised endpoint to the member signing key (legacy unsigned presence may not move a certificate-bound endpoint); wildcard, link-local and multicast endpoint literals are rejected; pending protection approvals are bounded per member and per node; transfer sessions are bounded per node and per member with configurable aggregate and per-member staging budgets; durable coordinated-ticket claims are pruned; reference snapshot retention evicts oldest snapshots first; owner-side audit records cover eligible-filesystem mutations and sensitive authorization decisions; startup failure closes partially initialized components. Desktop and Android peer cores implement the same presence and endpoint checks.

### 9.2 Target functionality not yet implemented

- Per-member TLS certificate pinning beyond the current signed presence/endpoint binding.
- Root succession/rotation, which remains explicitly deferred.
- Complete `docs/` documentation structure and ADRs beyond M0.

### 9.3 Known limitations

- No independent security audit.
- Protection approvals are process-local; a restart fails closed and requires fresh approvals.
- Remote filesystem mutations and sensitive authorization decisions are audited, and filesystem operations are bounded by source and member request windows. Tiered per-member filesystem quotas (for example, distinct bulk-delete budgets) are not yet enforced.
- Fault-injection tests are controlled software simulations of interrupted writes, verification failures and partial commits. They are not a substitute for real disk-full, power-loss, filesystem-corruption or physical-device testing.
- Broad-access consent is explicit in enrollment and upgrade flows; Android UI copy and migration messaging for the consent prompt remain minimal.
- Root succession/rotation is not implemented; a compromised or lost root identity requires a new network identity.
- The OS-user ownership boundary checks the eligible root itself and rejects shared home parents such as `/home` and `/Users`. It does not enumerate every user home beneath an arbitrary owner-controlled volume.
- Remote range reads recompute the full-file digest on each request.
- Directory moves and recursive deletes refuse trees containing PRIVATE/PROTECTED rules or excluded credential paths; per-descendant approval is not yet available.
- Native adapters stage write-back locally: Linux uses the system temporary directory; Android uses a proxy staging file capped at 512 MiB for editable files. Larger files remain readable but cannot be edited in place.
- FUSE `utimens` is a documented no-op; `chmod`, `chown`, `mknod`, links, xattrs and `fallocate` fail closed on writable paths.
- Rename/move refuses to replace an existing destination to avoid unintended overwrites; applications must delete the destination first.
- Android DocumentsProvider writable operations require an active membership and a reachable owner; there is no offline write queue.
- No live Linux FUSE mount/kernel callback validation.
- No physical Android device/lifecycle/SAF validation.
- Coordinated transfers are exposed through the desktop local-control socket and CLI; Android coordinator/UI integration is not yet implemented.
- Coordinated ticket claims, source jobs and coordinator requests are node-local durable state. Device clock skew beyond 120 seconds fails closed.
- No root succession/rotation (deferred by decision).
- No NAT traversal or relay.
- No mandatory at-rest encryption.
- No load/long-duration validation yet.

### 9.4 Deferred decisions

- Root succession/rotation protocol.
- Removal date for legacy `/node/*` routes (retained for one release cycle).
- Final Android UX.
- Any at-rest encryption architecture.

---

## 10. Documentation map

- `docs/PRODUCT_SPEC.md` — this canonical specification.
- `docs/ARCHITECTURE.md` — system architecture and components.
- `docs/NETWORKING.md` — peer communication and connectivity.
- `docs/MEMBERSHIP_AND_TRUST.md` — enrollment, admission, identities, revocation.
- `docs/FILESYSTEM_AND_PERMISSIONS.md` — native access, default permissions, private/protected.
- `docs/TRANSFER_SEMANTICS.md` — viewing, placement, movement, integrity, recovery.
- `docs/SECURITY.md` — threat model, cryptography, secrets, authorization.
- `docs/DEVELOPMENT.md` — environment, build, workflow.
- `docs/TESTING.md` — test layers and validation evidence.
- `docs/OPERATIONS.md` — startup, configuration, diagnostics, backup, recovery.
- `docs/ROADMAP.md` — remaining milestones.
- `docs/decisions/` — architecture decision records.

Root `README.md` is the entry point. Historical release notes are preserved.
