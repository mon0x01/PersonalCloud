# PersonalCloud security model

## Security goals

PersonalCloud is designed for a private set of personally operated devices. It must prevent unrelated users from joining or accessing the network, protect peer traffic, isolate local administration from the network listener, and enforce file permissions at the owning node.

## Current protections in source

- Non-loopback peer endpoints require HTTPS with a configured PKCS#12 server identity. Clients validate the peer certificate chain and hostname/IP subject alternative name.
- Network enrollment uses a short-lived challenge and a PBKDF2-HMAC-SHA-256-derived verifier (310,000 iterations). The account password is not sent to the approving peer.
- An existing active network member must explicitly approve or reject a joining device. The founder admits the first additional device; once at least two members are active, any active member may admit independently. Inactive or revoked local members cannot issue approvals.
- Each admission produces a short-lived Ed25519-signed `AdmissionApproval` bound to the network, request UUID, candidate identity/endpoint, approver node ID and exact approver certificate SHA-256. Joining devices reject forged, altered, expired and replayed approvals.
- Desktop and Android peer-core nodes generate independent Ed25519 signing identities. Chained membership certificates bind each public key to a node and network. Chain validation rejects future-issued certificates, non-root self-issue, children predating their issuer, duplicate identities and chains outside the expected root.
- Signed member requests bind the HTTP method, raw path, timestamp, nonce and body digest. Receivers reject invalid signatures, stale timestamps and replayed nonces. Timestamp bounds are compared directly rather than using overflow-prone absolute subtraction; regression tests cover extreme signed integer timestamps on desktop and Android peer core.
- Presence is signed by the member key and binds the advertised endpoint to the member certificate. Desktop and Android peers verify it during catalogue synchronization. Legacy unsigned presence remains accepted only when it does not move the certificate-bound endpoint.
- JSON input is bounded to 16 MiB and 64 nesting levels. Per-source sliding windows rate-limit ordinary peer requests, enrollment challenges and enrollment submissions; authenticated filesystem operations also have a per-member window. Endpoints with userinfo, query/fragment data, oversized hosts, or wildcard, link-local and multicast address literals are rejected.
- Pending protection approvals, active transfer sessions, reserved transfer staging and durable coordinated-ticket claims are bounded. Reference snapshot retention evicts the oldest recovery points first.
- Owner-side audit records cover eligible-filesystem mutations and sensitive decisions such as admission approval/rejection, revocation, reference-grant changes and filesystem consent. Records contain identifiers, paths and digests rather than file contents or credentials.
- Each member has durable daily write-byte and delete-entry budgets (20 GiB and 10,000 entries by default, `0` for unlimited). Writes reserve declared bytes before streaming and settle immediately before publication; recursive deletes settle the entry count before deleting. Per-member overrides are owner-local, and exhaustion returns HTTP `429` with `Retry-After`.
- The audit log serializes appends and rotation with JVM and operating-system file locks, forces each append before returning, rejects symlinked or non-regular audit paths, skips malformed historical lines and reads newest-first across the current and one retained rotated file.
- Member catalogues carry signed membership certificates and signed `MembershipRevocation` records. Revocation is monotonic: stale catalogues cannot reactivate a revoked identity, and certificate chains that pass through a revoked member are rejected. Local revocation is enforced by authenticated peer operations after the updated catalogue is received.
- Broad filesystem consent is explicit. New devices default to no broad access and record owner consent during enrollment; existing devices must opt in during upgrade. Consent state is visible in membership status and revocation disables access immediately.
- The transitional pairing protocol uses high-entropy one-time invitations and token hashes; it remains for compatibility and is distinct from the approval-gated network membership model.
- The desktop local-control socket is Unix-domain and owner-only (`0600`) inside a private data directory. It is not exposed on the network listener.
- Properties-backed state mutations roll back their in-memory changes if the atomic persistence operation fails, preventing a running node from acting on state that was not committed to disk. Cross-process access is serialized by JVM and OS file locks, but this is not a general transactional database; directory-fsync durability remains provider-dependent.
- Referenced roots are canonicalized. Unsafe traversal, symbolic links and special files are rejected where the storage model requires regular files/directories.
- Managed uploads use bounded sizes, temporary staging, SHA-256 verification and no-overwrite commit. The current signed network path uses uploader-bound resumable sessions with independently hashed chunks, durable progress journals, idempotent chunk retries and a full-file digest check before publication. Downloads use unique temporary files and verify expected size and digest before finalizing. Final downloads use a same-directory move without `REPLACE_EXISTING` or `ATOMIC_MOVE`; the latter has provider-specific target-exists behavior and can violate no-overwrite expectations. Destination checks do not follow symlinks, and the final move arbitrates concurrent writers.
- Delete-capable reference grants create owner-local recovery snapshots before deletion where the backing provider supports it. Snapshot restore verifies integrity and refuses to overwrite an existing destination.
- The Linux virtual filesystem is read-only by construction; mutation callbacks return `EROFS` and the mount requests `ro,nodev,nosuid,noexec`.
- Android app state uses AndroidKeyStore-backed AES-GCM. Android SAF references preserve provider URI permissions rather than copying referenced file content.

## File encryption at rest

The product does not mandate application-level encryption of file contents at rest. Use host operating-system encryption (for example, LUKS, BitLocker, FileVault or Android platform encryption) when protection against powered-off device theft is required. This does not protect files from a compromised or already-unlocked operating system. Referenced files are not transformed or re-encrypted by PersonalCloud.

AndroidKeyStore-backed AES-GCM protects the Android application's stored state; it is not a claim that PersonalCloud encrypts all user file contents at rest.

## In transit and membership

Peer traffic uses authenticated TLS. Never disable certificate verification or use a trust-all client. Certificate SANs must match the peer URL host/IP. Direct-only networking is an explicit product decision; there is no relay or central file-content service.

Android network membership currently requires Android 13/API 33 or newer for the platform Ed25519 provider. Older supported Android API levels retain the transitional peer compatibility path; they do not receive the new signed network-membership capability.

## Local state and secrets

The desktop `data/` directory contains node identity, membership private keys/certificates, membership records, peer state, token-vault key, reference registrations, grants, audit logs, nonce/replay records and recovery snapshots. Keep it private and back it up securely. TLS private keys and keystore passwords must not be committed to source control or included in distributable archives.

## Explicit limitations

- The Android peer-core implements the signed membership and storage protocol and passes simulated desktop–Android interoperability tests. Android framework integration (foreground service, SAF, DocumentsProvider and proxy descriptors) is source-validated but still requires Android SDK/Gradle compilation and physical-device validation.
- The Java JNR-FUSE2 adapter compiled against its Maven dependency on Arch Linux on 2026-11-04. The adapter has not yet been mounted through the Linux kernel; read-only callback behavior is covered by source-level integration checks, not live kernel testing.
- No independent security audit has been performed. Local filesystem race resistance remains an ongoing hardening task. Receiver transfer sessions survive restart, but physical device power-loss behavior and the Android UI's transfer-ID persistence require real-device acceptance testing.
- Fault-injection coverage is limited to deterministic software faults: interrupted streams, digest mismatches, destination conflicts, a persistence failure after file publication, restart recovery and cancelled snapshots. Real disk-full, abrupt power loss, filesystem corruption and hardware failure behavior are not reproduced by the automated suite.
- Per-member TLS certificate pinning beyond the current signed presence/endpoint binding is not implemented. Filesystem mutations are audited and bounded by per-source request windows, per-member operation windows and durable daily write-byte/delete-entry budgets.
- Direct connectivity can fail behind CGNAT or restrictive firewalls. There is deliberately no relay fallback.
- Revocation prevents future authorized protocol operations after peers learn the updated membership catalogue; it cannot retract bytes already downloaded by a peer. A revoked member holding stale local state can still sign requests or approvals, but peers that know the revocation reject them and refuse chains passing through the revoked identity.
- Application-level end-to-end file encryption and key-recovery workflows are not part of the current scope.

## State-store cross-process consistency hardening — 2026-11-05

- `StateStore` now takes a per-state-file JVM lock and an operating-system file lock for every read and mutation. The latest persisted properties are reloaded while holding the lock, preventing stale process snapshots from overwriting changes made by another PersonalCloud JVM.
- State, backup and lock paths reject symbolic links. Temporary state and backup files use unique names, file contents are forced before replacement, and parent-directory fsync is attempted where the provider supports it.
- A four-process regression test performs concurrent key and record writes and verifies a pre-existing reader observes every committed value.
- This is serialized multi-process state access, not a general transactional database. Directory fsync is provider-dependent; power-loss durability and cross-process coordination with non-PersonalCloud tools are not guaranteed.
- The Android peer-core test runner now compiles production and test sources with `javac --release 17 -Xlint:all`, matching the module's declared Java 17 compatibility instead of accidentally inheriting the host JDK's newer API surface.

## Protocol and storage reliability hardening — 2026-11-10

- Bounded the JSON parser to 16 MiB of input and 64 nesting levels before recursive descent, preventing parser resource exhaustion through oversized or deeply nested documents.
- Added bounded per-source request windows at the peer HTTP boundary and a per-member filesystem-operation window. Default limits are 600 requests, 30 enrollment challenges, 12 enrollment submissions and 300 filesystem operations per minute, overridable with `PERSONALCLOUD_RATE_LIMIT_REQUESTS_PER_MINUTE`, `PERSONALCLOUD_RATE_LIMIT_CHALLENGES_PER_MINUTE`, `PERSONALCLOUD_RATE_LIMIT_ENROLLMENTS_PER_MINUTE` and `PERSONALCLOUD_RATE_LIMIT_FILESYSTEM_OPS_PER_MINUTE`.
- Presence now carries a member Ed25519 signature over the advertised endpoint and metadata. Catalogue synchronization verifies the signature against the expected member certificate. Unsigned legacy presence is accepted only when its endpoint equals both the connected endpoint and the certificate-bound endpoint, so it cannot move a member endpoint.
- Endpoint validation rejects credentials, query/fragment data, hosts longer than 253 characters, and wildcard, link-local or multicast IP literals while retaining loopback and private-LAN direct peers.
- Pending protection approvals are bounded per member (32) and per node (256), with terminal-entry purge. Active transfer sessions are bounded per node (16) and per member (4). Aggregate and per-member staging reservations default to twice the configured per-file limit and are independently configurable. Durable coordinated-ticket claims are pruned and capped.
- Reference version pruning now evicts the oldest snapshot per path and globally; count or byte pressure cannot delete a newer recovery point while retaining older ones.
- Eligible-filesystem writes, directory creation, moves, deletes, approval requests, member admission decisions, revocations, reference-grant changes and filesystem consent changes produce owner-side audit records. File contents, credentials and TLS material are not logged.
- Node startup failure now closes the protocol listener, catalogue scheduler, local control server and file service. A partially initialized protocol listener stops and releases its executor instead of leaking a bound port.
- Added `JsonLimitsTest`, `SecurityMonitorRequestLimitTest`, `ProtectionApprovalLimitTest`, `ReferenceVersionRetentionTest`, `StorageFaultInjectionTest`, `TransferQuotaTest`, and presence assertions in `NetworkMembershipServiceTest`.
- **Verification boundary:** these tests use deterministic software faults. Real disk-full, abrupt power loss, filesystem corruption and physical-device behavior remain production-readiness work.

## Member filesystem budgets and audit durability — 2026-11-10

- Added durable per-member daily budgets for written bytes and deleted entries. Defaults are 20 GiB and 10,000 entries per UTC day, configurable with `PERSONALCLOUD_MEMBER_DAILY_WRITE_BYTES` and `PERSONALCLOUD_MEMBER_DAILY_DELETE_ENTRIES`; `0` disables a dimension. Ledger records live in the same locked `StateStore` as other node state, so they survive restart.
- Write budgets reserve the declared size before an upload begins and settle immediately before publication. A denied approval, digest mismatch, destination conflict, size mismatch or interrupted stream releases the reservation. A publication failure after settlement conservatively consumes the budget rather than under-counting.
- Recursive deletes count the affected tree first and settle the delete-entry budget before removing anything. An over-budget bulk delete leaves every entry in place. Partial destructive failure remains conservatively charged. Coordinated source deletes and single-file deletes charge one entry.
- Per-member overrides are owner-local and use `filesystem.budget.limit` records. Usage is stored separately under `filesystem.budget.usage`, keyed by UTC day and a hashed member ID. Old usage beyond the two-day retention window is pruned.
- An exhausted budget returns HTTP `429` with a bounded `Retry-After` and accounting metadata, and records a `FILESYSTEM_BUDGET_EXCEEDED` audit event. Existing request-rate and protection-approval limits are unchanged.
- `AuditLog` now takes a per-log JVM lock and an operating-system file lock for both append and rotation. Each append is forced to disk before returning. Audit, rotated-audit and lock paths reject symbolic links and non-regular files. Reads tolerate malformed historical lines and return newest-first records from the current file plus one retained rotation. `audit [list] [limit]` exposes the bounded history over local control.
- Added `FilesystemBudgetTest` and `AuditLogConcurrencyTest`; `LocalControlClientTest` and `EligibleStorageIntegrationTest` cover control-command audit records and remote over-budget rejection. The aggregate suite passed after these changes.
- **Verification boundary:** these tests use deterministic software faults and concurrent in-process writers. They do not reproduce real disk-full, power-loss, filesystem-corruption or physical-device behavior. Per-member TLS certificate pinning and an independent security audit remain outstanding.
