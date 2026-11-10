# PersonalCloud V2 roadmap

Development proceeds toward a coherent, direct-only private device network. Automated tests are run throughout implementation; manual device and platform acceptance is reserved for production readiness.

## M0 — Java node and local storage foundation — implemented
- Headless Java node lifecycle and peer protocol.
- Java local-control socket and CLI.
- Persistent node identity and state.
- Zero-copy reference registry, browse/search/stat/range-read and version snapshots.
- Pure-Java read-only filesystem boundary.
- Automated Java tests.

## M1 — Private network membership and catalogue — peer-core implemented
- Password-proved network bootstrap and challenge-based enrollment.
- Explicit approval/rejection by an existing active member.
- Per-device Ed25519 keys and chained signed membership certificates.
- Signed requests, replay protection and member revocation.
- Device catalogue, direct heartbeat and online/offline state.
- Android peer-core uses the same membership contract and passes simulated cross-node integration tests.
- Remaining: app lifecycle validation on Android, intermittent-network hardening and direct endpoint diagnostics.

## M2 — Remote reference filesystem and whole-file placement — desktop and Android peer-core implemented
- Member-scoped reference grants.
- Remote list/browse/stat/search/range-read/download/delete.
- Direct whole-file transfer to a selected destination node.
- Destination staging, digest verification and no-overwrite commit.
- Owner-side delete recovery snapshots; Android also has owner-local snapshot listing/restoration with bounded retention.
- Offline search metadata cache is explicitly marked stale/unavailable.
- Automated two-node integration tests exercise both directions between desktop and Android peer-core.

## M2.1 — Three-peer coordinated transfers — implemented
- Short-lived Ed25519-signed tickets issued by coordinator Z bind source/destination devices, eligible roots and paths, operation, source version, size, digest, expiry, request/transfer identity and optional owner approvals.
- X and Y verify tickets independently against the issuer's active membership key, enforce role/expiry checks and persist durable per-role claims. Same-transfer retries are idempotent; rebinding a ticket to another transfer is rejected.
- X streams resumable chunks directly to Y through the existing receiver session engine. Z exchanges metadata and status only and never receives, stages or relays file bytes.
- COPY and safe MOVE: destination authorization and staging, full integrity verification, destination commit, source revalidation, durable `DELETING` intent, then source deletion. Deletion failure reports `COPIED_NOT_MOVED`; retries reconcile without retransferring or losing the only copy.
- Source PRIVATE/PROTECTED policy and independent owner approvals are enforced at X; destination overwrite approvals are enforced at Y. Revoked source, destination or coordinator members are rejected.
- Desktop local control/CLI exposes `coordinated plan`, `prepare`, `transfer`, `status`, `retry` and `list`.
- Three-node automated tests cover direct X→Y isolation, coordinator metadata-only state, invalid/expired/tampered/replayed tickets, wrong source/destination/path/digest, source mutation, destination failure, interruption recovery, protected approvals and revocation.
- Remaining: Android coordinator/UI integration and live multi-device acceptance testing.

## M3 — Writable native integration — implemented and automatically tested
- Linux FUSE2 adapter over the shared read-write virtual filesystem model.
- Writable eligible storage at `/Devices/<device>/Filesystem/<root>/...`; reference and managed planes remain read-only.
- Create/write/read/mkdir/rename/delete/truncate with staged write-back, flush/fsync/release publication and no-overwrite commits.
- Writable Android DocumentsProvider create/write/rename/move/delete through signed owner-authorized calls.
- Fail-closed `chmod`/`chown`/`mknod`/link/xattr/`fallocate`; `utimens` is a documented no-op.
- Mount launcher with empty-mountpoint guard and restrictive mount options.
- KDE Dolphin actions for zero-copy directory reference registration, whole-file placement, and exact-file reference grants without copying.
- Automated shell/static tests for the FUSE boundary, plus two-node native-adapter and desktop–Android tests for round trips, concurrency, failed commits, traversal/symlink escapes, PRIVATE/PROTECTED and consent revocation.
- Remaining: exercise a real kernel mount and physical Android device; validate platform lifecycle/SAF behavior and add richer native controls/progress after UX feedback.

## M4 — Android network and system integration — peer-core implemented; app integration partial
- Android peer-core implements account/password-proof enrollment, explicit approval, signed membership, catalogue sync, heartbeat and revocation.
- Simulated desktop–Android protocol tests cover enrollment, identity persistence, signed requests, catalogue synchronization, reference access and managed storage.
- Android foreground service source schedules member synchronization every 20 seconds after startup.
- DocumentsProvider source is wired to signed network membership and exposes app-owned storage, remote member references/managed files, and owner-local SAF references through seekable descriptors.
- SAF folder-tree and single-file references retain URI permissions and do not copy source content. Individual-file grants are download-only; folder deletion requires persistent write access and a verified recovery snapshot.
- Android operational controls expose network bootstrap, password-proof join, approval polling, selectable request approval/rejection, member listing/revocation and owner-local recovery snapshot listing/restore. These controls are functional, not a final visual redesign.
- Android now has a Keystore-encrypted persistent outbound queue, durable SAF source URI retention, restart retry, queue inspection, manual resume and abort.
- Implemented: Android foreground service observes default-network and link-property changes. When the active IPv4 address is already covered by the TLS certificate IP SAN, it persists and advertises the changed endpoint without changing the signed membership certificate. An uncovered address fails closed with an explicit renewal status.
- Remaining: Android SDK/Gradle compile and APK packaging; physical-device lifecycle, SAF provider, proxy descriptor, storage and network validation; reduce remaining manual identifier entry and improve transfer/recovery status presentation. Android UI integration for three-peer coordinated transfers remains outstanding. Dynamic address recovery is still limited to the certificate's provisioned IPv4 SAN set; IPv6 listener support, DNS-SD/mDNS and cross-network NAT traversal remain separate work.
- Final UI redesign remains dependent on product-owner UX feedback.

## M5 — Operational hardening and production readiness — in progress
- Hardened download finalization across desktop and Android: unique staging, digest/size validation, symlink-aware destination checks and no-replace final moves. Added regression coverage for concurrent Android downloads racing on one destination.
- Android peer-core production sources are checked against Java 17 API compatibility in the automated suite.
- Properties-backed state mutations restore the previous in-memory state when persistence fails; a failure-injection test covers key and record updates/removals.
- Durable resumable direct transfer sessions: 4 MiB independently hashed chunks, persisted progress, idempotent chunk retries, uploader-bound status/abort, seven-day expiry, bounded staging reservations, restart recovery and idempotent final commit. Automated tests cover receiver restart, missing chunks, duplicate chunks, wrong uploader, corrupt chunks, zero-byte files, abort, and desktop↔Android multi-chunk interoperability.
- Membership/catalogue consistency under intermittent connectivity. Bounded-concurrency sync (four peers at a time), non-blocking Android membership I/O, 90-second heartbeat leases, and stale-catalogue merge protection are implemented; longer-duration and larger-network churn tests remain.
- Load, concurrency and long-duration tests.
- Security review and local filesystem race hardening.
- **Implemented:** read-only desktop endpoint diagnostics enumerate IPv4/IPv6 interface addresses, validate the local PKCS#12 TLS identity, and perform bounded STUN mapping checks from the listener's UDP port. Reports explicitly leave inbound TCP/TLS reachability unverified.
- **Remaining:** test the exact HTTPS endpoint from a second device and independent network; verify public IPv6 and router/CGNAT behavior. No automatic ICE traversal or relay fallback is planned.
- Production packaging, recovery and manual acceptance testing on actual devices and real Linux/Android platforms.

## Deferred by explicit product choice

No block striping, automatic replication, automatic synchronization, conflict resolution, relay fallback or mandatory application-level at-rest file encryption in the initial product. Control UI changes remain deferred until product-owner UX feedback is collected.

### M5 reliability update — 2026-11-05

- **Implemented:** StateStore cross-process serialization using JVM and OS file locks; refresh-before-read/write; state/backup/lock symlink rejection; unique temporary files; file fsync and best-effort parent-directory fsync.
- **Verified:** Four independent JVM writers concurrently persisted 160 keys and 160 records; a long-lived reader observed every committed value. Existing persistence-failure rollback tests still pass.
- **Implemented:** Sender-persisted transfer UUIDs and durable outbound queues on desktop and Android; restart-safe retries, exponential backoff, source digest revalidation, durable abort and receiver receipt reconciliation. Both receiver implementations retain seven-day metadata-only commit receipts to make commit/create replay idempotent.
- **Still required:** broader filesystem TOCTOU hardening; disk-full and abrupt-crash fault injection; membership/catalogue churn and long-duration tests.
- **Verification improvement:** Android peer-core test compilation now enforces Java 17 API compatibility with `--release 17 -Xlint:all`; the desktop interoperability harness compiles separately against Java 21.

### M5 membership reliability update — 2026-11-05

- Desktop catalogue work runs across a bounded four-peer worker pool; one offline peer no longer serially delays every healthy member.
- Android peer-core uses bounded parallel catalogue work and releases the membership monitor before any network I/O, preventing slow outbound peers from blocking inbound membership authentication or local state reads.
- Presence is a 90-second lease based on a verified heartbeat. Stale persisted `online` booleans expire after restart and are not forwarded as current presence.
- Android catalogue merging retains a newer locally observed heartbeat when importing an older peer catalogue and rejects timestamps outside the permitted future clock skew.
- Automated Android tests block two peer requests simultaneously and verify local status/authentication remains responsive; desktop and Android liveness tests pass.

### M5 direct-connectivity diagnostic increment — 2026-11-05

- Added `personalcloudctl network diagnostics`, which does not require the node daemon to be running.
- Enumerates local IPv4/IPv6 addresses with interface state and classifies private, carrier-grade NAT, link-local, unique-local and global-candidate scopes.
- Validates the configured PKCS#12 server key identity without printing its path or password.
- Performs bounded STUN Binding requests against configurable endpoints, binds the UDP probe to the configured listener port, validates transaction IDs/cookies/attribute lengths, and decodes IPv4/IPv6 XOR-MAPPED-ADDRESS.
- Compares mappings from independent STUN endpoints and reports endpoint-dependent mapping as uncertainty rather than claiming a specific NAT type.
- No router/firewall mutation, port-forwarding automation, automatic ICE traversal or relay fallback is introduced. Inbound TCP/TLS reachability remains explicitly unverified until checked from another network.

### M5 delegated-admission and revocation increment — 2026-11-09

- Added signed, short-lived `AdmissionApproval` records bound to the network, enrollment request UUID, candidate node identity/name/public key/endpoint, approver node ID and exact approver certificate SHA-256.
- Admission authority is enforced locally: the root may always admit, and once at least two members are active any active member may admit independently. Inactive or revoked local members are refused.
- Joining devices verify the approval signature, binding, lifetime and one-time use, and reject forged, altered, expired or replayed approvals.
- Hardened certificate-chain validation: future-issued certificates, non-root self-issue, child certificates predating their issuer, duplicate device identities, and chains outside the expected network root are rejected.
- Added signed monotonic `MembershipRevocation` records. Peers reject invalid or unauthorized revocation records, never reactivate a revoked identity from a stale catalogue, and refuse certificate chains that pass through a revoked member.
- Broad filesystem consent is now explicit in enrollment (`network join --consent`, Android enrollment option) and existing-device upgrade; new devices default to no broad access.
- Added `DelegatedAdmissionIntegrationTest` covering admission thresholds, independent approval, attribution, forged/altered/expired/replayed approvals, invalid chains, revocation propagation, stale conflicts, inactive/revoked approvers and consent.
- Extended desktop–Android interoperability coverage: Android-issued approvals are accepted by the desktop core, Android-originated signed revocations are enforced, and consent defaults are checked end to end.
- Remaining M5 work outside this increment: broader filesystem TOCTOU hardening, disk-full/abrupt-crash fault injection, and long-duration larger-network churn tests.

### M4 Android endpoint recovery increment — 2026-11-05

- Added a pure-Java Android peer endpoint resolver that compares active IPv4 address bytes against X.509 IP SAN values without DNS lookup and rejects loopback, link-local, multicast and uncovered addresses.
- Android's foreground service now watches the default network and link-property changes. It re-resolves the endpoint on a dedicated worker and persists the new mutable endpoint into the local membership catalogue.
- The mutable endpoint is separate from the immutable Ed25519 membership certificate. Endpoint movement does not rewrite root/issued certificate bytes or remote member records. Enrollment challenges advertise the current endpoint while the certificate continues to represent identity.
- Added tests for IPv4 SAN parsing, address matching, no-match fail-closed behavior, endpoint formatting, persisted local endpoint updates, certificate preservation, remote endpoint isolation and idempotency.
- Limitation: the callback can only advertise an IPv4 address already present in the server certificate SAN. The current Android listener remains IPv4-only; DNS-SD/mDNS, certificate identity independent of IP, IPv6 listener binding and NAT traversal remain outstanding.

## M6 — Protocol and storage reliability hardening — completed 2026-11-10

- **Parser bounds:** JSON input is capped at 16 MiB and 64 nesting levels; oversized or deeply nested documents are rejected before recursive parsing.
- **Request throttling:** each source address has a bounded sliding window for all peer requests plus narrower windows for enrollment challenges and enrollment submissions. Authenticated filesystem operations also have a per-member window. Defaults are 600 requests, 30 challenges, 12 enrollment submissions and 300 filesystem operations per minute, configurable with `PERSONALCLOUD_RATE_LIMIT_REQUESTS_PER_MINUTE`, `PERSONALCLOUD_RATE_LIMIT_CHALLENGES_PER_MINUTE`, `PERSONALCLOUD_RATE_LIMIT_ENROLLMENTS_PER_MINUTE` and `PERSONALCLOUD_RATE_LIMIT_FILESYSTEM_OPS_PER_MINUTE`.
- **Endpoint identity:** presence is signed by the member key and binds the advertised endpoint. Desktop and Android peers verify the signature against the member certificate; legacy unsigned presence is accepted only when it keeps the certificate-bound endpoint unchanged. Endpoint validation rejects userinfo, query/fragment data, oversized hosts, wildcard, link-local and multicast address literals.
- **Approval bounds:** pending protection approvals are capped per member (default 32, `PERSONALCLOUD_MAX_PENDING_APPROVALS_PER_MEMBER`) and per node (default 256, `PERSONALCLOUD_MAX_PENDING_APPROVALS`); terminal entries are purged after retention.
- **Transfer bounds:** active transfer sessions are capped per node (default 16, `PERSONALCLOUD_MAX_TRANSFER_SESSIONS`) and per member (default 4, `PERSONALCLOUD_MAX_TRANSFER_SESSIONS_PER_MEMBER`). Aggregate and per-member staging reservations default to twice the configured per-file limit and can be overridden with `PERSONALCLOUD_MAX_TRANSFER_STAGING_BYTES` and `PERSONALCLOUD_MAX_TRANSFER_STAGING_BYTES_PER_MEMBER`. Durable coordinated-ticket claims are pruned after expiry and capped at 5000.
- **Snapshot retention:** reference snapshot pruning walks oldest-first per path and globally, so global count/byte pressure cannot delete a newer recovery point while retaining older ones.
- **Audit:** owner-side audit records cover eligible-filesystem writes, directories, moves, deletes, approval requests, admission approve/reject, revocation, reference-grant create/revoke and filesystem consent changes. Records contain identifiers, paths and digests, not file contents or credentials.
- **Lifecycle:** a failed node startup closes the protocol, catalogue, control and file components; protocol close is idempotent and a partially started listener cannot keep a bound port or worker pool.
- **Fault injection:** added controlled tests for JSON/parser bounds, per-source request windows, approval caps, per-member transfer quotas, signed/tampered presence, interrupted managed writes, digest mismatch, destination conflict, persistence failure after publication, restart recovery, staged-file cleanup, and cancelled reference snapshots. These are deterministic software faults, not real disk-full or power-loss testing.
- **Remaining after M6:** per-member TLS certificate pinning beyond signed endpoint binding, real disk-full/power-loss/filesystem-corruption testing, physical-device acceptance and an independent security audit. Tiered per-member filesystem budgets were completed in M7. Root succession/rotation remains deferred.

## M7 — Member filesystem budgets and audit durability — completed 2026-11-10

- **Per-member budgets:** each network member has independent durable daily write-byte and delete-entry budgets. Defaults are 20 GiB written and 10,000 deleted entries per UTC day, overridable with `PERSONALCLOUD_MEMBER_DAILY_WRITE_BYTES` and `PERSONALCLOUD_MEMBER_DAILY_DELETE_ENTRIES`; `0` disables a dimension. The ledger is stored in `StateStore` and survives process restart.
- **Write accounting:** eligible-storage writes reserve their declared byte size before the stream begins and settle the reservation immediately before publication. Failed verification, denied approvals, destination conflicts and interrupted streams release the reservation; publication failure after settlement conservatively consumes the budget.
- **Delete accounting:** recursive deletes count the tree first and settle the delete-entry budget before touching any entry. A rejected bulk delete leaves the tree intact. Coordinated source deletes and single-file deletes reserve and settle one entry. Partial destructive failure remains conservatively charged.
- **Per-member overrides:** the owner can inspect and adjust budgets with `filesystem budgets`, `filesystem budget <member-id>`, `filesystem budget-set <member-id> <write-bytes-per-day> <delete-entries-per-day>` and `filesystem budget-clear <member-id>` over the local-control socket.
- **Protocol response:** an exhausted budget is rejected with HTTP `429`, a bounded `Retry-After`, accounting metadata and an owner-side `FILESYSTEM_BUDGET_EXCEEDED` audit record. Rate-limit and protection-approval paths are unchanged.
- **Audit durability:** `AuditLog` serializes appends and rotation with a JVM lock and an operating-system file lock, forces each append before returning, rotates under the lock, rejects symlinked or non-regular log/lock paths, tolerates malformed historical lines and reads newest-first across the current and one retained rotated file. `audit [list] [limit]` exposes recent records over local control.
- **Verification:** `FilesystemBudgetTest` covers limit enforcement, per-member isolation, restart persistence, override and clear behavior, failed-write release, recursive-delete preflight and UTC-day rollover. `AuditLogConcurrencyTest` covers concurrent instances, rotation, malformed lines and symlink rejection. `LocalControlClientTest` and `EligibleStorageIntegrationTest` cover control commands, audit records and remote over-budget rejection.
- **Remaining:** per-member TLS certificate pinning, real disk-full/power-loss/filesystem-corruption testing, physical-device acceptance and an independent security audit. Root succession/rotation remains deferred.
