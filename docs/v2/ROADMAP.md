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

## M3 — Linux native integration — source implementation in progress
- Java FUSE2 adapter source over the read-only virtual filesystem model.
- Fail-closed write/delete/rename/metadata mutation callbacks.
- Mount launcher with empty-mountpoint guard and restrictive mount options.
- KDE Dolphin actions for zero-copy directory reference registration, whole-file placement, and exact-file reference grants without copying.
- Automated shell/static tests for the boundary and service-menu installer.
- Remaining: compile against real JNR-FUSE dependency, install native FUSE2 runtime, exercise a real mount and kernel callbacks, and add richer native controls/progress after UX feedback.

## M4 — Android network and system integration — peer-core implemented; app integration partial
- Android peer-core implements account/password-proof enrollment, explicit approval, signed membership, catalogue sync, heartbeat and revocation.
- Simulated desktop–Android protocol tests cover enrollment, identity persistence, signed requests, catalogue synchronization, reference access and managed storage.
- Android foreground service source schedules member synchronization every 20 seconds after startup.
- DocumentsProvider source is wired to signed network membership and exposes app-owned storage, remote member references/managed files, and owner-local SAF references through seekable descriptors.
- SAF folder-tree and single-file references retain URI permissions and do not copy source content. Individual-file grants are download-only; folder deletion requires persistent write access and a verified recovery snapshot.
- Android operational controls expose network bootstrap, password-proof join, approval polling, selectable request approval/rejection, member listing/revocation and owner-local recovery snapshot listing/restore. These controls are functional, not a final visual redesign.
- Android now has a Keystore-encrypted persistent outbound queue, durable SAF source URI retention, restart retry, queue inspection, manual resume and abort.
- Implemented: Android foreground service observes default-network and link-property changes. When the active IPv4 address is already covered by the TLS certificate IP SAN, it persists and advertises the changed endpoint without changing the signed membership certificate. An uncovered address fails closed with an explicit renewal status.
- Remaining: Android SDK/Gradle compile and APK packaging; physical-device lifecycle, SAF provider, proxy descriptor, storage and network validation; reduce remaining manual identifier entry and improve transfer/recovery status presentation. Dynamic address recovery is still limited to the certificate's provisioned IPv4 SAN set; IPv6 listener support, DNS-SD/mDNS and cross-network NAT traversal remain separate work.
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

### M4 Android endpoint recovery increment — 2026-11-05

- Added a pure-Java Android peer endpoint resolver that compares active IPv4 address bytes against X.509 IP SAN values without DNS lookup and rejects loopback, link-local, multicast and uncovered addresses.
- Android's foreground service now watches the default network and link-property changes. It re-resolves the endpoint on a dedicated worker and persists the new mutable endpoint into the local membership catalogue.
- The mutable endpoint is separate from the immutable Ed25519 membership certificate. Endpoint movement does not rewrite root/issued certificate bytes or remote member records. Enrollment challenges advertise the current endpoint while the certificate continues to represent identity.
- Added tests for IPv4 SAN parsing, address matching, no-match fail-closed behavior, endpoint formatting, persisted local endpoint updates, certificate preservation, remote endpoint isolation and idempotency.
- Limitation: the callback can only advertise an IPv4 address already present in the server certificate SAN. The current Android listener remains IPv4-only; DNS-SD/mDNS, certificate identity independent of IP, IPv6 listener binding and NAT traversal remain outstanding.
