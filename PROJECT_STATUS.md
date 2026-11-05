# PersonalCloud project status

Last updated: 2026-11-05

## Product direction

PersonalCloud is a Java-only private network of personally operated devices. Every device is an independent node and retains ownership of its local files and physical storage. Access is granted explicitly between members. Peer traffic is direct and authenticated. There is no browser dashboard, central file-content service, relay, automatic replication, or mandatory application-level encryption of file contents at rest.

## Implemented and automated-tested in the current source

### Desktop node and local storage
- Headless Java 21+ node lifecycle and HTTPS peer endpoint.
- Persistent node ID, protected device signing identity, peer state, audit data and recovery snapshots.
- Owner-only Unix-domain local-control socket and Java CLI.
- Zero-copy registration of existing reference directories; registration does not move, copy, transform or re-encrypt referenced contents.
- Reference browsing, metadata, bounded search and random-access reads.
- Filesystem change detection and bounded, integrity-verified version snapshots.
- Read-only OS-neutral virtual namespace: `Devices/<device>/References` and `Devices/<device>/Distributed-Storage`.
- Tested pure-Java filesystem adapter boundary with path normalization/traversal rejection, metadata, cached-offline availability checks and bounded range reads.

### Private network membership and catalogue
- Desktop and Android peer-core support password-proved, challenge-based enrollment requests.
- New devices remain pending until explicitly approved or rejected by an existing active member.
- Per-device Ed25519 identities and chained signed membership certificates; device private keys are never shared.
- Signed member requests bind method, path, timestamp, nonce and body digest; replay and stale requests are rejected.
- Timestamp validation uses overflow-safe lower/upper-bound comparisons on desktop and Android peer core; regression tests reject correctly signed requests carrying extreme `Long.MIN_VALUE` timestamps.
- Member revocation and signed catalogue exchange.
- Direct heartbeat synchronization and online/offline status updates. The Android foreground service source schedules sync after startup and every 20 seconds for enrolled nodes.
- Endpoint identity is checked against the expected member record during synchronization.

### Download commit safety hardening — 2026-11-04
- Audited finalization paths for remote downloads. Java `ATOMIC_MOVE` may have provider-specific behavior when a destination already exists, so download paths now use same-directory moves without `REPLACE_EXISTING` or `ATOMIC_MOVE` to preserve the no-overwrite contract.
- Applied the rule to desktop peer-share downloads, desktop signed-network reference/managed downloads, desktop local-control downloads, and Android peer downloads.
- Destination checks now use `NOFOLLOW_LINKS` so dangling or ordinary destination symlinks are treated as existing paths rather than silently followed.
- Android peer downloads now use unique `Files.createTempFile` staging names, validate the SHA-256 header format, use overflow-checked byte accounting, and clean staging files on all failed paths.
- Added Android peer regression tests for pre-existing destinations, symlink destinations, two concurrent downloads racing for one destination, checksum mismatch cleanup and complete-file integrity. Exactly one concurrent download may commit.
- Android peer-core production sources are now compiled by the automated suite with `javac --release 17`, matching the module's declared Java compatibility instead of inheriting the host JDK 21 API surface.

### Persistent-state failure consistency hardening — 2026-11-04
- `StateStore` previously mutated its in-memory `Properties` before saving. If disk persistence failed, the running process could continue observing a change that had not been committed to disk.
- Added mutation rollback for key updates/removals and record updates/removals. A failed save restores the prior in-memory state before propagating the persistence error.
- Added deterministic failure-injection coverage by replacing the state directory with a regular file during writes; verifies key and record operations all roll back in memory and the original persisted state remains unchanged after reopening.
- Added the regression test to the standard desktop foundation suite.

### Upload commit and transfer accounting hardening — 2026-11-04
- Audited the ordinary peer upload path in `FileService.upload`. It previously created a placeholder destination and then replaced it with `REPLACE_EXISTING`; this introduced a replaceable-name window and weakened the no-overwrite contract.
- Changed uploads to write into a unique private staging file and publish with one same-directory move without `REPLACE_EXISTING` or `ATOMIC_MOVE`. The destination is never pre-created or replaced; a competing writer wins or loses at the final no-replace move.
- Added regression coverage for complete upload bytes, existing-destination preservation, injected source-stream failure, concurrent writers racing for the same name, and staging-file cleanup.
- Added overflow-checked byte accounting with `Math.addExact` to desktop snapshot creation and signed-network download paths. Android and peer-share download paths already used overflow-checked accounting.
- Full `./scripts/test-all.sh` passed after these changes, including the new upload race/failure regression.

### Remote references and managed files
- Explicit member-scoped `DOWNLOAD` / `DOWNLOAD+DELETE` reference grants.
- Remote shared-root listing, directory browsing, stat, metadata search, bounded random-access reads and checksum-verified download.
- Owner-side recovery snapshot before authorized reference deletion.
- Whole-file placement to a manually selected member's managed-storage root over a direct authenticated connection.
- Destination-side staging, size/SHA-256 verification, no-overwrite commit, member-visible listing/stat/download and authorized deletion.
- Android storage supports owner-local, integrity-verified recovery snapshot enumeration and restore. Snapshot access is not exposed to network members; retention is bounded to 20 snapshots per path and 200 total, capped at 10 GiB.
- Cached search results for offline members are labelled stale and unavailable; cached metadata is not treated as live content.

### Linux integration (adapter compiled on Arch; live mount pending)
- Java JNR-FUSE2 adapter for the read-only `/Devices/...` virtual namespace; compiled on the user's Arch Linux machine against JNR-FUSE 0.5.8 with FUSE2 headers (2026-11-04).
- Explicit rejection of write, delete, rename and metadata-mutation operations.
- Empty-mountpoint guard and restrictive read-only/nodev/nosuid/noexec mount options.
- Maven build uses an isolated project-local repository for the core JAR, verifies shaded artifact contents and runs a non-mounting executable smoke test. User-machine build and smoke test passed (2026-11-04); live kernel mount and callback exercise remain unverified.
- Java mount launcher and optional Maven build module.
- KDE Dolphin actions to register a selected directory in place, send a whole file to a selected online member, and grant access to one exact file by reference without copying it.
- Selected-file resolution finds its existing registered root and rejects symlinks, aliases and unregistered files.
- Automated shell tests cover launcher syntax, read-only callback coverage, mount safety, Dolphin argument quoting, symlink rejection and service-menu installation.
- The pure-Java filesystem boundary is compiled and exercised by the core suite. On Arch Linux, the JNR-FUSE adapter compiled successfully against JNR-FUSE 0.5.8 with Maven after installing FUSE2 development headers (2026-11-04). The adapter has not yet been mounted through the kernel or exercised through live FUSE callbacks.

### Membership liveness and synchronization hardening — 2026-11-05
- Desktop catalogue passes now synchronize independent members on a bounded four-worker pool instead of serially waiting on each peer.
- Android catalogue synchronization uses the same bounded four-peer concurrency. It no longer holds the membership monitor while performing outbound HTTPS requests, so inbound signed authentication, local status reads and membership actions are not blocked by a slow peer.
- Online state is treated as a 90-second heartbeat lease. Persisted `online=true` flags expire after process downtime or a network partition; expired status is not advertised in member catalogues.
- Android catalogue imports preserve newer locally observed heartbeat state rather than rolling it back from an older peer snapshot; implausibly future heartbeat timestamps are rejected.
- Added deterministic Android multi-peer blocking-transport tests proving parallel progress and monitor availability, plus desktop/Android stale-presence regression coverage.

### Android integration (peer-core tested; app framework build pending)
- Android peer-core now implements the same password-proof enrollment, explicit approval, Ed25519 membership certificates, signed active-member requests, replay protection, member catalogue and revocation model as desktop.
- Simulated desktop–Android integration exercises both directions: Android joins a desktop-created network, receives approval, verifies certificates, signs heartbeats, synchronizes member/catalogue status, reads and shares references, performs ranged reads, places managed files and exercises deletion permissions.
- The legacy invitation/token protocol remains for compatibility with older peers; it is not the new network membership model.
- Android peer storage provides separate referenced and managed roots. Managed receive uses staging, digest verification and no-overwrite move. Reference deletion verifies that the source did not change during snapshot creation, keeps an owner-local snapshot, and retires a deleted single-file grant.
- Owner-local Android recovery snapshots can be listed and restored after SHA-256 verification. Restore never overwrites an existing file; retention is bounded.
- Android `DocumentsProvider` source is registered and uses signed network membership to expose local app-owned storage, owner-local SAF references, and remote members' `References` and `Distributed-Storage`. Remote files use seekable proxy descriptors and authenticated byte-range reads; local SAF references use seekable descriptors without copying the original content. Cached offline metadata is visibly unavailable.
- `AndroidSafReferenceStore` supports both selected folder trees and selected individual documents without importing their bytes. Folder deletion is available only with persistent SAF write permission and a verified owner-side recovery snapshot. Individual-file references are read-only (`DOWNLOAD`) because a safe restore target cannot be guaranteed without parent-folder permission.
- Persistable Android URI permissions are retained while any active grant or deletion snapshot requires them. Failed reference creation releases a newly acquired permission only when no other grant or recovery snapshot depends on it. Snapshot retention is bounded and grouped by source tree plus relative path.
- Android foreground service source starts catalogue/heartbeat synchronization after listener startup and repeats it every 20 seconds for enrolled nodes.
- Android app source now exposes operational network bootstrap, password-proof join, enrollment approval polling, selectable pending-request approval/rejection, member listing/revocation, and owner-local recovery snapshot listing/restore. These are functional controls, not a final UI redesign.
- Static checks validate manifest registration, foreground-service lifecycle/sync wiring, membership controls, SAF folder/single-file references, permission rollback/retention and the DocumentsProvider access contract. The Android framework/provider module has not been compiled with Android SDK/Gradle in this environment and has not been exercised on a physical device.

## Current build and automated test result

Run the complete automated suite from the repository root:

```bash
./scripts/test-all.sh
```

This builds the desktop Java node; runs desktop storage, control, membership, network-protocol, remote-reference, managed-storage and remote byte-range integrity tests; runs Android peer-core and simulated desktop–Android interoperability tests; statically validates Android app integration; and performs Linux integration shell/static checks. It does not require a physical Android device, KDE session, Android SDK or native FUSE mount.

## Remaining implementation scope

- Compile/package the Android APK with a real Android SDK/Gradle toolchain, resolve platform compatibility warnings, then validate the foreground service, certificate lifecycle and DocumentsProvider on a physical device during production readiness.
- Validate the JNR-FUSE shaded artifact launch smoke test, then exercise real mount/unmount and kernel callbacks on Linux; verify Dolphin integration in a live KDE session.
- Refine the provisional Android operational controls into the final minimal native experience after product-owner UX feedback; reduce remaining manual identifier entry and improve transfer/recovery status presentation.
- Physical Android APK/SAF/lifecycle validation and live Linux FUSE mount validation.
- Transfer UX must persist and present the transfer ID/progress across app restarts; the receiver protocol and peer-core resume APIs are implemented, but end-user UI recovery needs device validation.
- Read-only desktop direct-connectivity diagnostics now enumerate interfaces, validate local TLS material and compare bounded STUN UDP mappings. Global interface candidates are reported independently from the configured bind address, with a separate bound-family match field. A desktop TLS provisioning script now creates an encrypted local CA key and a SAN-correct PKCS#12 server identity for active non-temporary interface addresses without opening the listener or changing firewall settings. Actual inbound HTTPS reachability from another network, CGNAT behavior and public IPv6 acceptance still require independent devices/networks.
- Load/concurrency tests at large file sizes, long-duration stability, performance profiling, independent security audit and real-device acceptance tests. There is deliberately no relay fallback.

## Validation boundary

Automated tests validate Java services, protocol contracts, security checks, simulated multi-node interoperability, and Linux/Android source integration contracts. Physical-device networking, Android lifecycle/SAF behavior, real FUSE mounting, KDE Dolphin behavior, filesystem permissions and deployment recovery belong to the later production-readiness phase. They are not represented as passed merely because automated tests pass.

## Data-preservation boundary

Do not delete `data/`, the configured managed-storage directory, TLS identities, or Android app data during upgrades. The installer must preserve node identity, membership keys/certificates, grants, reference metadata, peer state, token vault, audit history and recovery snapshots. Existing external managed storage must remain outside source replacement operations.

## 2026-11-05 — StateStore multi-process consistency

- Added exclusive OS file locking plus a JVM-local lock for all StateStore reads and mutations.
- Each operation refreshes the persisted state while holding the lock, preventing independent PersonalCloud processes from overwriting stale in-memory snapshots.
- Added symlink rejection for state, backup, lock and state-directory paths.
- State and backup writes use unique staging files, force file contents before replacement, and attempt parent-directory fsync where supported.
- Added `StateStoreMultiProcessTest`: four independent JVM writers concurrently persist 160 keys and 160 records; an already-open reader verifies every value.
- Focused desktop suite passed after the change. Android peer-core, desktop–Android interoperability, Android source-contract and Linux integration checks also reached their PASS assertions in the aggregate run; the aggregate runner exceeded its 600-second timeout after printing the final PASS line, so its process exit was not independently confirmed. Individual component runs are recorded separately in the engineering log.
- Tightened the Android peer-core verification runner to compile production and tests with `--release 17 -Xlint:all`; the desktop/Android interop test is compiled against Java 21 desktop classes. The full Android peer protocol and real desktop interoperability test command passed after this change.


## 2026-11-05 — Direct resumable transfer engine

- Implemented authenticated transfer-session create/status/chunk/commit/abort endpoints on desktop and Android peers.
- New desktop and Android managed-file clients now use direct 4 MiB chunks, per-chunk SHA-256, full-file SHA-256, persisted receiver journals and missing-chunk resume.
- Transfer sessions are uploader-bound, expire after seven days, and have bounded count/aggregate staging reservations.
- Final commit is idempotent by transfer ID, so a receiver restart after file publication but before journal cleanup does not create a duplicate.
- Commit hashes the chunk sequence and streams it directly into managed storage without a second full-size assembly file.
- Automated desktop, Android peer and cross-platform tests pass, including 9 MiB multi-chunk transfers in both directions and receiver-side restart recovery.

## Durable outbound transfer lifecycle (2026-11-05)

- Desktop and Android peer-core now persist sender-side transfer jobs before any receiver session request, with stable transfer IDs, exponential backoff, source mutation checks, restart recovery, explicit resume/abort, and receipt reconciliation.
- Android foreground service now owns a Keystore-encrypted SAF-backed outbound queue, retries after service restart, and retains persistable source read permission while a job is nonterminal.
- Both receiver implementations retain metadata-only commit receipts for seven days so sender replay is idempotent after a lost commit response.
- Android UI now exposes transfer queue listing, manual resume, and abort. The actual APK/device lifecycle still requires Android SDK and physical-device verification.


## 2026-11-05 — Direct connectivity diagnostics

- Added a daemon-independent `personalcloudctl network diagnostics` command for local interface, bind, TLS and STUN mapping inspection.
- STUN uses a UDP socket bound to the same numeric port as the peer listener, reports UDP mapping separately, bounds each request, validates transaction IDs and decodes IPv4/IPv6 XOR-MAPPED-ADDRESS.
- Multi-endpoint mapping differences are surfaced as uncertain endpoint-dependent behavior; diagnostics do not claim a definitive NAT classification.
- Explicitly reports that inbound TCP/TLS reachability is unverified. No port-forwarding, firewall changes, automatic ICE traversal or relay fallback are performed.
- Deterministic tests use local mock STUN servers; no third-party STUN service or public network is required for the automated suite.
- Added desktop peer TLS provisioning with encrypted CA private key, IP SANs for active IPv4/IPv6 interfaces, PKCS#12 verification, no-overwrite behavior and invalid-input cleanup tests.

### Desktop TLS routing (2026-11-05)

- Desktop server identity and Android peer truststore now resolve from separate default directories.
- Legacy `PERSONALCLOUD_TLS_DIR` and explicit per-file/per-role overrides remain supported.
- Startup prompts independently for the desktop identity and Android truststore passwords.
- Invalid non-literal bind addresses fail closed.
- Android's existing trusted-peer-CA import action is the path for importing the public desktop CA.
- This is reciprocal HTTPS server trust plus signed application membership, not TLS client-certificate mTLS.


## Android network endpoint recovery — 2026-11-05

- Implemented default-network monitoring in the Android foreground service. Link-property changes trigger endpoint reevaluation on a dedicated worker.
- Active IPv4 addresses are matched by raw address bytes against certificate IP SANs; DNS resolution is not used. Uncovered addresses are rejected rather than advertised.
- The Android membership client persists the current local endpoint and updates its own catalogue row. The signed membership certificate and other members' records are preserved.
- Tests cover endpoint selection, SAN parsing, persisted endpoint movement, idempotency, certificate preservation and remote-member isolation.
- Android app SDK compilation and physical network-transition validation remain outstanding. Address movement is limited to IPv4 addresses already present in the server certificate SAN; IPv6 listener support, mDNS and NAT traversal are not included.
