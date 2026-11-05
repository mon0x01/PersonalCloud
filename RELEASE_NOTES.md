# Release notes

## PersonalCloud V2 scope-driven engineering increment — 2026-11-04

### Private network and desktop distributed storage
- Added password-proved network bootstrap and challenge-based enrollment.
- Added explicit member approval/rejection, per-device Ed25519 identities, chained membership certificates, signed requests, replay protection and member revocation.
- Added direct heartbeat and signed membership-catalogue exchange with online/offline status.
- Added member-scoped reference grants, remote browse/stat/search, authenticated range reads with per-range SHA-256 validation, full-download integrity verification and owner-side recovery snapshots before authorized deletion.
- Added direct whole-file managed-storage placement with receiver-side staging, checksum verification, no-overwrite commit, and remote listing/download/delete.
- Added persisted offline search metadata explicitly marked stale/unavailable.

### Linux native integration
- Added a pure-Java read-only filesystem facade with normalization, traversal rejection, stale/offline checks and bounded range reads.
- Added optional JNR-FUSE2 adapter source and a guarded read-only mount launcher.
- Added KDE Dolphin actions for zero-copy directory reference registration, whole-file placement to an online member, and exact-file reference grants without copying file contents.
- Added server-side selected-file resolution to an existing registered directory; unregistered paths and symbolic-link aliases are rejected before a grant can be created.
- Added automated Linux shell/static integration checks.
- The JNR-FUSE dependency/native mount is not built or mounted in this build environment; that remains a platform acceptance step.

### Android integration
- Ported password-proof enrollment, explicit approval, per-device Ed25519 identities, signed member requests, replay protection, catalogue synchronization and revocation to the Android peer core.
- Added signed-member reference and managed-storage operations with desktop interoperability in both directions.
- Added Android foreground-service catalogue/heartbeat scheduling and signed-network DocumentsProvider source for remote references and managed files.
- Added owner-local Android recovery snapshot listing/restoration, SHA-256 verification, no-overwrite recovery and bounded retention.
- Strengthened managed-file commit to use no-replace move semantics and added a race test for a destination appearing during transfer.
- Added static Android app/manifest integration checks to the full suite.
- Android SDK/Gradle is unavailable in this build environment, so the framework/provider source is statically checked but not APK-compiled or device-validated.

### Validation and boundaries
- `./scripts/test-all.sh` builds the Java desktop node and runs desktop, network, storage, Android peer-core, simulated interop, Android app static integration and Linux integration tests.
- No physical Android, KDE, or FUSE mount testing is claimed in this increment.
- Browser dashboard remains excluded. UI redesign remains deferred pending product-owner UX feedback.
- Application code remains Java-only; no Python application/integration code is introduced.

### Audit hardening increment — 2026-11-04
- Fixed desktop remote random-access reads to require an exact Content-Range, exact body length and a matching per-range SHA-256 digest before returning bytes.
- Added focused integrity tests for valid ranges, digest tampering, malformed range metadata, truncated payloads and out-of-bounds ranges.
- Fixed signed-request timestamp validation on desktop and Android peer core: direct bound comparisons prevent integer overflow from accepting an extreme timestamp. Added regression tests that sign requests using `Long.MIN_VALUE` and verify rejection.
- Reconciled architecture, security and networking documentation with the current signed-membership, Android SAF and Linux integration source.
- Added a Linux CI workflow to compile the optional JNR-FUSE adapter against Maven and FUSE2 dependencies; this workflow has not yet run in the current local environment.

### Download finalization and compatibility hardening — 2026-11-04
- Removed `ATOMIC_MOVE` from download finalization paths where its provider-specific existing-target behavior could violate the no-overwrite contract. Applied to desktop peer, signed-network, local-control and Android peer downloads.
- Destination checks now reject existing paths without following symlinks; same-directory no-replace moves arbitrate concurrent destination races.
- Android downloads now use unique temporary files, strict SHA-256 header validation, overflow-checked byte counting and failed-transfer staging cleanup.
- Added regression coverage for existing targets, symlink targets, concurrent same-destination downloads, checksum mismatch cleanup and verified final content.
- Automated Android peer-core compilation now targets Java 17 with `--release 17`.

### Persistent-state consistency hardening — 2026-11-04
- Made `StateStore` key and record mutations transactional with respect to its in-memory view: persistence failures restore the previous in-memory properties before returning the error.
- Added deterministic disk-failure injection tests covering put/remove and putRecord/removeRecord, plus reopening the original state to verify it remains unchanged.
- Documented remaining boundaries: cross-process locking and full directory-fsync crash durability are not yet implemented.


## Engineering Update 2 — 2026-11-04

- Recorded successful JNR-FUSE 0.5.8 adapter compilation on the user's Arch Linux machine with Maven and FUSE2 development headers. This verifies Java adapter compilation and shaded-JAR creation, not a live kernel mount.
- Reworked the FUSE Maven build to replace the deprecated project-local `system` dependency with a normal Maven dependency installed into an isolated project-local repository.
- Added shaded-JAR content checks and a `java -jar ... --help` launch smoke test.
- Configured service-descriptor merging and excluded dependency manifests, signatures and module descriptors from shading to reduce packaging collisions and strong-encapsulation warnings.
- Added automated checks for Maven build reproducibility and documented the remaining live mount boundary.


## Engineering Update 3 — upload commit safety and overflow checks (2026-11-04)

- Replaced `FileService.upload` placeholder reservation plus `REPLACE_EXISTING` finalization with a single same-directory move that does not replace existing paths.
- Added deterministic upload tests for existing destination preservation, source interruption cleanup, concurrent writer races and complete payload integrity.
- Changed desktop snapshot and signed-network download byte counters to `Math.addExact`, matching the overflow-safe approach already used in other transfer paths.
- Full desktop, Android peer-core/interoperability, Android source integration and Linux integration test suite passed in a clean engineering workspace.
- The user separately compiled and launch-smoke-tested the Update 2 JNR-FUSE adapter on Arch Linux with FUSE2 installed. The FUSE source/build files are unchanged in Update 3; live mount validation remains deferred.

## Engineering update — 2026-11-05

- Serialized StateStore access across independent PersonalCloud processes with an OS lock and JVM-local lock.
- Refreshed persisted state under lock before every read or mutation to prevent stale-snapshot lost updates.
- Rejected symbolic links for state-related paths and introduced unique staging files, file fsync, and best-effort parent-directory fsync.
- Added a multi-process regression test with four independent JVM writers and 320 persisted values (160 keys plus 160 records).
- Tightened Android peer-core verification to enforce Java 17 API compatibility with `--release 17 -Xlint:all` instead of relying on the host JDK default.


## 2026-11-05 — Direct resumable transfer engine

- Added authenticated transfer-session creation, status, chunk upload, commit and abort routes to desktop and Android peer nodes.
- Added independently SHA-256-verified 4 MiB chunks, durable receiver journals, restart recovery and idempotent chunk retries.
- Added uploader-bound transfer ownership, seven-day expiry and bounded active staging reservations.
- Replaced new desktop and Android managed-file client uploads with direct resumable chunk transfers; retained the legacy whole-file route for compatibility.
- Added explicit resume/status/abort APIs and transfer-ID reporting on interruption.
- Added idempotent managed-storage commit records keyed by transfer ID to protect against a crash after publication but before session cleanup.
- Removed the extra full-size assembly copy: commit verifies chunks and streams them sequentially into the managed-storage publication boundary.
- Added desktop and Android transfer-manager tests plus 9 MiB multi-chunk desktop↔Android interoperability coverage.

## 2026-11-05 — Durable outbound transfer lifecycle

- Added persistent sender-side transfer queues for desktop and Android with stable UUIDs, restart recovery, bounded retry/backoff, source digest revalidation, durable abort, and receiver commit reconciliation.
- Wired Android managed placement through a Keystore-encrypted sender queue and persistable SAF read grants; added queue, resume, and abort controls.
- Added seven-day metadata-only receiver commit receipts so a lost commit response can be replayed without uploading the file again.
- Expanded desktop and Android peer-core tests for process-restart and failure-window behavior.


## 2026-11-05 — Membership liveness and synchronization reliability

- Changed desktop catalogue synchronization from serial peer iteration to a bounded four-worker pool.
- Changed Android membership synchronization to run at most four peer operations concurrently and to perform network I/O outside the membership monitor. Slow peers no longer block inbound membership authentication or local state queries.
- Replaced permanent persisted online flags with 90-second heartbeat freshness leases; stale status is no longer presented or propagated after downtime.
- Hardened Android catalogue merging to preserve newer local heartbeat observations and reject timestamps too far in the future.
- Added deterministic concurrency, lock-availability, stale-presence and stale-catalogue regression tests.


## 2026-11-05 — Direct connectivity diagnostics

- Added `personalcloudctl network diagnostics`, usable without a running daemon.
- Added local interface inventory, IPv4/IPv6 address scope classification and PKCS#12 key identity validation.
- Added bounded STUN Binding discovery with configurable endpoints, listener-port UDP binding, strict transaction/attribute validation and IPv4/IPv6 XOR mapping decode.
- Added multi-server mapping comparison and conservative output that never treats STUN as proof of inbound TCP/TLS reachability.
- Corrected global-address reporting so interface discovery is independent of listener binding; a loopback listener no longer hides an active interface's global IPv6 candidate. Added a separate flag for whether the configured listener address/family matches that candidate.
- Added deterministic loopback mock-STUN tests for success, timeout, mapping differences, IPv6 decoding and malformed transaction rejection.

## 2026-11-05 — TLS provisioning, IPv6 diagnostics and interop harness reliability

- Corrected global-interface candidate reporting so active public IPv4/IPv6 candidates are reported independently of the configured listener bind address; added a separate bound-address match field.
- Added a desktop CA and HTTPS PKCS#12 identity generator with SANs for active stable IPv4/IPv6 addresses, protected CA key permissions, no-overwrite behavior and cleanup on failure.
- Network diagnostics now discover the same default desktop identity directory used by node startup and distinguish valid, missing, password-required and invalid identities without exposing credentials.
- Stabilized the desktop–Android interoperability harness by placing disposable TLS artifacts in a unique project build directory, verifying each generated artifact, staging the identities/truststore into the integration workspace and cleaning only its disposable test data.
- The update installer now runs the full desktop foundation, Android peer-core, desktop–Android process interoperability, Android source-contract and Linux/TLS provisioning checks.
- Clean reconstructed-checkout installer simulation completed with exit code 0. Android SDK/Gradle APK compilation, physical-device validation, live FUSE mounting and inbound reachability from another network remain unverified.

### Desktop TLS routing reliability

- Fixed desktop startup to load the new desktop server identity from `personalcloud-desktop-peer-tls` while independently loading the Android peer truststore from `personalcloud-android-peer-tls`.
- Preserved legacy shared-directory and explicit file overrides.
- Added regression coverage for separate paths, compatibility overrides, and invalid listener addresses.


### Android network endpoint recovery — 2026-11-05

- Android peer service now observes default-network and link-property changes and refreshes its advertised endpoint when the new IPv4 address is covered by its TLS certificate.
- Endpoint changes update mutable local routing state and are propagated by the next signed membership/heartbeat exchange. The signed membership identity certificate and remote member records are preserved.
- Endpoint selection tests reject loopback, link-local, multicast, malformed SANs and addresses not covered by the certificate.
- The Android app framework remains statically validated because Android SDK/Gradle is unavailable in this environment. Physical network-switch acceptance remains required.
