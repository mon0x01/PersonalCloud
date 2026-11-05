# PersonalCloud security model

## Security goals

PersonalCloud is designed for a private set of personally operated devices. It must prevent unrelated users from joining or accessing the network, protect peer traffic, isolate local administration from the network listener, and enforce file permissions at the owning node.

## Current protections in source

- Non-loopback peer endpoints require HTTPS with a configured PKCS#12 server identity. Clients validate the peer certificate chain and hostname/IP subject alternative name.
- Network enrollment uses a short-lived challenge and a PBKDF2-HMAC-SHA-256-derived verifier (310,000 iterations). The account password is not sent to the approving peer.
- An existing active network member must explicitly approve or reject a joining device.
- Desktop and Android peer-core nodes generate independent Ed25519 signing identities. Chained membership certificates bind each public key to a node and network.
- Signed member requests bind the HTTP method, raw path, timestamp, nonce and body digest. Receivers reject invalid signatures, stale timestamps and replayed nonces. Timestamp bounds are compared directly rather than using overflow-prone absolute subtraction; regression tests cover extreme signed integer timestamps on desktop and Android peer core.
- Member catalogues carry signed membership certificates and revocation status. Local revocation is enforced by authenticated peer operations after the updated catalogue is received.
- The transitional pairing protocol uses high-entropy one-time invitations and token hashes; it remains for compatibility and is distinct from the approval-gated network membership model.
- The desktop local-control socket is Unix-domain and owner-only (`0600`) inside a private data directory. It is not exposed on the network listener.
- Properties-backed state mutations roll back their in-memory changes if the atomic persistence operation fails, preventing a running node from acting on state that was not committed to disk. This does not yet provide cross-process transactional locking or full directory-fsync crash durability.
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
- Direct connectivity can fail behind CGNAT or restrictive firewalls. There is deliberately no relay fallback.
- Revocation prevents future authorized protocol operations after peers learn the updated membership catalogue; it cannot retract bytes already downloaded by a peer.
- Application-level end-to-end file encryption and key-recovery workflows are not part of the current scope.

## State-store cross-process consistency hardening — 2026-11-05

- `StateStore` now takes a per-state-file JVM lock and an operating-system file lock for every read and mutation. The latest persisted properties are reloaded while holding the lock, preventing stale process snapshots from overwriting changes made by another PersonalCloud JVM.
- State, backup and lock paths reject symbolic links. Temporary state and backup files use unique names, file contents are forced before replacement, and parent-directory fsync is attempted where the provider supports it.
- A four-process regression test performs concurrent key and record writes and verifies a pre-existing reader observes every committed value.
- This is serialized multi-process state access, not a general transactional database. Directory fsync is provider-dependent; power-loss durability and cross-process coordination with non-PersonalCloud tools are not guaranteed.
- The Android peer-core test runner now compiles production and test sources with `javac --release 17 -Xlint:all`, matching the module's declared Java 17 compatibility instead of accidentally inheriting the host JDK's newer API surface.
