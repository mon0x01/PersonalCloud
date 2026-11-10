# PersonalCloud architecture

## 1. System model

PersonalCloud is a private, direct-connected network of personally operated devices. Every enrolled device is an independent node with its own identity, local data, managed-storage root and peer HTTPS endpoint. There is no central file-content service or relay. A device that owns a file is authoritative for that file; when it is offline, the content is unavailable even if cached metadata remains visible.

Each node has three boundaries:

1. **Local control plane** — owner-only Java CLI over a Unix-domain socket.
2. **Peer control/data plane** — authenticated HTTPS/JSON protocol for membership, presence, catalogue, references and managed files.
3. **Local storage plane** — existing directories referenced in place plus a separate PersonalCloud-managed storage root.

## 2. Product invariants

- One physical owner per file in the initial product model.
- Whole-file placement on one manually selected destination; no block striping.
- Existing directories/files are referenced in place and are never copied or moved during registration.
- Referencing and authorization are separate operations.
- Reference grants use `DOWNLOAD` or `DOWNLOAD+DELETE`.
- Delete-capable reference grants create a verified owner-side recovery snapshot before deletion where the backing provider supports it.
- Offline nodes are unavailable; stale metadata is never represented as live content.
- Peer traffic uses authenticated TLS and member-signed requests.
- No relay, replication, automatic synchronization, public discovery or central file storage.
- No mandatory application-level encryption of file contents at rest; host OS encryption is preferred.
- The principal UX is native OS integration rather than a browser dashboard.
- Application and integration code is Java; shell is used only for launchers and OS packaging glue.

## 3. Desktop Java node

### `PersonalCloudApplication` and `PersonalCloudNode`

The process entry point builds and owns a node's runtime dependency graph, loads persistent state, starts the peer endpoint, local-control socket and periodic catalogue synchronization, and closes services on shutdown.

### `NetworkMembershipService` and `DeviceIdentity`

Each node creates an Ed25519 signing key pair. A network bootstrap stores a PBKDF2-HMAC-SHA-256 verifier, a root membership certificate and the local member record. Enrollment uses a short-lived challenge and a password proof; the password itself is not sent to the approving device. An active member explicitly approves or rejects the pending device, returning a short-lived signed admission approval attributable to that member. A signed certificate chain links member identities to the network root.

Authenticated peer requests sign the HTTP method, raw path, timestamp, nonce and body digest. Receivers validate the member certificate chain, network identity, issue ordering, duplicate identities, timestamp, signature and replay nonce before dispatching the request. Revoked identities and chains passing through revoked members are rejected. Revocation records are signed and monotonic, so stale catalogues cannot restore access. Broad filesystem consent is explicit for new enrollment and existing-device upgrade.

### `DeviceCatalogueService` and `NetworkPeerClient`

Nodes exchange signed member catalogues and direct presence/heartbeat requests. The catalogue tracks the endpoint and online/offline state of members. Offline members retain cached metadata, but remote content reads fail as unavailable.

### `PeerProtocolServer`

The JDK HTTP server module (`jdk.httpserver`) exposes the node's HTTPS/JSON peer API. It supports enrollment, membership, presence, heartbeat, remote reference operations and managed-file operations. The browser dashboard and network-exposed local administration API are not part of this build. A transitional invitation/token API remains for compatibility with the previous Android peer protocol.

### `LocalControlServer`, `LocalControlClient` and `PersonalCloudCli`

The owner-only Unix-domain socket separates local administration from the peer listener. The socket is created with owner-only permissions. The Java CLI provides local node, membership, reference, grant, browse/search/stat/download and managed-placement operations.

## 4. Storage model

### Referenced storage

`ReferenceStorageService` registers selected directories by canonical path and stores metadata only. The original files remain at their existing paths. Symbolic links, special files, traversal paths and unsafe roots are rejected. `ReferenceGrantService` binds a member identity to a selected reference and permission level. Remote operations include root listing, folder browse, stat, search, bounded byte-range reads, checksum-verified downloads and authorized deletion.

### Managed storage

`ManagedStorageService` stores whole files below a node-local managed root. A source node chooses the destination member and streams the complete file directly over authenticated HTTPS. The receiver stages the bytes, enforces size/path limits, verifies SHA-256 and commits without overwriting an existing destination. The destination remains the physical owner.

### Recovery and monitoring

`StorageWatcher` uses Java NIO `WatchService` to observe registered storage changes. `VersionService` and `ReferenceVersionService` keep bounded owner-local snapshots and verify content digests during restoration. Android SAF-backed references maintain their own URI-permission-aware bounded recovery store.

### Virtual filesystem model

`ReferenceFileSystemModel` and `ReadOnlyVirtualFilesystem` expose a read-only namespace:

```text
Devices/<device>/References/...
Devices/<device>/Distributed-Storage/...
```

The model handles canonical path lookup, metadata, offline state and bounded random-access reads. Native adapters must delegate to this boundary instead of implementing path authorization independently.

## 5. Linux integration

The optional Java JNR-FUSE2 adapter projects the virtual filesystem into a read-only mount. It explicitly rejects data and metadata mutation callbacks and requests `ro,nodev,nosuid,noexec` mount flags. KDE Dolphin KIO service-menu actions register a directory in place, send a whole file to a selected online member, or create an exact-file reference grant without copying the file. The adapter source and shell integration checks exist; the optional Maven/JNR-FUSE build and real kernel mount still require Linux FUSE2 dependencies and platform validation.

## 6. Android integration

The Android peer-core is a Java 17-compatible module that implements the membership, signed-request, catalogue, reference and managed-storage protocol. It is exercised by headless tests against the desktop node.

The Android app source includes:
- A foreground peer service with periodic catalogue/heartbeat synchronization.
- AndroidKeyStore-backed AES-GCM protection for app state.
- Operational controls for network creation/join, approval/rejection, member listing/revocation and owner recovery.
- `DocumentsProvider` integration for app-managed files, owner-local SAF references and remote member content.
- Storage Access Framework folder-tree and single-document references that persist URI permissions and do not copy original bytes.
- Seekable proxy file descriptors backed by authenticated byte-range reads for remote documents.

Network membership requires Android 13/API 33 or newer for the platform Ed25519 provider; older supported Android versions retain legacy peer compatibility. The Android framework module still needs Android SDK/Gradle compilation and physical-device validation. The final visual design remains deferred pending product-owner UX feedback.

## 7. Security boundaries

- Non-loopback peer traffic uses TLS with a matching certificate SAN.
- Network membership is explicit and approval-gated.
- Every node has its own signing key; private keys are not shared.
- Signed requests bind method, path, timestamp, nonce and body digest.
- Signed presence binds the advertised endpoint to the member key; unsigned legacy presence cannot move a certificate-bound endpoint.
- Local administration is not exposed through the peer listener.
- File operations enforce member grants, canonical paths, no-symlink rules and configured byte limits.
- Downloads and managed uploads verify size and SHA-256 before finalization.
- Deletion of shared referenced originals is permission-gated and snapshot-backed where supported.
- JSON input, per-source request rates, pending approvals, transfer sessions, reserved staging and coordinated-ticket claims are bounded.
- Eligible-filesystem mutations and sensitive authorization decisions produce owner-side audit records without logging file contents or credentials.

## 8. Known engineering limits

- Android app framework source has not yet been built with the Android SDK/Gradle in this development environment.
- The JNR-FUSE module compiled successfully against its external Maven dependency on Arch Linux on 2026-11-04. A real Linux-kernel mount and callback exercise remain unverified.
- Transfer resume after abrupt process/device failure, long-duration/concurrency testing, performance profiling, a security audit, real disk-full/power-loss fault testing and final native UX refinement remain production-readiness work. The automated fault-injection suite uses deterministic software faults.
- Tiered per-member filesystem quotas beyond the request-rate window and per-member TLS certificate pinning beyond signed endpoint binding are not yet implemented.
- Direct connectivity can fail behind CGNAT or restrictive firewalls; no relay fallback is provided.
