# PersonalCloud V1 architecture

## 1. Product invariants

- A PersonalCloud node owns the files under its configured storage root.
- Original content is read from and retained on the owner node unless an authorized `MODIFY` operation deletes it.
- Pairing establishes peer trust; an explicit per-peer file/folder grant is still required.
- `VIEW` permits list/download only. `MODIFY` additionally permits remote deletion of the owner's original.
- A remote download is a copy. Revoking a grant cannot retract data already downloaded by a peer.
- No central service stores original files. This release has no rendezvous or relay service.

## 2. Runtime components

```text
Browser (HTML/CSS/JS)
  | session cookie / same-origin API
  v
PersonalCloudServer (JDK HttpServer or HttpsServer)
  |-- AppConfig / PasswordService / SessionManager / TotpService
  |-- FileService / FileIndexer / StorageWatcher / VersionService
  |-- GrantService / PeerService / RemotePeerClient
  |-- StateStore / AuditLog / SecurityMonitor
  v
Owner local storage + private node data

Node B -- HTTPS + bearer token --> Node A
  file bytes are streamed from A's storage, through B, to B's requesting client
```

The Java server serves dashboard assets and JSON/file APIs. The browser executes HTML, CSS, and JavaScript; Java does not replace those browser technologies.

## 3. Pairing and trust direction

Pairing is directional. B submits A's short-lived single-use code to A. A stores a hash of B's incoming bearer token and returns the raw token once; B stores A's endpoint and token encrypted under B's local AES-256-GCM vault key. This creates the trust direction required for B to call A. Pairing in the reverse direction is a separate operation.

Sharing then works from A to B only when A has incoming trust for B. A creates a grant with peer ID, relative path, and `VIEW` or `MODIFY`. Requests authenticate the peer token and resolve the actual peer ID; the server does not trust a peer-supplied node ID by itself. Opaque share identifiers and folder-descendant checks constrain subsequent requests.

## 4. Authentication and browser sessions

Each node has one administrator account. Passwords are verified using salted PBKDF2-HMAC-SHA256 hashes. When MFA is off, Basic authentication remains available for local automation and CLI integration; the dashboard creates an in-memory session cookie after login. Enabling MFA disables Basic authentication for protected APIs and requires password plus a current RFC 6238 TOTP or unused recovery code.

The TOTP seed is encrypted using the local token vault key. Ten recovery codes are shown once and only their hashes are persisted. Accepted TOTP time steps are stored to reject reuse; recovery codes are consumed once. Browser sessions contain random 256-bit opaque values, only their SHA-256 hashes are kept in memory, sessions expire after 12 hours, and a node restart invalidates them. The manager caps active sessions at 64.

## 5. File and folder model

`FileService` is the filesystem trust boundary. It validates relative paths, root containment, no-follow access, symlink escapes, duplicate destinations, and upload size. It supports file/folder listing, upload, folder creation, file/folder move, small plain-text previews, streamed downloads, and streamed folder ZIPs. ZIP entry names are sanitized independently of the host OS path separator.

Directory uploads preserve relative paths when the browser supplies `webkitRelativePath`; each file is uploaded as its own bounded request, so a mid-operation failure can result in partial success. Folder ZIP downloads are streamed and sanitized but are not resumable. File downloads support a single byte range and include a SHA-256 response header.

The `StorageWatcher` recursively registers real directories without following symlinks. It increments a revision when file/directory changes are observed, including newly created subdirectories. The browser polls a tiny status endpoint every five seconds and runs full file/folder refreshes only when the revision changes.

## 6. Permissions, deletion, and recovery

A file or folder grant is scoped to a single peer. A folder grant exposes descendant files and a ZIP download. `VIEW` cannot call remote deletion. `MODIFY` can delete an individual original file, but the owner creates and persists a local recovery snapshot first. Local file delete uses the same snapshot-before-delete order. The snapshot store is inside the private data directory, outside the indexed storage root, and never exposed to peers.

Each snapshot has SHA-256 metadata. Restore verifies the content and refuses to overwrite a destination. Retention is bounded to 20 snapshots per path, 500 snapshots total, and 10 GiB aggregate content. A file larger than the configured maximum upload size cannot be snapshotted, so the delete request is cancelled rather than silently deleting unrecoverable content.

Moves rewrite the affected grant paths while retaining grant IDs and permissions. Revocation prevents subsequent remote access but does not remove already downloaded peer copies.

## 7. State and secrets

The data directory contains node identity, salted admin hash, `vault.key`, encrypted outgoing peer tokens, grants, pairing records, MFA state/recovery-code hashes, state backup, recovery blobs/metadata, and audit logs. It must not overlap the owned storage root. The data directory should be private to the operating-system user. A full backup must keep the state and vault key together. If the vault key is lost, encrypted outgoing tokens cannot be restored and those outbound pairings must be recreated. MFA recovery codes remain available if the encrypted TOTP seed cannot be decrypted.

`StateStore` is a properties-backed single-node state file with atomic replacement and a last-known-good backup. It is not a transactional multi-process database. Run one PersonalCloud process per data directory.

## 8. Network and threat boundaries

The listener defaults to loopback HTTP. Any non-loopback listener requires a PKCS#12 TLS keystore. Peer HTTPS calls use certificate and hostname verification; a custom trust store can be configured. HSTS applies to HTTPS responses. Use a trusted LAN or VPN and firewall controls.

TLS is transport encryption, not application-level E2EE. Both peer endpoints terminate TLS and may read the content. There is no NAT traversal, STUN/ICE/TURN, rendezvous, relay, or automatic discovery. Peers must have mutually reachable HTTPS endpoints. No third-party infrastructure is provisioned by this project.

## 9. Deferred architecture

A future cross-network design should separate candidate exchange from data custody: rendezvous should exchange peer connection details only, an ICE/STUN path should attempt direct connectivity, and a blind relay may forward encrypted packets when direct connectivity fails. File-content E2EE needs device-held keys, identity verification, rotation, and revocation semantics before it is implemented. Android should be a separate peer agent implementing the same explicit grant semantics while respecting mobile OS storage/background constraints. Background sync needs conflict and offline-queue semantics separate from the current explicit file access model.
