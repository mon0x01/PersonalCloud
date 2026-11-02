# PersonalCloud V1.0.0 release notes

## Included

- Local-first, owner-controlled file access between paired Java nodes.
- Explicit per-peer file/folder VIEW and MODIFY permissions, one-time pairing, revoke, peer health.
- Browser dashboard built with HTML/CSS/JavaScript and a Java 21+ backend.
- Folder listing, create, move/rename, upload and nested-folder ZIP download.
- WatchService-based external filesystem change detection and automatic dashboard refresh.
- Bounded streaming uploads, file streaming, SHA-256 headers, byte-range downloads, path/symlink/ZIP safeguards.
- PBKDF2 password hashes, optional TOTP MFA, one-time recovery codes, replay prevention, bounded browser sessions.
- HTTPS for non-loopback nodes, encrypted local peer tokens, activity auditing and state backup recovery.
- Owner-local snapshots before deletes, verified restore, and bounded version retention.
- Unit, API integration, and optional real-browser two-node tests.

## Compatibility

- JDK 21 or newer.
- No Node.js requirement at runtime. Node.js is optional for frontend syntax validation in `scripts/verify.sh`.
- No database server, Maven/Gradle, or third-party Java runtime dependency.

## Explicit non-goals in V1.0.0

No NAT traversal/STUN/ICE/TURN, rendezvous or relay; no public-internet deployment; no application-level end-to-end file encryption; no Android app/background agent; no Windows/macOS native packaging or platform test; no background sync/offline queue/conflict resolution; no multi-user accounts/roles; no SQLite; no malware scanning or independent security audit.

This release is for controlled localhost or trusted LAN/VPN use. Do not port-forward a node directly to the public internet.
