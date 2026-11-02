# PersonalCloud V1 implementation and validation status

**Release scope:** self-hosted, local-first peer file access over localhost or mutually reachable trusted LAN/VPN endpoints. This document describes this source archive only. It does not mean the user's GitHub branch has been updated.

## Implemented in V1

| Area | Included functionality |
|---|---|
| Node runtime | Java 21+ HTTP/HTTPS server; independent node identity, state and owner storage; browser dashboard |
| Browser UX | HTML/CSS/JS dashboard; login/session; local file/folder lists; search; upload; folder upload; create folder; move/rename; text preview; recovery history; peer/share management |
| Filesystem watcher | Recursive JDK WatchService; external create/modify/delete and new-directory events advance a revision; dashboard refreshes files/folders when it observes a change |
| Peer trust | Directional pairing; single-use 10-minute invite; incoming token hash; AES-GCM-encrypted outgoing token; peer health and revoke/unpair |
| Grants | Per-peer file and folder `VIEW`/`MODIFY`; folder descendants; streamed ZIP folder download; revoke |
| File transfer | Bounded streamed uploads; streamed file downloads; single byte-range download; SHA-256 response header; folder ZIP sanitization; directory-preserving upload |
| File safety | Relative path validation; root containment; no symlink escape; duplicate destination rejection; bounded text-only previews; incomplete upload temp exclusion |
| Recovery | Owner-local snapshots before local/remote file deletes; manual snapshot; SHA-256 restore verification; no overwrite; retention bounds (20/path, 500 total, 10 GiB total) |
| Authentication | PBKDF2-HMAC-SHA256 password hashing; password rotation; optional RFC 6238 TOTP MFA; one-time recovery codes; TOTP/recovery replay rejection; 12-hour in-memory sessions capped at 64 |
| Operations | Login and pairing throttles; CSRF/origin checks; audit log; atomic state writes and state backup recovery; data/storage non-overlap fail-closed check; TLS required for non-loopback bind |
| Documentation | README, architecture, security and networking notes; automated validation; GitHub Actions workflow |

## Validation completed in the build environment

### Java/unit and API integration suite

`./scripts/verify.sh` is designed to build the JAR, run unit tests, run a multi-node smoke suite, and optionally check JavaScript syntax when Node is installed. The unit checks cover the RFC 6238 reference vector, TOTP enrollment, code/recovery replay rejection, recovery after encrypted-seed key loss, browser-session revocation/capacity, filesystem watcher events, and bounded per-path snapshot retention/restoration.

The smoke suite covers:

- Two-node pairing and peer token persistence/encryption.
- One-time pairing code replay rejection, invalid bearer rejection and same-origin mutation rejection.
- Peer health and TLS peer pairing using generated test certificates/trust store.
- Non-loopback plaintext startup rejection and data/storage path overlap rejection.
- File and folder sharing; directory-preserving upload; ZIP folder download and archive path safety.
- Upload size, duplicate destination, traversal and symlink rejection; incomplete upload exclusion.
- Plain-text preview and binary-preview rejection.
- File/folder move and preservation of affected grants.
- SHA-256 headers, byte-range resume and invalid range handling.
- VIEW delete denial; MODIFY remote delete with owner-local recovery snapshot.
- Snapshot, delete, hash verification, restore and state backup recovery.
- Password migration/rotation, login and pairing throttling, MFA enable/login/disable, and replay rejection.

### Real-browser two-node E2E

`./scripts/browser-test.sh` optionally launches two isolated local nodes and drives the dashboard using Playwright Chromium. The completed browser run in the build environment verified:

- Unauthenticated dashboard and login for both nodes.
- Local index and watcher-driven display of files/folders created outside the dashboard.
- Upload, folder creation, folder listing, folder move/rename, and text preview.
- One-time pairing in the UI.
- Folder grant selected through the folder list and ZIP download with nested content preserved.
- VIEW download with no delete control; a grant can be revoked independently of another folder grant; original files remain.
- MODIFY remote delete; original removed on owner node only after local recovery snapshot.
- Dashboard MFA enrollment, display of 10 recovery codes, recovery-code login, single-use recovery consumption, MFA disable.
- No uncaught browser JavaScript page errors during the tested UI flow.

The UI tests use ephemeral directories and dummy files. They do not touch actual user storage. The Playwright browser test is optional and requires the separately installed Playwright Python package and Chromium. It is included as a reproducible test script.

## Not implemented / not validated as a real-world deployment

| Area | Status |
|---|---|
| NAT traversal, STUN, ICE, TURN, rendezvous, relay fallback | Not implemented; no public infrastructure is provisioned |
| Automatic LAN discovery | Not implemented; pairing is manual |
| Cross-network operation on arbitrary residential/mobile networks | Not validated; peers need mutually reachable TLS endpoints, e.g. a separately configured VPN |
| Application-level file-content E2EE | Not implemented; TLS is terminated by each endpoint |
| Android app/background node | Not implemented or tested on a physical Android device |
| Native Windows/macOS packaging | Not implemented/tested; Java may run there, but this archive's platform validation targets Linux/JDK |
| Background sync, offline queue, conflict resolution, selective sync | Not implemented |
| Multi-user accounts, roles, enterprise identity | Not implemented; one local administrator per node |
| SQLite migration | Not implemented; local state is properties-backed |
| Malware scanning, independent penetration test, formal security audit | Not completed |
| Public-internet production operations, backups, relay operations | Not implemented or tested |

## Release assessment

This is a coherent **PersonalCloud V1 engineering release for controlled trusted-network use**, not a production-ready public-internet cloud. Automated regression tests and a browser-based two-node UI test have passed in the build environment. Actual user LAN/VPN and physical-device acceptance still depends on the user's network, certificates, firewall, OS, and hardware. Do not directly port-forward a node to the public internet.
