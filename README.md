# PersonalCloud V1

**Local-first peer-to-peer file access. Every node owns its files.** A node serves only files or folders its administrator explicitly grants to a paired peer. Downloads travel from the owner node to the requesting node; there is no central PersonalCloud file store.

> **V1 boundary:** PersonalCloud V1 is a self-hosted, trusted-network/VPN file-access application. It is not a public-cloud service, does not automatically traverse NAT, and has not undergone an independent security audit. Do not port-forward a node directly to the public internet.

## Product rules

1. The original file stays on the device that owns it.
2. Pairing establishes trust; it does not automatically grant file access.
3. A file/folder owner explicitly grants access to a named paired peer.
4. `VIEW` allows listing and downloading a copy. It never allows deleting the owner's original.
5. `MODIFY` allows listing, downloading, and deleting the owner's original. The owner first creates a private local recovery snapshot.
6. Revoking a grant prevents subsequent access. It does not delete the original or copies already downloaded by the peer.
7. A node can both serve its own files and request files from other nodes.
8. A coordination or relay service is not required by this build because peers connect directly to their configured HTTPS endpoints. There is no central file-storage server.

## V1 capabilities

### Device trust and access control

- Stable per-node UUID and one administrator account per node.
- Directional pairing using a random single-use code with a 10-minute lifetime. Pair in the opposite direction separately when both devices need to request each other's files.
- Incoming peer bearer tokens are stored as SHA-256 hashes. Outgoing peer tokens are encrypted at rest using AES-256-GCM and a local `vault.key`.
- File-level and folder-level `VIEW` / `MODIFY` grants.
- Grant revocation and removal of either side of a pairing.
- Authenticated peer-health checks.

### Browser dashboard and file operations

- Browser interface built with HTML, CSS, and JavaScript; Java serves the static assets and implements the APIs.
- Local file and folder lists, search, upload, folder creation, move/rename, and manual refresh.
- Recursive storage watcher detects external file/folder changes. The browser polls a small revision value and refreshes the index when the tree changes.
- Multi-file upload and directory upload (preserves relative folder paths in browsers that support `webkitdirectory`). Files in a directory upload are separate requests; a failure can leave earlier files uploaded.
- Folder sharing and streamed ZIP download with archive-path sanitization.
- Small text-file preview (up to 256 KiB). Preview is served as inert `text/plain`, never executed as HTML.
- Single HTTP byte-range downloads for resume and an `X-Content-SHA256` response header for integrity checking.
- Local and remote file deletion. `MODIFY` deletion creates an owner-local snapshot before deleting the original.

### Local recovery and reliability

- Manual snapshots and automatic snapshots before local or remote file deletion.
- Restore verifies the snapshot's SHA-256 and refuses to overwrite an existing destination.
- Snapshot retention is bounded: up to 20 snapshots per path, 500 total, and 10 GiB total snapshot data. A snapshot larger than the configured per-file upload limit cannot be created; in that case deletion is cancelled.
- Atomic state writes where supported, a last-known-good state backup, and recovery when the primary state file is unreadable.
- Storage watcher monitors directories without following symbolic links.
- Activity log for selected administrative, pairing, file and grant operations.

### Authentication and transport security

- Salted PBKDF2-HMAC-SHA256 password verifier; the first-run password is printed once. The plaintext legacy password file is migrated and removed.
- Optional authenticator-app MFA using RFC 6238 TOTP (SHA-1, six digits, 30-second period), with 10 one-time recovery codes. TOTP time-step replay and recovery-code reuse are rejected.
- Browser session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` when HTTPS is enabled. Sessions last up to 12 hours, are held in memory, and are invalidated when the process restarts. At most 64 sessions are retained per node.
- When MFA is enabled, password-only HTTP Basic access is disabled. A password plus TOTP/recovery code is required to establish a browser session.
- Login and pairing failure throttles, same-origin checks for browser state changes, bounded request sizes, path traversal/symlink defenses, and secure response headers.
- Default listener is loopback-only HTTP. Non-loopback binding is rejected unless a PKCS#12 TLS keystore is configured.
- Outbound peer HTTPS validates certificates and hostnames. A custom PKCS#12 trust store can be used for private/self-managed certificates.

## Requirements

- JDK 21 or newer (the build uses virtual threads; JDK 26 also works).
- Bash.
- A modern browser.
- For `scripts/verify.sh`: `curl`, `python3`, `keytool` (JDK), `unzip`, and `sha256sum`.
- Node.js is optional and is used only for the frontend syntax check. It is **not** needed to run PersonalCloud.
- Optional browser E2E tests require Python Playwright and a Playwright-compatible Chromium browser.

The application has no Maven/Gradle build, no Java runtime libraries outside the JDK, no frontend package manager, and no database server dependency. It uses the JDK HTTP/HTTPS server/client, crypto APIs, NIO filesystem APIs, and `WatchService`.

## Build and run locally

```bash
./build.sh
./run.sh
```

Open <http://localhost:8787>. The first-run terminal output includes `Username: admin` and a generated password. Save it securely; the application does not retain that password in plaintext. The browser shows a login screen and creates a session after authentication.

Default paths:

- Node identity, password hash, MFA secret, peer tokens, grants, state, recovery snapshots, and logs: `./data/`
- Files owned by this node: `~/PersonalCloud/storage/`

**The data directory and storage root must be separate, non-overlapping directories.** This prevents node credentials and recovery snapshots from being indexed as user files. Back up the complete data directory and the owned storage directory separately. Keep `vault.key` with its corresponding state backup. If it is lost, encrypted outgoing peer tokens cannot be decrypted and must be re-paired. If the encrypted MFA seed becomes unavailable, use an unused recovery code to sign in and disable/re-enroll MFA.

## Test two nodes on one computer

Open two terminals in the project root.

**Terminal A:**

```bash
PERSONALCLOUD_NAME="Laptop-A" \
PERSONALCLOUD_PORT=8787 \
PERSONALCLOUD_DATA_DIR="$PWD/data-a" \
PERSONALCLOUD_STORAGE_ROOT="$PWD/storage-a" \
./run.sh
```

**Terminal B:**

```bash
PERSONALCLOUD_NAME="Laptop-B" \
PERSONALCLOUD_PORT=8788 \
PERSONALCLOUD_DATA_DIR="$PWD/data-b" \
PERSONALCLOUD_STORAGE_ROOT="$PWD/storage-b" \
./run.sh
```

Put disposable test content under `storage-a/`. Then:

1. Open Node A and generate a one-time pairing code.
2. Open Node B and enter Node A's URL and code under **Pair a device**.
3. Node A can now grant Node B access to a local file or folder. Pair in the other direction if Node A also needs to request Node B's files.
4. On Node A, grant Node B `VIEW` or `MODIFY` for a relative file/folder path.
5. On Node B, load Node A's remote shares. Download a file or a folder ZIP.
6. Test `MODIFY` only with disposable files: deleting remotely removes the owner's original after a local recovery snapshot is created.
7. Revoke each grant and verify that the peer loses visibility after refreshing. The original remains on the owner node.

A pairing relationship and a share grant are separate. A peer may be paired but still see no shared files.

## Enable MFA

Sign in to the node's dashboard, open **Security**, and choose **Set up authenticator MFA**. Add the displayed secret/URI to an authenticator app, enter the current six-digit code, and enable it. Save the ten recovery codes offline; they are displayed only at enrollment. Each recovery code is single-use. When MFA is enabled, the dashboard requires password plus an authenticator code or an unused recovery code. Password-only Basic authentication is rejected.

## Network access: HTTPS on a trusted LAN or VPN

The default `127.0.0.1` listener is suitable for local development only. A non-loopback bind requires TLS. Create a PKCS#12 server keystore with SAN entries for the exact hostname/IP used in the peer URL; example values below are placeholders:

```bash
keytool -genkeypair \
  -alias personalcloud \
  -keyalg RSA -keysize 3072 -validity 365 \
  -dname "CN=pc-a" \
  -ext "SAN=dns:pc-a,ip:192.168.1.20" \
  -storetype PKCS12 \
  -keystore pc-a.p12
chmod 600 pc-a.p12
```

Start Node A:

```bash
PERSONALCLOUD_NAME="Laptop-A" \
PERSONALCLOUD_BIND_ADDRESS=0.0.0.0 \
PERSONALCLOUD_PORT=8787 \
PERSONALCLOUD_TLS_KEYSTORE="$PWD/pc-a.p12" \
PERSONALCLOUD_TLS_KEYSTORE_PASSWORD='your-keystore-password' \
./run.sh
```

For a self-managed test certificate, export it and import it into a PKCS#12 trust store on each peer that connects to Node A:

```bash
keytool -exportcert -alias personalcloud -keystore pc-a.p12 \
  -rfc -file pc-a.crt
keytool -importcert -alias pc-a -file pc-a.crt \
  -storetype PKCS12 -keystore trust-pc-a.p12
chmod 600 trust-pc-a.p12
```

On the connecting node:

```bash
PERSONALCLOUD_TLS_TRUSTSTORE="$PWD/trust-pc-a.p12" \
PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD='your-truststore-password' \
./run.sh
```

The peer URL hostname/IP must match the certificate SAN. Hostname verification is not disabled. Your browser/OS must trust the certificate too. Use a properly managed private CA or trusted CA certificate for real use; self-signed certificates are for controlled tests. Restrict firewall access to a trusted LAN/VPN interface and required port.

**Current network limitation:** PersonalCloud does not implement multicast discovery, STUN, ICE, TURN, rendezvous, NAT traversal, or relay fallback. Different-network peers need mutually reachable HTTPS endpoints (for example, through a separately configured VPN). Do not port-forward the service directly to the public internet.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `PERSONALCLOUD_NAME` | Machine hostname | Friendly node label |
| `PERSONALCLOUD_PORT` | `8787` | HTTP/HTTPS listener port |
| `PERSONALCLOUD_BIND_ADDRESS` | `127.0.0.1` | Bind address; non-loopback requires TLS |
| `PERSONALCLOUD_DATA_DIR` | `./data` | Node identity, secrets, peers, grants, state, recovery, audit |
| `PERSONALCLOUD_STORAGE_ROOT` | `~/PersonalCloud/storage` | Files owned and indexed by this node |
| `PERSONALCLOUD_TLS_KEYSTORE` | Unset | PKCS#12 server keystore; enables HTTPS |
| `PERSONALCLOUD_TLS_KEYSTORE_PASSWORD` | Unset | Keystore password |
| `PERSONALCLOUD_TLS_TRUSTSTORE` | JVM default trust | Optional PKCS#12 peer trust store |
| `PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD` | Unset | Trust-store password |
| `PERSONALCLOUD_MAX_UPLOAD_BYTES` | `2147483648` (2 GiB) | Maximum one-file upload and snapshot size; range 1 byte–20 GiB |

## Automated validation

Backend/unit/integration suite:

```bash
./scripts/verify.sh
```

This builds the JAR, runs the RFC 6238 and session tests, verifies filesystem watcher events, launches isolated node processes, and exercises pairing, token encryption, peer health, replay rejection, folder grants/ZIP download, uploads, path and symlink rejection, file movement, grant preservation, snapshot/restore integrity, checksum/range downloads, activity logging, login/pairing throttles, TLS trust, state recovery, password migration, MFA, session behavior, and non-loopback HTTP fail-closed behavior. Node.js syntax checking runs when Node is installed; lack of Node.js does not prevent running the application.

Optional real-browser, two-node UI suite:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install playwright
python -m playwright install chromium
./scripts/browser-test.sh
```

The browser suite launches two isolated local nodes and exercises login, watcher-driven refresh, upload, folder creation/move, text preview, pairing, folder share/ZIP download, VIEW download, independent grant revocation, MODIFY deletion, owner recovery, MFA recovery login/disable, and browser JavaScript errors. It touches only temporary test directories. Set `PC_CHROMIUM_EXECUTABLE=/path/to/chromium` to use a system Chromium installation; set `PERSONALCLOUD_BROWSER_PORT_A` and `_B` to override its test ports.

## V1 limitations and deferred work

The following are deliberately **not claimed as complete**:

- NAT traversal, STUN/ICE/TURN, rendezvous, public relay, and automatic peer discovery.
- Application-level end-to-end file-content encryption independent of TLS.
- Android app/background node and native Windows/macOS desktop integration.
- Background synchronization, offline queues, conflict resolution, and selective sync.
- Multi-user accounts, roles, external identity providers, and organizational administration.
- SQLite migration; node metadata remains a small properties-backed local store.
- Full directory deletion, multipart/chunked uploads, resumable uploads, and large-file preview.
- Malware scanning, independent penetration testing, security audit, and production operations/backup automation.

TLS encrypts the transport connection, but both endpoints terminate TLS and can read content. A receiving peer can retain copies it already downloaded after access is revoked. File SHA-256 response headers detect transfer mismatch when checked by a client; they are not signatures and do not prove sender identity independently of TLS/peer authentication.

## Repository layout

```text
src/                         Earlier standalone Java learning exercises (preserved)
src/main/java/dev/personalcloud/
  PersonalCloudApplication.java
  core/                       File services, grants, watcher, MFA, state, recovery, audit
  net/                        Peer HTTP client and JSON protocol
  web/                        HTTP/HTTPS server and authenticated APIs
src/main/resources/web/       HTML, CSS, JavaScript dashboard
src/test/java/                Unit and filesystem watcher tests
scripts/                      Build verification, API smoke tests, browser E2E tests
```
