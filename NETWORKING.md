# PersonalCloud networking

## Network topology

Every enrolled device runs an independent peer node. Nodes communicate directly over TLS; there is no central file-content service or relay. Internet connectivity alone does not guarantee reachability: direct access may require public IPv6, router port forwarding or successful direct NAT traversal. Carrier-grade NAT and restrictive firewalls can make a direct connection impossible. Automatic STUN/ICE traversal and relay fallback are not implemented.

## Protocol surfaces

The peer listener exposes a JSON-over-HTTPS protocol. It does not expose the local administration interface or a browser dashboard.

### Node and transitional compatibility routes

- `GET /node/info`
- `POST /node/pair`
- Legacy authenticated routes under `/node/health`, `/node/shares` and `/node/peer`

These routes preserve compatibility with the earlier Android invitation/token peer protocol. They are not the current private-network trust model.

### Private-network enrollment routes

- `GET /network/challenge` — obtain a short-lived enrollment challenge.
- `POST /network/enroll` — submit the candidate device identity, password proof and device signature.
- `GET /network/enroll/status/{requestId}` — poll a request for approval/rejection and retrieve the signed membership bundle after approval.

The network account password is converted to a PBKDF2-HMAC-SHA-256 verifier and used to produce a challenge-bound HMAC proof. The password itself is not sent to the remote member. An existing active member explicitly approves or rejects the new device. The founder admits the first additional device; once two members are active, any active member may admit independently. Approval returns a short-lived signed `AdmissionApproval` bound to the request, candidate identity/endpoint, approver node ID and exact approver certificate SHA-256. Each device generates its own Ed25519 key pair and receives a chained membership certificate.

### Signed active-member routes

After enrollment, each request is signed by the device's Ed25519 key. The signature binds the method, raw request path, timestamp, unique nonce and SHA-256 body digest.

- `GET /network/members`
- `GET /network/presence`
- `POST /network/heartbeat`
- `GET /network/references`
- `GET /network/references/{grantId}/entries?path=...`
- `GET /network/references/{grantId}/stat?path=...`
- `GET /network/references/{grantId}/content?path=...&offset=...&length=...`
- `DELETE /network/references/{grantId}?path=...` — requires a `DOWNLOAD+DELETE` grant.
- `GET /network/search?q=...&limit=...`
- `POST /network/transfers` — create a durable, uploader-bound transfer session (signed JSON: path, size, SHA-256).
- `PUT /network/transfers/{transferId}/chunks/{index}` — upload one independently authenticated and hashed chunk.
- `GET /network/transfers/{transferId}` — inspect verified chunk progress and resume state.
- `POST /network/transfers/{transferId}/commit` — verify the complete file digest and publish without overwriting.
- `DELETE /network/transfers/{transferId}` — abort and remove a session owned by the authenticated uploader.
- `PUT /network/managed/files?path=...` — legacy direct whole-file upload retained for compatibility.
- `GET /network/managed/files`
- `GET /network/managed/files/{fileId}`
- `GET /network/managed/files/{fileId}/content?offset=...&length=...`
- `DELETE /network/managed/files/{fileId}`

Member requests are checked against the local network identity, the signed certificate chain (including root, issuer ordering, duplicate identities and revoked links), active/revoked status, timestamp freshness, nonce replay state and request signature before dispatch. Revocation records are signed and monotonic; stale catalogues cannot reactivate a revoked member.

Per-source request windows bound ordinary peer traffic and the enrollment challenge/submission routes; authenticated filesystem operations also have a per-member window. Defaults are 600 requests, 30 challenges, 12 enrollment submissions and 300 filesystem operations per minute; override them with `PERSONALCLOUD_RATE_LIMIT_REQUESTS_PER_MINUTE`, `PERSONALCLOUD_RATE_LIMIT_CHALLENGES_PER_MINUTE`, `PERSONALCLOUD_RATE_LIMIT_ENROLLMENTS_PER_MINUTE` and `PERSONALCLOUD_RATE_LIMIT_FILESYSTEM_OPS_PER_MINUTE`.

`GET /network/presence` returns an Ed25519-signed presence record bound to the member certificate and advertised endpoint. Synchronizing peers verify the signature. Legacy unsigned presence remains accepted only when the endpoint still equals both the connected endpoint and the certificate-bound endpoint, so an unsigned response cannot move a member endpoint. Endpoint validation rejects credentials, query/fragment data, oversized hosts, and wildcard, link-local or multicast IP literals; loopback and private-LAN peers remain supported.

Catalogue synchronization is bounded-concurrent (at most four peers at a time). Android does not hold its membership-state monitor during outbound peer requests, so one unreachable peer cannot block inbound member authentication or local membership controls. A member's online flag is a 90-second direct-heartbeat lease; persisted flags expire after downtime and stale catalogue snapshots do not overwrite a newer local heartbeat. This is a liveness indicator, not a guarantee that the next file transfer will succeed.

Resumable sessions are bounded to 16 active sessions per node and 4 per member by default (`PERSONALCLOUD_MAX_TRANSFER_SESSIONS`, `PERSONALCLOUD_MAX_TRANSFER_SESSIONS_PER_MEMBER`). Aggregate and per-member staging reservations default to twice the configured per-file limit and can be overridden with `PERSONALCLOUD_MAX_TRANSFER_STAGING_BYTES` and `PERSONALCLOUD_MAX_TRANSFER_STAGING_BYTES_PER_MEMBER`. Pending protection approvals are bounded to 32 per member and 256 per node. These bounds fail closed with a 409 response.

## Direct connectivity and bind address

The node defaults to loopback for safety. Set `PERSONALCLOUD_BIND_ADDRESS` to a reachable interface address for direct peer connections. The endpoint advertised to peers must be reachable from those peers, and its TLS certificate SAN must match the host/IP in the endpoint URL.

The node does not automatically solve CGNAT or firewall restrictions. It deliberately does not relay file content through another device.

### Read-only endpoint diagnostics

Run this from the project root:

```bash
./integrations/linux/personalcloudctl network diagnostics
```

This command works even when the node daemon is stopped. It validates the configured PKCS#12 server identity, lists local interface addresses and performs bounded STUN Binding requests against two default discovery endpoints. When `PERSONALCLOUD_TLS_KEYSTORE` is not set, it looks for `desktop-server.p12` in `PERSONALCLOUD_TLS_DIR` (default `~/.local/share/personalcloud-android-peer-tls`) and securely prompts for the password in an interactive terminal. `tlsIdentityStatus` distinguishes `VALID`, `NOT_FOUND`, `PASSWORD_REQUIRED` and `INVALID_OR_UNREADABLE`; setting `PERSONALCLOUD_TLS_KEYSTORE_PASSWORD` is supported for controlled automation but is not required interactively. STUN requests use a UDP socket bound to the configured listener's numeric port, allowing the observed UDP mapping to be compared with that port without confusing an ephemeral client port with the service port. Custom STUN endpoints can be supplied with `PERSONALCLOUD_STUN_SERVERS=host:port,host:port`; the timeout is bounded with `--timeout-ms` (100–5000 ms).

The report distinguishes loopback-only binding, missing TLS identity, consistent mappings and endpoint-dependent mappings. `globalInterfaceCandidatePresent` means at least one active interface has a globally-routed candidate, independent of the configured listener; `boundAddressGlobalCandidatePresent` indicates whether the selected listener address/family matches one. This prevents a loopback bind from hiding a global IPv6 address on Wi-Fi. It never edits firewall/router settings or changes the advertised member endpoint. STUN observes outbound UDP mapping only: it cannot prove inbound TCP/TLS reachability, certificate-name correctness from a remote perspective, or successful peer authentication. The `inboundTcpTlsReachability` field therefore remains `UNVERIFIED`. Validate the advertised HTTPS URL from a second device on a different network before relying on direct connectivity. This is diagnostics, not automatic STUN/ICE traversal or relay fallback.

## TLS configuration

Create a desktop server identity after connecting the desktop to the networks whose addresses should be covered:

```bash
./scripts/create-desktop-peer-tls.sh
```

The generator gathers active non-loopback IPv4/IPv6 addresses (excluding temporary, deprecated and tentative IPv6 addresses), creates a private desktop CA and a server certificate with matching IP subject-alternative names, validates the certificate/PKCS#12 bundle, and refuses to overwrite existing identity files. The CA signing key is encrypted at rest and owner-only; only `desktop-ca.crt` should be imported into Android through **Import trusted peer CA**. Keep `desktop-server.p12` and `desktop-ca.key` on the desktop. The script does not change the bind address, start the node, open a firewall port, or alter router settings.

The default output directory is `~/.local/share/personalcloud-android-peer-tls`, matching `scripts/start-node.sh`. Start the node on a chosen interface only after reviewing the addresses and certificate SANs:

```bash
PERSONALCLOUD_BIND_ADDRESS='<chosen local or global interface IP>' ./scripts/start-node.sh
```

The startup script prompts for the server identity password. A globally routed IPv6 address can still be blocked by the host firewall, upstream network, or remote peer's network; it may also change over time. Regenerate/rotate the server certificate if the address used in the peer URL changes. The separate Android server CA still needs to be trusted by the desktop through `PERSONALCLOUD_TLS_TRUSTSTORE` when the desktop initiates connections to the phone.

- Non-loopback binding requires a configured PKCS#12 server identity.
- Outgoing peers validate the remote certificate or configured issuing CA.
- Hostname/IP subject alternative names must match the address used by the client.
- Never disable certificate verification to make pairing work.
- Keep private keys, trust stores and passwords outside the repository.

Environment variables:

| Variable | Purpose |
|---|---|
| `PERSONALCLOUD_BIND_ADDRESS` | Local address to bind |
| `PERSONALCLOUD_PORT` | Peer HTTPS port |
| `PERSONALCLOUD_TLS_KEYSTORE` | Local PKCS#12 server identity |
| `PERSONALCLOUD_TLS_KEYSTORE_PASSWORD` | Identity password |
| `PERSONALCLOUD_TLS_TRUSTSTORE` | Optional PKCS#12 trust store for outgoing connections |
| `PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD` | Trust-store password |

## Transfer semantics

- Referenced files remain on their original owner device and are read on demand.
- Remote reads support bounded byte ranges, so a client need not download the full file to open or seek within it.
- A managed file is streamed directly to the selected destination node in bounded 4 MiB chunks; no intermediary or central file-content server is involved.
- The destination persists each verified chunk and a transfer journal, so the receiver can report progress and accept missing chunks after a client or node restart.
- A retry of an already-received chunk is idempotent only when its size and SHA-256 match the stored chunk.
- Commit performs a full-file SHA-256 pass and streams the chunks sequentially into the existing managed-storage publication path; it does not create a second full-size assembly copy.
- Transfer sessions are bound to the authenticated uploader, expire after seven days, and are bounded by session-count and aggregate staging reservations.
- The final managed-storage commit is idempotent by transfer ID, protecting against a crash after the file is published but before the transfer journal is cleaned up.
- The destination enforces size/path limits and commits without overwriting an existing destination.
- Downloads stage to a temporary file and verify expected size and SHA-256 before finalization.
- `DOWNLOAD` permits read/browse operations; `DOWNLOAD+DELETE` additionally permits deletion of the referenced original. The owner creates a recovery snapshot before supported deletion.
- Revocation blocks future signed protocol operations once updated membership state is received; it cannot erase bytes already downloaded by another member. Signed revocation records are monotonic and chains passing through a revoked member are refused.

### Durable outbound placement jobs

Desktop and Android senders persist a transfer job and sender-generated transfer UUID before creating the receiver session. The receiver create call is idempotent for the same UUID and immutable path/size/SHA-256 tuple. Sender jobs retain source locators and digests, not source bytes; Android source URIs are stored in its Keystore-backed encrypted state domain and their persistable read grant is retained while the job is nonterminal. A job resumes by revalidating the source digest and asking the receiver for the missing chunk set. A changed or revoked source is never silently substituted.

A receiver that has committed a managed file retains a metadata-only receipt tombstone for seven days. Status, create replay, and commit replay return the same receipt; abort cannot erase a committed receipt. Tombstones contain no chunk data and do not count against active staging quotas. This resolves the sender/receiver crash window after file publication but before the sender durably records the receipt.

## Desktop TLS identity and Android truststore

The desktop's incoming HTTPS identity and its outbound Android-peer truststore are separate files generated by different provisioning flows. `scripts/start-node.sh` defaults to `~/.local/share/personalcloud-desktop-peer-tls/desktop-server.p12` for the desktop server identity and `~/.local/share/personalcloud-android-peer-tls/desktop-truststore.p12` for trust of Android peer certificates. It prompts for each password independently. `PERSONALCLOUD_TLS_IDENTITY_DIR` and `PERSONALCLOUD_TLS_TRUSTSTORE_DIR` override the separate directories; explicit `PERSONALCLOUD_TLS_KEYSTORE` / `PERSONALCLOUD_TLS_TRUSTSTORE` paths override files. The older `PERSONALCLOUD_TLS_DIR` remains a shared-directory compatibility override.

Import the public desktop CA certificate (`desktop-ca.crt`) into Android through the app's **Import trusted peer CA (.crt / .pem)** action. The Android app stores it as its trusted peer CA. Keep `desktop-ca.key` and `desktop-server.p12` on the desktop. The desktop truststore separately needs the Android peer CA so desktop-originated HTTPS requests can validate the phone.

This is reciprocal HTTPS server-certificate trust plus PersonalCloud application-level signed member authentication; it is not TLS client-certificate mutual TLS. A non-loopback listener still requires a server identity with a SAN matching the selected address. Binding does not open firewall ports or prove inbound reachability.


## Android endpoint changes

The Android foreground peer service watches the active default network and its link properties. It changes the advertised endpoint only when the active IPv4 address is present as an IP SAN in the imported Android server certificate. The endpoint is mutable routing metadata; the Ed25519 membership certificate remains unchanged. The node publishes the refreshed endpoint in its next signed heartbeat/catalogue exchange.

If a new network address is not covered by the certificate, PersonalCloud fails closed and reports that the Android TLS identity must be renewed. The current Android listener is IPv4-only and the certificate must contain the active address. This does not provide DNS-SD/mDNS, arbitrary DHCP address recovery, IPv6 listener support, NAT traversal or relay.
