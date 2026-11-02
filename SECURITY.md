# PersonalCloud V1 security notes

## Intended deployment boundary

PersonalCloud V1 is intended for localhost development or a trusted LAN/VPN with correctly configured TLS and firewall restrictions. It is not designed or audited for direct public-internet exposure. Do not port-forward its listener to the internet.

## Controls present in this release

- Loopback-only HTTP by default; any non-loopback bind fails unless a PKCS#12 TLS keystore is configured.
- TLS certificate validation and hostname checking for outbound peer HTTPS calls.
- PBKDF2-HMAC-SHA256 password verifier; plaintext legacy password file is migrated and removed.
- Optional RFC 6238 TOTP MFA with encrypted seed, one-use recovery codes, and replay rejection.
- HttpOnly, SameSite=Strict browser session cookie; Secure attribute under HTTPS; 12-hour expiry; process restart invalidates sessions; at most 64 sessions.
- MFA disables Basic authentication for protected endpoints.
- Incoming peer tokens are hashed; outgoing peer tokens and TOTP seed are encrypted at rest with AES-256-GCM using `vault.key`.
- Single-use pairing invitations, login/pairing throttling, same-origin checks for browser mutations, audit log.
- Path normalization, storage-root containment, symlink rejection, bounded uploads, duplicate-destination rejection, and ZIP path sanitization.
- Recovery snapshots before owner-side file deletion, content hash verification before restore, bounded snapshot retention.
- State data directory is rejected when it overlaps the indexed storage root.

## Important residual risks

1. **TLS is not E2EE.** Each peer terminates TLS and can read transferred content. There is no file-content encryption protocol or device-key verification.
2. **Local administrator is trusted.** A compromised OS account or administrator process can access owned files, data directory, and vault key.
3. **One admin per node.** There are no separate users, roles, delegated administrators, or organizational policies.
4. **Rate limits are process-local.** Login/pairing throttles reset on restart and are not a distributed abuse defense.
5. **State store is not a database.** Properties-backed state and atomic replacement are for a single node/process, not multi-process transactional concurrency.
6. **Downloaded copies persist.** Revocation prevents subsequent access; it cannot delete or revoke copies a peer already downloaded.
7. **Recovery is bounded.** Snapshot retention prunes old data after its limits. Keep a separate backup of both node data and owned file storage.
8. **No malware scanning.** Uploaded files are stored as files; content is not scanned.
9. **No independent security audit or penetration test** has been performed.
10. **No NAT/relay protection model.** There is no relay or rendezvous service, and arbitrary public connectivity is not supported.

## Operational precautions

- Keep `PERSONALCLOUD_DATA_DIR` private to the account running the node. Never commit it, `vault.key`, passwords, certificates, or keystore passwords.
- Keep `PERSONALCLOUD_DATA_DIR` and `PERSONALCLOUD_STORAGE_ROOT` separate and non-overlapping.
- Back up the entire data directory and file storage independently. Keep `vault.key` with its corresponding token records.
- Protect TLS keystores and trust stores. Use certificates whose SAN matches the exact peer URL hostname/IP.
- Restrict network reachability with host firewalls and a trusted VPN/LAN. Do not expose the node directly to the public internet.
- Use disposable files when testing `MODIFY`, because it deletes the owner's original after snapshot creation.
- Save MFA recovery codes offline. They are displayed once and cannot be retrieved in plaintext later.

Report security defects privately to the maintainer before publishing exploit details.
