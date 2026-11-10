# Integration and upgrade notes

## Build the node

JDK 21+ is required.

```bash
./build.sh
```

## Start the node

```bash
./run.sh
```

Defaults:
- peer bind address: `127.0.0.1`
- peer port: `8787`
- node data: `./data`
- managed storage: `$HOME/PersonalCloud/storage`

Non-loopback binding is blocked without a TLS PKCS#12 identity. Configure the `PERSONALCLOUD_*` environment variables documented in `README.md` and `NETWORKING.md`.

## Local control

The local control socket is `<PERSONALCLOUD_DATA_DIR>/control.sock`, owner-only. Example commands:

```bash
./integrations/linux/personalcloudctl status
./integrations/linux/personalcloudctl references list
./integrations/linux/personalcloudctl references add "Documents" "$HOME/Documents"
./integrations/linux/personalcloudctl browse REFERENCE_ID
./integrations/linux/personalcloudctl search report
./integrations/linux/personalcloudctl filesystem budgets
./integrations/linux/personalcloudctl filesystem budget MEMBER_ID
./integrations/linux/personalcloudctl filesystem budget-set MEMBER_ID 21474836480 10000
./integrations/linux/personalcloudctl audit list 50
```

## Existing runtime state

Preserve `data/` across source upgrades. It contains `node-id.txt`, `state.properties`, `state.properties.bak`, `vault.key`, activity logs and version snapshots. Do not copy TLS private keys into the repository. The default managed storage root is outside the repository and must not be deleted as part of a source-code upgrade.

## Membership upgrade notes

- Existing network members keep their signed membership certificate and device identity; the upgrade does not rotate the network root.
- Broad filesystem consent is never granted silently. A new device starts with access disabled and must pass the explicit consent flag during enrollment (`network join <url> [account] --consent`, or the Android enrollment option).
- An existing device upgraded to this release must run `filesystem consent` (or the Android equivalent) before broad eligible-storage access is exposed. `network status` reports `filesystemConsentRequired` until then.
- Approvals are now signed `AdmissionApproval` records. Legacy approval results without the record remain accepted for compatibility, but new peers verify the signed record and reject replayed or expired approvals.
- Revocation now includes a signed `MembershipRevocation` record. Legacy unsigned `REVOKED` catalogue status remains accepted, but new peers validate signed records when present and keep revocation monotonic.
- Legacy `/node/*` token routes remain available for the compatibility period.
- Per-member filesystem budgets default to 20 GiB written and 10,000 deleted entries per UTC day. Set `PERSONALCLOUD_MEMBER_DAILY_WRITE_BYTES` or `PERSONALCLOUD_MEMBER_DAILY_DELETE_ENTRIES` to change the node defaults (`0` means unlimited), or use `filesystem budget-set <member-id> <write-bytes-per-day> <delete-entries-per-day>` for one member. Existing usage lives in `state.properties` keys beginning with `filesystem.budget.` and follows the normal state backup/restore process.

## Tests

```bash
./scripts/test-v2-foundation.sh
./scripts/android-desktop-interop-test.sh
./scripts/android-peer-test.sh
./scripts/test-all.sh
```

`DelegatedAdmissionIntegrationTest` covers delegated admission thresholds, approval attribution and rejection cases, certificate-chain hardening, revocation propagation and consent. `DesktopInteropTest` covers desktop↔Android approval, revocation and consent interoperability.

M6 reliability coverage is split between `JsonLimitsTest`, `SecurityMonitorRequestLimitTest`, `ProtectionApprovalLimitTest`, `ReferenceVersionRetentionTest`, `StorageFaultInjectionTest`, `TransferQuotaTest` and presence assertions in `NetworkMembershipServiceTest`. The fault-injection tests model interrupted streams, digest mismatches, destination conflicts, persistence failure after file publication, restart recovery and cancelled snapshots. They do not simulate real disk-full, power-loss or filesystem-corruption behavior.

M7 coverage is split between `FilesystemBudgetTest` (limit enforcement, per-member isolation, restart persistence, overrides, failed-write release, recursive-delete preflight and UTC-day rollover), `AuditLogConcurrencyTest` (concurrent instances, rotation, malformed lines and symlink rejection), plus budget/audit assertions in `LocalControlClientTest` and remote over-budget rejection in `EligibleStorageIntegrationTest`. Real disk-full/power-loss behavior, per-member TLS pinning, physical-device acceptance and an independent security audit remain outstanding.
