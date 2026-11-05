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
```

## Existing runtime state

Preserve `data/` across source upgrades. It contains `node-id.txt`, `state.properties`, `state.properties.bak`, `vault.key`, activity logs and version snapshots. Do not copy TLS private keys into the repository. The default managed storage root is outside the repository and must not be deleted as part of a source-code upgrade.

## Tests

```bash
./scripts/test-v2-foundation.sh
./scripts/android-peer-test.sh
./scripts/test-all.sh
```

All application, CLI, filesystem-model and test code in this scoped release is Java. Shell scripts only orchestrate compilation, certificate generation and test execution.
