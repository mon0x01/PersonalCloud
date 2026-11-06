# PersonalCloud

**PersonalCloud is a Java-only private network of personal devices.** Each device remains an independent node and owns its own files and physical storage. Members discover and access only explicitly authorized data. File contents move directly between devices; there is no third-party cloud-storage intermediary.

This repository contains the scoped Java V2 desktop node, its local control CLI, private network membership, remote reference access, whole-file managed placement, and a separate Android peer implementation.

## Product invariants

- Whole-file placement: a file is stored as a complete file on one selected device. No block striping.
- Manual placement: the user selects the destination device.
- Existing data: selected directories are referenced in place; registration never copies, moves, transforms or re-encrypts their contents.
- Availability: an offline device is unavailable. No automatic replication or migration.
- Connectivity: direct peer-to-peer connections only. No file relay or central file-content store.
- Membership: network account credentials prove an enrollment request; an existing active member explicitly approves the new device. Every device has its own signing identity.
- Permissions: `DOWNLOAD` or `DOWNLOAD+DELETE`. Delete-capable grants authorize deletion of the owner's original; an owner-side recovery snapshot is created first where supported.
- Security: authenticated TLS for non-loopback peer traffic. No mandatory application-level encryption at rest; use OS/full-disk encryption where appropriate.
- Interface: native OS integration is the target. No large browser dashboard.
- Implementation: Java application and integration code; no Python application, CLI, filesystem or test code.

## Implemented desktop capabilities

- Headless Java 21+ node with a peer HTTPS endpoint.
- Persistent node identity and protected per-device Ed25519 signing identity.
- Password-proved, explicitly approved private-network enrollment.
- Chained signed membership certificates, signed peer requests, replay protection and revocation.
- Periodic direct member heartbeat and online/offline device catalogue.
- Owner-only Unix-domain local control socket and Java CLI.
- Zero-copy reference-root registration, browsing, search, metadata and random-access reads.
- Remote reference grants, browsing, stat, search, bounded range reads with per-range SHA-256 verification, and full-download integrity checks.
- Owner-side recovery snapshots before authorized deletion.
- Manual whole-file placement into a selected remote node's managed-storage root, with staging, digest validation, no-overwrite commit and remote listing/download/delete.
- Read-only OS-neutral filesystem projection at `Devices/<device>/References` and `Devices/<device>/Distributed-Storage`.
- Linux JNR-FUSE2 adapter source with explicit read-only mutation rejection, plus KDE Dolphin actions for directory references, whole-file placement and exact-file reference grants without copies.

## Current integration boundary

The Linux Java filesystem model and read-only JNR-FUSE2 adapter are implemented; the adapter has compiled successfully on Arch Linux with Maven and FUSE2 development headers. A real kernel mount remains to be validated. KDE Dolphin actions register directories in place, place whole files on a selected member, and share an individual file by reference without copying it. Android peer-core implements signed network membership and remote storage operations. Android app source includes operational membership controls, a signed-network DocumentsProvider, and no-copy SAF references for selected folders and individual files. The Android framework module still needs SDK compilation and physical-device validation; final UI redesign remains deferred pending product-owner UX feedback.

See:
- [Project status](PROJECT_STATUS.md)
- [Product scope](docs/v2/SCOPE.md)
- [Architecture](ARCHITECTURE.md)
- [Security model](SECURITY.md)
- [Roadmap](docs/v2/ROADMAP.md)

## Requirements

- JDK 21 or newer for the desktop node and Java automated tests.
- OpenSSL and `keytool` for TLS certificate provisioning.
- Maven and the Linux FUSE2 runtime (`libfuse.so.2`) are required only for the optional native mount adapter.
- The Android peer APK is built with Android SDK Platform 35, Build Tools 35.0.0, JDK 17+ and Gradle 8.9. Run `./scripts/setup-android-build-tools.sh` once to install a checksum-verified, user-local toolchain without sudo or Android Studio. The setup does not change shell startup files or install system packages. The peer-core interoperability tests run with the JDK and do not compile the Android framework module.

## Build and test

```bash
./build.sh
./scripts/test-all.sh

# One-time Android build environment setup (user-local, no sudo)
./scripts/setup-android-build-tools.sh

# Build and inspect the APK without installing it
./scripts/build-android-apk.sh

# Build and install on exactly one authorized USB-connected Android device
./scripts/build-install-android-peer.sh
```

Start the desktop node:

```bash
./run.sh
```

By default the node binds to `127.0.0.1:8787` and stores node state in `./data`. Managed storage defaults to `$HOME/PersonalCloud/storage`. For direct LAN use, configure a LAN bind address and a TLS identity whose SAN matches the advertised endpoint.

## Local Java control

The node creates an owner-only Unix-domain socket at `<PERSONALCLOUD_DATA_DIR>/control.sock`. The CLI connects to this socket; local control commands are not exposed on the peer-facing HTTPS endpoint.

```bash
./integrations/linux/personalcloudctl status
./integrations/linux/personalcloudctl network status
./integrations/linux/personalcloudctl network bootstrap "My Network" my-account
./integrations/linux/personalcloudctl network members
./integrations/linux/personalcloudctl network requests
./integrations/linux/personalcloudctl network approve REQUEST_ID
./integrations/linux/personalcloudctl references list
./integrations/linux/personalcloudctl references add "Documents" "$HOME/Documents"
./integrations/linux/personalcloudctl reference-grants create MEMBER_ID REFERENCE_ID . DOWNLOAD
./integrations/linux/personalcloudctl managed place DESTINATION_NODE_ID source.bin backups/source.bin
./integrations/linux/personalcloudctl network search report
```

Network bootstrap and join prompt for passwords through the terminal without echoing them. See `integrations/linux/README.md` for the complete CLI.

## Data preservation

Do not delete `data/` when upgrading. It contains node identity, membership keys/certificates, peer state, credential vault, reference registrations, audit logs, grants and recovery snapshots. Managed files default to `$HOME/PersonalCloud/storage`, outside the source checkout. TLS private keys must remain outside the repository.
