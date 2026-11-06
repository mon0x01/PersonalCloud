# PersonalCloud Android peer

The Android application is an independent PersonalCloud node, not a web-dashboard client. Its Java peer core implements the desktop V2 private-network membership and signed-storage protocol while retaining the transitional invitation/token API for compatibility with older nodes.

## Implemented and automated-tested peer-core capabilities

- Independent node ID and encrypted persistent peer state backed by Android Keystore AES-GCM in the app.
- TLS server identity import and peer certificate trust.
- Password-proof network enrollment, explicit approval, per-device Ed25519 identity and signed membership certificates.
- Signed member requests, nonce replay rejection, member catalogue synchronization, direct heartbeat and revocation.
- Network-scoped reference grants using `DOWNLOAD` / `DOWNLOAD+DELETE`.
- Remote reference listing, browsing, search, stat, full download, verified byte-range reads and permission-controlled deletion.
- Whole-file managed placement with staging, SHA-256 verification, no-overwrite commit, network-wide listing and ranged reads.
- Owner-local recovery snapshots before reference deletion, SHA-256-verified restore, no-overwrite restore and bounded retention.
- Legacy invitation/token pairing remains for backward compatibility.
- Simulated desktop–Android interop tests exercise signed enrollment and authenticated file operations in both directions.

## Android app integration source

`app/src/main/java/dev/personalcloud/android/PersonalCloudDocumentsProvider.java` is registered as a `DocumentsProvider`. It exposes phone-owned managed storage, local SAF references, and signed-network members' `References` and `Distributed-Storage`. Remote opens use seekable proxy descriptors backed by authenticated byte-range reads. Cached metadata remains visible when a member is offline but is labelled unavailable. Mutations are rejected except the explicit owner-authorized deletion operations.

`AndroidSafReferenceStore` adds in-place references through Android's Storage Access Framework:

- A selected folder tree is retained through a persistable URI permission. PersonalCloud stores only the URI/document identifiers and metadata; it does not import or copy the folder contents.
- A selected individual document can also be referenced without copying. Single-file references are `DOWNLOAD` only in this release because safe deletion recovery requires a parent folder with persistent write capability.
- Folder `DOWNLOAD+DELETE` grants require persistent write permission. Before deletion the original bytes are snapshotted, size and SHA-256 are verified, and restore refuses to overwrite an existing document.
- Persisted URI permissions remain while any active grant or recovery snapshot needs them. Failed picker operations release newly acquired but unused permissions.
- The owner can browse and open local SAF references from Android's system document picker using seekable local proxy descriptors.

`PeerService` starts the HTTPS listener and schedules signed catalogue/heartbeat synchronization after startup and every 20 seconds for enrolled members. The app's operational controls expose network bootstrap, password-proof join, approval polling, pending-request approval/rejection, member listing and revocation. These controls are functional plumbing, not a final UX redesign.

## Current limitations

- The Android app/framework/provider module has not been compiled against Android SDK/Gradle in this environment. Static source checks and peer-core tests are not a substitute for APK compilation or physical-device validation.
- Physical behavior of persistable SAF permissions, third-party document providers, proxy file descriptors, foreground-service lifecycle and intermittent network changes is reserved for production-readiness validation.
- Android network membership is enabled on Android 13/API 33 or newer. Older supported API levels remain on legacy peer compatibility.
- Owner-local recovery snapshot listing and restore are exposed through operational controls; final UX work remains subject to product-owner feedback.

## Build/test

The Android peer-core and simulated desktop interoperability tests run from the repository root:

```bash
./scripts/android-peer-test.sh
```

The full suite also includes static source/manifest checks for the Android app layer:

```bash
./scripts/test-android-app-integration.sh
```

Assembling the Android APK requires Android SDK Platform 35, Build Tools 35.0.0, JDK 17+ and Gradle 8.9. From the repository root, run:

```bash
./scripts/setup-android-build-tools.sh   # one-time, checksum-verified user-local setup
./scripts/build-android-apk.sh           # compile, package and validate the APK
./scripts/build-install-android-peer.sh  # optional: install on one authorized USB device
```

The setup uses the official Android command-line tools and Gradle distribution, verifies both SHA-256 checksums, and installs under the current user's home directory. It does not require Android Studio, sudo, or changes to shell startup files. The build scripts automatically load the generated environment file. Peer-core tests do not compile the Android framework module and do not replace physical-device acceptance testing.
