# Linux integration

PersonalCloud's Linux integration is Java-first. The daemon and local-control client are the application; shell files in this directory only launch Java entry points or install KDE metadata.

## Components

- `personalcloudctl`: Java CLI over the owner-only Unix-domain control socket.
- `personalcloud-mount`: launches the optional writable Java FUSE2 adapter.
- `fuse/`: JNR-FUSE adapter for `/Devices/<device>/References`, `/Devices/<device>/Distributed-Storage`, and writable `/Devices/<device>/Filesystem`.
- `personalcloud-dolphin-reference`: KDE Dolphin action to register a selected directory in place.
- `personalcloud-dolphin-place-file`: KDE Dolphin action to choose an online member and send a whole file to its managed storage.
- `personalcloud-dolphin-share-file`: KDE Dolphin action to share one selected file by reference without copying it.
- `install-dolphin-actions.sh`: installs the three actions under the user's KIO service-menu directory.

The reference and managed planes are deliberately read-only. They support bounded random-access reads for remote files, reject filesystem mutations there, and distinguish stale offline catalogue entries from available content. Eligible storage under `/Devices/<device>/Filesystem/<root>/...` is writable for active remote members: create, write, mkdir, rename/move, truncate and delete are authorized and executed by the owning peer. Writes are staged in the system temporary directory and published only after a complete SHA-256-verified upload, so an interrupted write never truncates or corrupts the owner's original file. No-overwrite commits and non-replacing renames prevent unintended replacement. `chmod`, `chown`, `mknod`, links, xattrs and `fallocate` fail closed on writable paths; `utimens` is a documented no-op. Offline metadata remains browseable when cached; opening or mutating unavailable content fails instead of returning stale bytes.

## Build the core

From the project root:

```bash
./build.sh
```

## Optional FUSE2 adapter

The adapter is an optional module because it needs the Linux FUSE2 native runtime and Maven to resolve JNR-FUSE. On Arch Linux, install the build/runtime dependencies with:

```bash
sudo pacman -S --needed maven fuse2
```

Then build it from the project root:

```bash
./integrations/linux/build-fuse.sh
```

The build creates `integrations/linux/fuse/target/personalcloud-linux-fuse-0.2.0.jar` with its Java dependencies bundled. FUSE2 (`libfuse.so.2`) must be present at runtime and `/dev/fuse` must be accessible to the user. The mount uses `default_permissions,nodev,nosuid,noexec`; only the eligible-storage subtree is writable.

Start the PersonalCloud node first. Then mount the namespace with:

```bash
./integrations/linux/personalcloud-mount "$HOME/PersonalCloud"
```

The mount directory must be empty. The launcher refuses to hide existing files. The default control socket resolves to the project's `data/control.sock`; `PERSONALCLOUD_CONTROL_SOCKET` or `PERSONALCLOUD_DATA_DIR` can override it.

## KDE Dolphin integration

Install the service-menu action:

```bash
./integrations/linux/install-dolphin-actions.sh
```

In Dolphin, right-click a directory and choose **Add folder as PersonalCloud reference**. Registration stores only the selected path and metadata; it does not copy or move files. Right-click a regular file and choose **Send to a PersonalCloud device** to transfer the whole file into a selected online member's managed storage. Or choose **Share through PersonalCloud (no copy)** to grant one online member access to that exact file in an already registered directory. The share action offers `DOWNLOAD` and `DOWNLOAD+DELETE`; the latter permits destructive deletion, with a recovery snapshot taken by the owner node before deletion. File sharing by reference refuses files outside registered roots and symlink aliases. All actions run in Konsole so errors remain visible. The two file actions require `kdialog` and `jq`.

To remove the action, delete:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/kio/servicemenus/personalcloud-reference.desktop
${XDG_DATA_HOME:-$HOME/.local/share}/kio/servicemenus/personalcloud-send-file.desktop
${XDG_DATA_HOME:-$HOME/.local/share}/kio/servicemenus/personalcloud-share-file.desktop
```

## CLI examples

```bash
./integrations/linux/personalcloudctl status
./integrations/linux/personalcloudctl network status
./integrations/linux/personalcloudctl network members
./integrations/linux/personalcloudctl references list
./integrations/linux/personalcloudctl references add "Documents" "$HOME/Documents"
./integrations/linux/personalcloudctl references locate "$HOME/Documents/notes.txt"
./integrations/linux/personalcloudctl browse REFERENCE_ID
./integrations/linux/personalcloudctl search design
./integrations/linux/personalcloudctl stat REFERENCE_ID "Project/notes.txt"
./integrations/linux/personalcloudctl download REFERENCE_ID "Project/notes.txt" "$HOME/Downloads/notes.txt"
```

The CLI uses `<PERSONALCLOUD_DATA_DIR>/control.sock` or `./data/control.sock` by default. Set `PERSONALCLOUD_CONTROL_SOCKET` to override it. The mount launcher explicitly sets the project data directory if no socket override is supplied.

Downloads use bounded chunks, verify source size and modification timestamp, compute SHA-256 and refuse to overwrite an existing destination.

## Validation status

The Java-only virtual-filesystem facade is compiled and covered by the core automated test suite (normalization, traversal rejection, metadata, offline behavior, exact bounded reads, eligible-storage write-back, no-overwrite conflicts, concurrent writers and symlink escapes). The JNR-FUSE adapter compiles on Arch Linux against JNR-FUSE 0.5.8 and its shaded JAR passes the non-mounting `--help` smoke test. A real kernel mount, live callback exercise and Dolphin interaction remain production-readiness acceptance tests.


### Building the optional FUSE adapter

On Arch Linux, install `fuse2` development files and Maven, then run:

```bash
./integrations/linux/build-fuse.sh
```

The build compiles the core JAR, installs it into a project-local Maven repository under `build/maven-repository`, builds the shaded adapter, checks required classes, and runs the non-mounting `--help` smoke test. It does not mount a filesystem.
