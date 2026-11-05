# Android Storage Architecture

## Current node storage

The Android node's existing managed storage remains under the app-private
`filesDir/node-storage` directory. This location is not changed by volume
discovery. No current files are moved, copied, deleted, or re-encrypted.

## Volume discovery

`AndroidStorageVolumeRegistry` enumerates the shared/external volumes exposed
to the calling Android user through `StorageManager.getStorageVolumes()`.

For each volume it reports:

- User-visible label and filesystem UUID-derived identity when available.
- Primary, removable, and emulated characteristics.
- Current mount state and whether the state is writable.
- Reported total and free capacity, when Android exposes it.
- Whether an app-specific writable directory is available.
- Whether user-authorized Storage Access Framework access is required.

The registry also reports the node's current app-private internal storage.

On Android 11/API 30 and newer, state changes are observed through
`StorageManager.StorageVolumeCallback`. On API 28 and 29, system media
mount/eject broadcasts are used.

## Android access models

### App-private internal storage

This is the current default PersonalCloud managed root. It is directly
accessible to the application and is not exposed to other applications.

### App-specific external storage

`Context.getExternalFilesDirs()` can provide application-owned directories
on supported stable shared-storage volumes, including physical media slots
such as SD cards. These files are removed when the app is uninstalled.
Only relative paths should be persisted because mount paths can change.

### USB OTG and other SAF-managed volumes

Transient USB flash drives are not returned by `getExternalFilesDirs()`.
Android may expose them in the storage-volume inventory, but access to their
contents requires a user-authorized Storage Access Framework document tree.

A discovered volume is not automatically readable or writable. The
`StorageVolume` mount directory is metadata and does not grant extra
filesystem permissions. Android 11+ also restricts selection of certain
storage roots through the system picker.

## Important current limitation

This change implements inventory and state monitoring only. It does not yet
make SD-card or USB-OTG storage a managed PersonalCloud destination.

The next storage-engineering stage must introduce a managed-storage backend
abstraction that supports:

- Existing app-private path storage.
- App-specific external storage selected by volume identity.
- SAF document-tree storage for USB OTG and other provider-backed volumes.
- Streaming writes, range reads, integrity verification, metadata, deletion,
  recovery snapshots, and safe behavior when a volume disappears.

Do not persist absolute mount paths or silently fall back to another volume
when a selected volume becomes unavailable. A missing selected volume must
remain unavailable until it returns or the user explicitly changes placement.


## Selectable network-managed placement

The Android node can select an active destination for network-managed incoming files:

- App-private internal storage (the default and existing location).
- Android app-specific directories exposed for mounted external volumes, including supported SD-card volumes.

Only stable volume identities are persisted: the primary external volume identity or a filesystem UUID for non-primary volumes. Absolute mount paths are resolved again on service start and are not persisted. If the selected volume is absent or read-only, service startup fails closed rather than silently redirecting files to internal storage.

The legacy local node/reference root and owner-local recovery snapshots remain app-private. Only the network-managed `distributed-storage` root is selected. Existing registered managed files pin the selected volume identity; switching it is refused while those records exist because that would otherwise hide data. A future explicit migration operation is required to move those files safely.

Android app-specific directories are removed when the app is uninstalled. External app-specific placement therefore requires a separate backup and is not equivalent to a user-owned SAF folder. The UI warns and requires explicit confirmation before selecting such a destination.

Verified incoming uploads are written to a temporary file on the selected volume, checked against the declared size and SHA-256, then moved to the final path without replacement. This avoids a hard-link requirement that is not supported by all removable filesystems.

### USB OTG limitation

Transient USB OTG volumes are not guaranteed to be exposed through `getExternalFilesDirs()`. Their user-authorized SAF document-tree backend is not yet wired into network-managed uploads. Existing SAF reference sharing remains available and is not a managed destination. No claim of USB OTG managed-write support is made by this phase.

## SAF-backed managed placement

When a user selects a writable folder through `ACTION_OPEN_DOCUMENT_TREE`, the
app stores its persistable tree URI and a SHA-256-derived identity in encrypted
configuration. The foreground peer service refuses to start on this backend if
the tree URI, read/write permissions, directory-creation capability, or selected
storage identity is unavailable. It never falls back silently to app-private
storage.

Network-managed bytes use a separate `ManagedStorageBackend` contract. The SAF
adapter creates a dedicated `PersonalCloud Managed` directory and creates each
physical file with a random opaque provider name. The logical relative path and
uploader metadata remain in the encrypted `network-storage` index. Incoming
bytes are length-checked and SHA-256 checked, then read back from the provider
and verified again before catalogue publication. On service startup, every indexed
provider object is checked for existence and a stable size. Unindexed provider objects
are deliberately preserved: loss of the app's local metadata or encryption key is not
proof that shared-storage bytes are safe to delete. Interrupted uploads can therefore
leave hidden orphan objects in the reserved folder; automatic destructive cleanup is
not performed. Existing SAF references continue to use the zero-copy
`AndroidSafReferenceStore`; the two stores are not interchangeable.

Range reads use a seekable file descriptor when the provider supports it and a
bounded stream fallback otherwise. The fallback is correct but may be slower
for ranges near the end of large provider-backed files. Provider-specific
behavior still requires physical-device validation. Deletion removes the
provider object and catalogue record; it does not claim a separate SAF undo
snapshot in this phase.

The SAF system picker does not grant unrestricted access to every directory.
On Android 11 and newer, root locations and certain system directories may be
blocked by the picker. USB OTG operation is therefore conditional on the
connected device and document provider exposing a writable, creatable folder.
