# PersonalCloud V2 product scope

## Product statement

A private, direct-connected network of personally operated devices. Every enrolled device is an independent node and retains ownership of its own files and physical storage. Other nodes can discover and access files only when explicitly authorized.

## Included product principles

- Devices are peers; no central file-storage server.
- A node is reachable/online or unavailable/offline. Files owned only by an offline node remain visible as metadata where cached but cannot be read.
- Whole-file ownership and manual destination selection.
- Existing directories can be referenced in place with zero-copy registration.
- New files can be placed on a selected network device through a direct authenticated transfer. Transfers use durable, resumable chunks and final SHA-256 verification; bytes never pass through a central storage service.
- New desktop network members prove the shared network credentials and require explicit approval by an existing online member.
- Each device has an independent cryptographic identity; a shared private key is never distributed.
- `DOWNLOAD` and `DOWNLOAD+DELETE` are the intended file permissions.
- Peer traffic is encrypted and authenticated.
- No mandatory application-level at-rest encryption; host OS encryption is recommended.
- No automatic replication, sync, block striping, relay or third-party cloud storage in the initial scope.
- Device-oriented browsing plus network-wide metadata search.
- Ultra-minimal native OS integration; no large browser dashboard.
- Java-only application and integration code.

## Out of scope for initial scoped foundation

- Automatic synchronization and conflict resolution.
- Replication or availability coding.
- Block-level distribution/erasure coding.
- Relay servers.
- Multi-user/family sharing or public discovery.
- A central file-content service.
- Mandatory application-level file encryption at rest.

## Reference vs managed file

A referenced file remains in its existing directory. PersonalCloud stores only a directory reference and reads the file from its owner when requested. It is not automatically moved into the managed pool.

A managed file is owned by PersonalCloud storage on a specific node. The user chooses a destination member and the source transfers the whole file directly to that node. The destination verifies the expected size and SHA-256 before committing it. An existing destination is never overwritten.

## Permissions

A `DOWNLOAD` grant permits browsing/stat/ranged read/download but not deletion. A `DOWNLOAD+DELETE` grant additionally permits deletion of the selected original. The owning node creates a recovery snapshot before a supported deletion. Revoking a grant removes future access; it cannot retract bytes already downloaded by an authorized peer.

## Key non-functional requirements

- No file contents pass through a central storage service.
- All non-loopback peer connections use authenticated TLS.
- Local control interfaces are not network-exposed.
- File downloads verify size and SHA-256 before finalizing.
- File and directory operations reject unsafe paths and symbolic links where relevant.
- Offline nodes are clearly marked unavailable; cached metadata is never represented as live content.
- Local data and identity survive source-code upgrades.
- Each subsystem has repeatable automated tests.
