# PersonalCloud architecture notes

## Node model

Every installed/running PersonalCloud instance is a node. A node has its own:

- stable node ID;
- admin dashboard password;
- storage root and file index;
- incoming peer trust records;
- outgoing peer connection records;
- per-file, per-peer access grants.

A node can request remote files and can serve files that it owns. Pairing is directional. If B submits A's pairing code, A records B as a trusted incoming peer and B stores a token for making authenticated requests to A. Pairing in the opposite direction enables the reverse file-access direction.

## Trust and grant flow

1. The owner node generates a random, single-use pairing code with a 10-minute expiry.
2. The receiving node submits its node ID, name, and code to the owner's `/node/pair` endpoint.
3. The owner consumes the code, creates a random 256-bit peer token, and stores only its SHA-256 hash against the receiving node ID.
4. The receiving node stores the peer URL and the returned token locally.
5. The owner grants a particular relative file path to that peer with `VIEW` or `MODIFY` permission.
6. The receiving node authenticates to the owner with the peer token. The owner resolves the share ID to a grant for that exact peer ID before listing, streaming, or deleting anything.

The node API does not accept arbitrary filesystem paths from a peer. Peers request opaque share IDs. The owner resolves those IDs to its own stored relative paths.

## Request paths

- Browser → local node: HTTP Basic authentication protects the dashboard and management API.
- Node → node: a per-peer Bearer token authenticates the remote node API.
- File data: the owner opens the original file and streams bytes over the peer connection. The receiver does not need a copy until a user downloads it.

Remote download currently streams from the source node to the receiving node's HTTP client, then to the browser connected to that receiving node. There is no third-party storage or central file relay.

## Storage model

The index is computed from the storage root using `Files.walk`. Only regular files are indexed. Symbolic links are skipped. `FileIndexer` creates `FileMetadata` values; `FileService` is the guarded path-resolution and streaming boundary.

Node IDs, incoming token hashes, outgoing peer tokens, and grants are persisted in a local `Properties` file under the data directory. Writes use a temporary file followed by an atomic replacement where supported. On POSIX systems, secret/state files and the data directory are restricted to the current user.

This is intentionally a small persistence layer for the MVP. SQLite and migrations should replace it before the state model grows substantially.

## Security boundaries and known gaps

- Admin credentials and peer tokens travel over plain HTTP in this build. Use only a trusted LAN or a VPN. Do not publish the port to the public internet.
- A trusted peer can only see grants addressed to its own node ID. A `VIEW` peer cannot use the delete endpoint. `MODIFY` can delete the owner's original file.
- File path normalization, storage-root containment checks, real-path containment checks, and no-follow regular-file checks reduce path traversal and symlink escape risk. They do not replace OS-level isolation or eliminate all local filesystem race conditions.
- The pairing endpoint is public by design, but requires a random, single-use, short-lived code. Production should add rate limiting and abuse monitoring.
- There is no NAT traversal, relay, automatic discovery, Android background agent, HTTPS server, resumable transfer, malware scanning, or audit trail in this build.
