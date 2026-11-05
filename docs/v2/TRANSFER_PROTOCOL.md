# PersonalCloud direct resumable transfer protocol

## Purpose

Transfer a whole file directly from one authenticated member to another without a central file-content service or an intermediate cloud. The source remains the source of truth until the receiver verifies and publishes the complete file.

## Lifecycle

1. `POST /network/transfers` creates a receiver-side session bound to the authenticated uploader node ID, relative destination path, declared size and full-file SHA-256.
2. `PUT /network/transfers/{id}/chunks/{index}` sends a bounded chunk (default 4 MiB). The request signature covers the session ID, index, byte length and chunk SHA-256. The receiver independently hashes the bytes before atomically publishing the chunk.
3. `GET /network/transfers/{id}` returns received chunk indexes and byte progress. A client reconnects, reads this status and sends only missing chunks.
4. `POST /network/transfers/{id}/commit` checks that every expected chunk exists, verifies the complete size and SHA-256, and streams the verified chunk sequence to the platform managed-storage commit boundary.
5. `DELETE /network/transfers/{id}` aborts a session owned by the authenticated uploader.

## Invariants

- Every endpoint requires an active network-member signature. Session operations are additionally bound to the uploader identity that created the session.
- Chunk indexes are zero-based and each chunk has its expected fixed range; only the final chunk may be shorter.
- A duplicate chunk is accepted only if the persisted chunk has the same expected length and SHA-256.
- A chunk is published with create-if-absent semantics. A retry cannot replace previously accepted bytes.
- Session journals and chunk files live under a node-local transfer directory. The receiver persists verified progress and re-discovers chunks after restart.
- Full-file SHA-256 is checked before invoking the managed-storage publication path.
- The commit callback receives the stable transfer ID. Managed storage records that ID so a retry after a crash between file publication and session cleanup returns the already committed file rather than creating a duplicate or failing on its own destination.
- Publication retains the existing no-overwrite guarantee.
- Sessions expire after seven days. Active sessions are limited by count and aggregate staging reservation.
- The receiver hashes chunks in one pass and then streams them sequentially into the managed-storage commit path. It does not build a second complete assembly copy.

## Current limits and caveats

- Default chunk size: 4 MiB (receiver-advertised in session status).
- Desktop maximum file size follows `PERSONALCLOUD_MAX_FILE_BYTES`; Android managed storage retains its 20 GiB limit.
- Direct reachability remains subject to IPv6, port forwarding, NAT and firewall conditions. This protocol does not add relay fallback.
- The legacy whole-file `PUT /network/managed/files` route remains available for compatibility; new clients use the resumable protocol.
- Client applications must retain the transfer ID when a transfer is interrupted to resume it later. The desktop client exposes the ID through `RemoteTransferInterruptedException`; Android's connector reports it in the interruption exception message and exposes a resume API.

## Sender-side durability and commit replay

The sender must persist a UUID, destination member, normalized destination path, source locator, source size, and SHA-256 before its first network request. Retrying `POST /network/transfers` with the same UUID and metadata is idempotent; rebinding that UUID to different metadata is rejected. Each retry reopens the source and verifies size and full digest before transmitting only the receiver's missing chunks.

After commit, the receiver stores a seven-day metadata-only tombstone containing the committed receipt. `GET` status, replayed `POST` create, and replayed `POST` commit return the durable receipt. `DELETE` cannot change a committed session to aborted. The tombstone is separate from staged chunk storage and is excluded from active-session and reserved-byte quotas. This protects against process death or lost HTTP responses on either side of publication.

The desktop queue is exposed through the local control CLI (`managed transfers`, `managed transfer-status`, `managed resume`, and `managed abort`). The Android foreground peer service owns an encrypted persistent queue, reopens SAF documents through persisted read grants, retries eligible jobs on a bounded schedule, and exposes queue, resume, and abort actions in the Android app. Android jobs preserve only the content URI and digest metadata, never a duplicate local copy of source bytes.
