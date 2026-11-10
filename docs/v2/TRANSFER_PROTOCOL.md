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
- Sessions expire after seven days. Active sessions are limited by count and aggregate/per-member staging reservation. The default caps are 16 sessions per node and 4 per uploader (`PERSONALCLOUD_MAX_TRANSFER_SESSIONS`, `PERSONALCLOUD_MAX_TRANSFER_SESSIONS_PER_MEMBER`); aggregate and per-member staging default to twice `PERSONALCLOUD_MAX_FILE_BYTES` and can be overridden with `PERSONALCLOUD_MAX_TRANSFER_STAGING_BYTES` and `PERSONALCLOUD_MAX_TRANSFER_STAGING_BYTES_PER_MEMBER`.
- The receiver hashes chunks in one pass and then streams them sequentially into the managed-storage commit path. It does not build a second complete assembly copy.

## Current limits and caveats

- Default chunk size: 4 MiB (receiver-advertised in session status).
- Desktop maximum file size follows `PERSONALCLOUD_MAX_FILE_BYTES`; Android managed storage retains its 20 GiB limit.
- Quota rejection is a deliberate `409 Conflict`, not a transient network failure. An interrupted sender should free or abort other sessions before retrying.
- Direct reachability remains subject to IPv6, port forwarding, NAT and firewall conditions. This protocol does not add relay fallback.
- The legacy whole-file `PUT /network/managed/files` route remains available for compatibility; new clients use the resumable protocol.
- Client applications must retain the transfer ID when a transfer is interrupted to resume it later. The desktop client exposes the ID through `RemoteTransferInterruptedException`; Android's connector reports it in the interruption exception message and exposes a resume API.

## Sender-side durability and commit replay

The sender must persist a UUID, destination member, normalized destination path, source locator, source size, and SHA-256 before its first network request. Retrying `POST /network/transfers` with the same UUID and metadata is idempotent; rebinding that UUID to different metadata is rejected. Each retry reopens the source and verifies size and full digest before transmitting only the receiver's missing chunks.

After commit, the receiver stores a seven-day metadata-only tombstone containing the committed receipt. `GET` status, replayed `POST` create, and replayed `POST` commit return the durable receipt. `DELETE` cannot change a committed session to aborted. The tombstone is separate from staged chunk storage and is excluded from active-session and reserved-byte quotas. This protects against process death or lost HTTP responses on either side of publication.

The desktop queue is exposed through the local control CLI (`managed transfers`, `managed transfer-status`, `managed resume`, and `managed abort`). The Android foreground peer service owns an encrypted persistent queue, reopens SAF documents through persisted read grants, retries eligible jobs on a bounded schedule, and exposes queue, resume, and abort actions in the Android app. Android jobs preserve only the content URI and digest metadata, never a duplicate local copy of source bytes.

## Three-peer coordinated transfers

A coordinator Z can initiate a COPY or MOVE from source X to destination Y without handling file bytes. The data path remains X → Y. Z exchanges signed metadata and status only; it never opens the source file, creates a receiver session, stages chunks or receives content.

### Ticket

Z signs a canonical ticket with its active membership Ed25519 key. The ticket binds:

- ticket, request and transfer UUIDs;
- issuer, source and destination node IDs;
- source and destination eligible-root IDs and normalized relative paths;
- operation (`COPY` or `MOVE`), overwrite intent;
- source size, full-file SHA-256 and source version;
- optional source and destination approval IDs;
- issue time and expiry.

Tickets are metadata-only. The canonical JSON field order is stable, so the signature covers every bound value. X and Y verify the signature against the issuer's current active membership key and independently enforce membership, role and expiry checks. The default lifetime is 600 seconds and the maximum is 3600 seconds; tickets issued more than 120 seconds in the future or outside their lifetime are rejected.

Each receiving role durably claims a ticket ID against one transfer identity and request identity. Replaying the same ticket with the same transfer identity is idempotent and resumes or returns the existing result. Reusing the ticket ID with a different transfer identity, request identity or signed body is rejected.

### Endpoints

- `GET /network/coordinated/metadata?role=source|destination&rootId=...&path=...` returns metadata only. The source role reports type, size, digest and version; the destination role reports existence, type and overwrite requirements. PRIVATE paths are hidden and PROTECTED paths report that approval is required.
- `POST /network/coordinated/transfers` on X accepts `{ticket, ticketSignature}`. The authenticated requester must be the ticket issuer, the ticket must be bound to X, and the destination must be an active member. X authorizes its own source resource, claims the ticket for the source role, creates the destination receiver session, and streams chunks directly to Y.
- `POST /network/transfers` on Y with `kind: "coordinated"` accepts `{transferId, ticket, ticketSignature}`. Y verifies the ticket, requires the uploader to be the ticket source and Y to be the ticket destination, claims the ticket for the destination role, authorizes the write, and creates a normal resumable receiver session.
- `GET /network/coordinated/transfers/{requestId}` on X returns the source job's metadata-only state and, while non-terminal, destination progress. The authenticated requester must be the ticket issuer.

Chunk upload, status, commit and abort continue to use the standard resumable transfer endpoints between X and Y. The destination session is bound to the source device as uploader, so the coordinator cannot upload chunks even if it learns the transfer ID.

### Execution and MOVE ordering

The source job is durable and keyed by the ticket request UUID. States are `TRANSFERRING`, `COPIED`, `DELETING`, `MOVED`, `COPIED_NOT_MOVED`, `RETRYABLE` and `FAILED`.

For a MOVE, X performs this order:

1. Verify the ticket, membership, destination activity and source policy/approval.
2. Revalidate the source size, digest and version at authorization time.
3. Create the destination session and transfer chunks directly to Y.
4. Receive the destination's verified commit receipt.
5. Revalidate that the source is unchanged since the ticket was issued.
6. Persist `DELETING` with the verified receipt.
7. Delete the source only after destination commit and source revalidation.
8. Report `MOVED`. If deletion fails, report `COPIED_NOT_MOVED` and keep the destination receipt.

A retry of a `DELETING` or `COPIED_NOT_MOVED` job retries the idempotent source deletion and reconciles the terminal state. A crash before deletion therefore cannot lose the only copy, and a crash after deletion converges to `MOVED` without retransferring bytes.

COPY uses a source `READ` decision. MOVE uses a source `MOVE` decision. Destination creation uses `CREATE`, and overwriting an existing destination uses `WRITE`. Protected operations require an owner approval obtained independently at the owning device; the approval ID is carried in the signed ticket and bound to the ticket ID. Revoked source, destination or coordinator members are rejected.

### Coordinator state

The coordinator persists one durable request record per coordination request, including the signed ticket, state and metadata-only result. `retry` re-invokes the same ticket; terminal results are returned unchanged. The coordinator status view exposes the source job state, destination progress when available and the committed receipt, never file content.

### Limits and caveats

- Coordinated transfers are exposed through the desktop local-control socket and CLI (`coordinated plan`, `prepare`, `transfer`, `status`, `retry`, `list`). Android UI integration is not yet implemented.
- Protection approvals remain process-local; a restart fails closed and requires fresh approvals.
- Coordination assumes the source and destination are directly reachable from each other. No relay or coordinator-assisted fallback is introduced.
- Ticket claims, source jobs and coordinator requests are node-local durable state; clock skew beyond 120 seconds between devices fails closed.
