package dev.personalcloud.network;

import dev.personalcloud.core.StateStore;
import dev.personalcloud.net.Json;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Durable sender-side transfer queue. A sender-generated UUID is persisted locally before the
 * receiver session is created, closing the crash window between remote session creation and
 * saving the transfer identifier. Repeated create requests are idempotent at the receiver.
 *
 * The queue stores metadata and a source path, never file contents. Resumption re-hashes the
 * original source and fails closed if it has changed or disappeared.
 */
public final class OutboundTransferQueue {
    private static final String RECORD_TYPE = "outboundTransfer";
    private static final int MAX_RETAINED_JOBS = 500;
    private static final int MAX_AUTOMATIC_RETRIES_PER_PASS = 2;
    private static final long BASE_RETRY_MILLIS = 5_000L;
    private static final long MAX_RETRY_MILLIS = TimeUnit.HOURS.toMillis(1);

    @FunctionalInterface
    public interface EndpointResolver {
        String endpointFor(String memberId) throws Exception;
    }

    public interface TransferTransport {
        Map<String, Object> create(String endpoint, String transferId, String destinationPath,
                                   long size, String sha256, NetworkMembershipService membership) throws Exception;
        Map<String, Object> resume(String endpoint, String transferId, Path source,
                                   NetworkMembershipService membership, long maximumBytes) throws Exception;
        Map<String, Object> status(String endpoint, String transferId,
                                   NetworkMembershipService membership) throws Exception;
        Map<String, Object> abort(String endpoint, String transferId,
                                  NetworkMembershipService membership) throws Exception;
    }

    private final StateStore store;
    private final NetworkMembershipService membership;
    private final EndpointResolver endpoints;
    private final long maximumBytes;
    private final TransferTransport transport;
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public OutboundTransferQueue(StateStore store, NetworkMembershipService membership,
                                 EndpointResolver endpoints, long maximumBytes) {
        this(store, membership, endpoints, maximumBytes, new HttpTransport());
    }

    public OutboundTransferQueue(StateStore store, NetworkMembershipService membership,
                                 EndpointResolver endpoints, long maximumBytes, TransferTransport transport) {
        if (store == null || endpoints == null || transport == null || maximumBytes < 0) {
            throw new IllegalArgumentException("Outbound transfer queue dependencies are invalid.");
        }
        this.store = store;
        this.membership = membership;
        this.endpoints = endpoints;
        this.maximumBytes = maximumBytes;
        this.transport = transport;
    }

    /** Starts a durable transfer. A returned INTERRUPTED job is retained and will retry automatically. */
    public Map<String, Object> place(String memberId, String destinationPath, Path source) throws Exception {
        requireText(memberId, "Destination member ID");
        requireText(destinationPath, "Managed destination path");
        SourceSnapshot snapshot = inspectSource(source, null, null);
        String jobId = UUID.randomUUID().toString();
        Map<String, String> row = new LinkedHashMap<>();
        row.put("transferId", jobId);
        row.put("destinationNodeId", memberId);
        row.put("destinationPath", destinationPath);
        row.put("sourcePath", snapshot.path().toString());
        row.put("sourceSize", Long.toString(snapshot.size()));
        row.put("sourceSha256", snapshot.sha256());
        row.put("createdAt", Instant.now().toString());
        row.put("updatedAt", Instant.now().toString());
        row.put("status", "QUEUED");
        row.put("attemptCount", "0");
        row.put("nextAttemptAt", "0");
        row.put("lastError", "");
        row.put("receipt", "");
        pruneTerminalHistory();
        store.putRecord(RECORD_TYPE, jobId, row);
        Map<String, Object> result = attempt(jobId);
        throwIfPermanentFailure(result);
        return result;
    }

    /** Explicitly resumes one interrupted transfer, bypassing its automatic retry backoff. */
    public Map<String, Object> resume(String jobId) throws Exception {
        Map<String, Object> result = attempt(normalizeJobId(jobId));
        throwIfPermanentFailure(result);
        return result;
    }

    /** Status combines the durable local record with live receiver progress when reachable. */
    public Map<String, Object> status(String jobId) throws Exception {
        String id = normalizeJobId(jobId);
        Map<String, String> row = requireJob(id);
        Map<String, Object> result = asPublicMap(id, row);
        if (!isTerminal(row.get("status")) && !"NEEDS_ATTENTION".equals(row.get("status"))) {
            try {
                String endpoint = endpoints.endpointFor(row.get("destinationNodeId"));
                Map<String, Object> remote = transport.status(endpoint, id, membership);
                result.put("receiver", remote);
                if ("COMMITTED".equals(remote.get("state"))) {
                    markCommitted(id, row, receiptFromStatus(remote));
                    store.putRecord(RECORD_TYPE, id, row);
                    result = asPublicMap(id, row);
                    result.put("receiver", remote);
                    result.put("receipt", receiptFromStatus(remote));
                }
            } catch (Exception unavailable) {
                result.put("receiver", Map.of("state", "UNAVAILABLE", "message", safeMessage(unavailable)));
            }
        }
        return result;
    }

    /** Aborts the remote staging session; offline aborts remain queued for automatic retry. */
    public Map<String, Object> abort(String jobId) throws Exception {
        String id = normalizeJobId(jobId);
        ReentrantLock lock = lockFor(id);
        lock.lock();
        try {
            Map<String, String> row = requireJob(id);
            if ("COMPLETED".equals(row.get("status"))) throw new IllegalStateException("A completed transfer cannot be aborted.");
            if ("ABORTED".equals(row.get("status"))) return asPublicMap(id, row);
            if ("QUEUED".equals(row.get("status"))) {
                setState(row, "ABORTED", "", 0L);
                store.putRecord(RECORD_TYPE, id, row);
                return asPublicMap(id, row);
            }
            try {
                String endpoint = endpoints.endpointFor(row.get("destinationNodeId"));
                abortOrReconcile(id, row, endpoint);
            } catch (Exception unavailable) {
                recordFailure(row, "ABORT_PENDING", unavailable);
                store.putRecord(RECORD_TYPE, id, row);
            }
            return asPublicMap(id, row);
        } finally {
            lock.unlock();
        }
    }

    public List<Map<String, Object>> list() {
        List<Map<String, String>> rows = new ArrayList<>(store.records(RECORD_TYPE));
        rows.sort(Comparator.comparing((Map<String, String> row) -> row.getOrDefault("updatedAt", "")).reversed());
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : rows) result.add(asPublicMap(row.get("_id"), row));
        return List.copyOf(result);
    }

    /** Called by the node's local-control scheduler. It retries due and crash-orphaned jobs. */
    public int retryDue() {
        long now = System.currentTimeMillis();
        int attempted = 0;
        for (Map<String, String> row : store.records(RECORD_TYPE)) {
            if (attempted >= MAX_AUTOMATIC_RETRIES_PER_PASS) break;
            String status = row.get("status");
            boolean resumable = "QUEUED".equals(status) || "CREATING".equals(status)
                    || "TRANSFERRING".equals(status) || "INTERRUPTED".equals(status)
                    || "WAITING_SOURCE".equals(status) || "ABORT_PENDING".equals(status);
            if (!resumable) continue;
            // QUEUED/CREATING/TRANSFERRING with nextAttemptAt=0 are crash-orphaned
            // intermediate states. The per-job lock prevents the periodic scheduler from
            // duplicating a live transfer in this process.
            long due = parseLong(row.get("nextAttemptAt"), Long.MAX_VALUE);
            if (due > now) continue;
            String id = row.get("_id");
            ReentrantLock lock = lockFor(id);
            if (!lock.tryLock()) continue;
            try {
                Map<String, String> current = requireJob(id);
                if ("ABORT_PENDING".equals(current.get("status"))) retryAbort(id, current);
                else attemptLocked(id, current);
                attempted++;
            } catch (Exception failure) {
                // Every retry path persists its own result. A malformed record should not stop
                // independent transfers from being retried on the next scheduler pass.
                attempted++;
            } finally {
                lock.unlock();
            }
        }
        return attempted;
    }

    private Map<String, Object> attempt(String id) throws Exception {
        ReentrantLock lock = lockFor(id);
        lock.lock();
        try { return attemptLocked(id, requireJob(id)); }
        finally { lock.unlock(); }
    }

    private Map<String, Object> attemptLocked(String id, Map<String, String> row) throws Exception {
        String state = row.getOrDefault("status", "");
        if ("COMPLETED".equals(state) || "ABORTED".equals(state)) return asPublicMap(id, row);
        // NEEDS_ATTENTION jobs are excluded from automatic retry, but an explicit manual
        // resume revalidates the original digest and may proceed if the exact original source
        // has been restored.
        try {
            SourceSnapshot source = inspectSource(Path.of(row.get("sourcePath")),
                    parseLong(row.get("sourceSize"), -1), row.get("sourceSha256"));
            String endpoint = endpoints.endpointFor(row.get("destinationNodeId"));
            setState(row, "CREATING", "", 0L);
            store.putRecord(RECORD_TYPE, id, row);
            // Safe to repeat after a crash: the receiver checks uploader, target path, size and hash.
            transport.create(endpoint, id, row.get("destinationPath"), source.size(), source.sha256(), membership);
            setState(row, "TRANSFERRING", "", 0L);
            store.putRecord(RECORD_TYPE, id, row);
            Map<String, Object> receipt = transport.resume(endpoint, id, source.path(), membership, maximumBytes);
            row.put("receipt", Json.stringify(receipt));
            row.put("destinationFileId", String.valueOf(receipt.getOrDefault("fileId", "")));
            setState(row, "COMPLETED", "", 0L);
            row.put("nextAttemptAt", "0");
            store.putRecord(RECORD_TYPE, id, row);
            Map<String, Object> result = asPublicMap(id, row);
            result.put("receipt", receipt);
            return result;
        } catch (SourceChangedException changed) {
            setState(row, "NEEDS_ATTENTION", safeMessage(changed), 0L);
            store.putRecord(RECORD_TYPE, id, row);
            return asPublicMap(id, row);
        } catch (SourceUnavailableException unavailable) {
            recordFailure(row, "WAITING_SOURCE", unavailable);
            store.putRecord(RECORD_TYPE, id, row);
            return asPublicMap(id, row);
        } catch (Exception failure) {
            if (isPermanentFailure(failure)) {
                // Destination/path/authorization conflicts cannot improve with time. Release any
                // receiver staging reservation and expose the original failure to the caller.
                try {
                    String endpoint = endpoints.endpointFor(row.get("destinationNodeId"));
                    transport.abort(endpoint, id, membership);
                } catch (Exception cleanupFailure) {
                    // Receiver sessions have a bounded seven-day TTL if immediate cleanup is unavailable.
                }
                setState(row, "FAILED", safeMessage(failure), 0L);
            } else {
                recordFailure(row, "INTERRUPTED", failure);
            }
            store.putRecord(RECORD_TYPE, id, row);
            return asPublicMap(id, row);
        }
    }

    private void retryAbort(String id, Map<String, String> row) throws Exception {
        try {
            String endpoint = endpoints.endpointFor(row.get("destinationNodeId"));
            abortOrReconcile(id, row, endpoint);
        } catch (Exception unavailable) {
            recordFailure(row, "ABORT_PENDING", unavailable);
            store.putRecord(RECORD_TYPE, id, row);
        }
    }

    private void abortOrReconcile(String id, Map<String, String> row, String endpoint) throws Exception {
        try {
            Map<String,Object> remote = transport.status(endpoint, id, membership);
            if ("COMMITTED".equals(remote.get("state"))) {
                markCommitted(id, row, receiptFromStatus(remote));
                store.putRecord(RECORD_TYPE, id, row);
                return;
            }
        } catch (Exception statusFailure) {
            if (isMissingSession(statusFailure)) {
                setState(row, "ABORTED", "", 0L);
                store.putRecord(RECORD_TYPE, id, row);
                return;
            }
            // Status may be transiently unavailable; still attempt the authenticated abort.
        }
        try {
            transport.abort(endpoint, id, membership);
            setState(row, "ABORTED", "", 0L);
        } catch (Exception failure) {
            if (isMissingSession(failure)) setState(row, "ABORTED", "", 0L);
            else recordFailure(row, "ABORT_PENDING", failure);
        }
        store.putRecord(RECORD_TYPE, id, row);
    }

    private void markCommitted(String id, Map<String,String> row, Map<String,Object> receipt) {
        row.put("receipt", Json.stringify(receipt));
        row.put("destinationFileId", String.valueOf(receipt.getOrDefault("fileId", "")));
        setState(row, "COMPLETED", "", 0L);
    }

    private static Map<String,Object> receiptFromStatus(Map<String,Object> remote) {
        Object value = remote.get("receipt");
        if (!(value instanceof Map<?,?> map)) throw new SecurityException("Receiver reports COMMITTED without a durable receipt.");
        Map<String,Object> receipt = new LinkedHashMap<>();
        for (Map.Entry<?,?> entry : map.entrySet()) {
            if (entry.getKey() instanceof String key) receipt.put(key, entry.getValue());
        }
        receipt.put("transferId", remote.getOrDefault("transferId", ""));
        receipt.put("transferState", "COMMITTED");
        return receipt;
    }

    private static boolean isMissingSession(Exception failure) {
        String message = safeMessage(failure).toUpperCase(java.util.Locale.ROOT);
        return message.contains("HTTP 404") || message.contains("TRANSFER SESSION NOT FOUND")
                || message.contains("TRANSFER SESSION EXPIRED");
    }

    private static void setState(Map<String, String> row, String status, String error, long nextAttemptAt) {
        row.put("status", status);
        row.put("lastError", error == null ? "" : error);
        row.put("updatedAt", Instant.now().toString());
        row.put("nextAttemptAt", Long.toString(nextAttemptAt));
    }

    private static void recordFailure(Map<String, String> row, String status, Exception failure) {
        long attempts = parseLong(row.get("attemptCount"), 0) + 1;
        long exponent = Math.min(10, attempts - 1);
        long delay = Math.min(MAX_RETRY_MILLIS, BASE_RETRY_MILLIS * (1L << exponent));
        row.put("attemptCount", Long.toString(attempts));
        row.put("lastAttemptAt", Instant.now().toString());
        setState(row, status, safeMessage(failure), System.currentTimeMillis() + delay);
    }

    private SourceSnapshot inspectSource(Path requested, Long expectedSize, String expectedHash) throws Exception {
        if (requested == null) throw new SourceUnavailableException("The original source path is not currently available.");
        Path absolute = requested.toAbsolutePath().normalize();
        if (Files.notExists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new SourceUnavailableException("The original source file is temporarily unavailable; reconnect its storage to resume.");
        }
        if (Files.isSymbolicLink(absolute) || !Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new SourceChangedException("The original transfer source is no longer a regular non-symlink file.");
        }
        Path file = absolute.toRealPath();
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || Files.isSymbolicLink(file)) throw new SourceChangedException("The original transfer source is not a regular file.");
        if (before.size() > maximumBytes) throw new SourceChangedException("The original source now exceeds this node's configured transfer limit.");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[256 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        BasicFileAttributes after = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
                || !String.valueOf(before.fileKey()).equals(String.valueOf(after.fileKey()))) {
            throw new SourceChangedException("The source changed while PersonalCloud was verifying it.");
        }
        String hash = HexFormat.of().formatHex(digest.digest());
        if (expectedSize != null && expectedSize.longValue() != after.size()) {
            throw new SourceChangedException("The original source size changed; the transfer was not resumed.");
        }
        if (expectedHash != null && !expectedHash.equals(hash)) {
            throw new SourceChangedException("The original source SHA-256 changed; the transfer was not resumed.");
        }
        return new SourceSnapshot(file, after.size(), hash);
    }

    private void pruneTerminalHistory() throws Exception {
        List<Map<String, String>> rows = new ArrayList<>(store.records(RECORD_TYPE));
        if (rows.size() < MAX_RETAINED_JOBS) return;
        rows.sort(Comparator.comparing(row -> row.getOrDefault("updatedAt", "")));
        int excess = rows.size() - MAX_RETAINED_JOBS + 1;
        for (Map<String, String> row : rows) {
            if (excess <= 0) break;
            if (!isTerminal(row.get("status")) && !"NEEDS_ATTENTION".equals(row.get("status"))) continue;
            store.removeRecord(RECORD_TYPE, row.get("_id"));
            excess--;
        }
        if (excess > 0) throw new IllegalStateException("The outbound transfer history is full of active jobs; abort or complete a transfer before starting another.");
    }

    private Map<String, String> requireJob(String id) {
        Map<String, String> row = store.getRecord(RECORD_TYPE, id);
        if (row == null) throw new IllegalArgumentException("Outbound transfer job was not found: " + id);
        return new LinkedHashMap<>(row);
    }

    private static Map<String, Object> asPublicMap(String id, Map<String, String> row) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("jobId", id);
        result.put("transferId", row.getOrDefault("transferId", id));
        result.put("status", row.getOrDefault("status", "UNKNOWN"));
        result.put("destinationNodeId", row.getOrDefault("destinationNodeId", ""));
        result.put("destinationPath", row.getOrDefault("destinationPath", ""));
        result.put("sourcePath", row.getOrDefault("sourcePath", ""));
        result.put("sourceSize", parseLong(row.get("sourceSize"), 0));
        result.put("sourceSha256", row.getOrDefault("sourceSha256", ""));
        result.put("attemptCount", parseLong(row.get("attemptCount"), 0));
        result.put("createdAt", row.getOrDefault("createdAt", ""));
        result.put("updatedAt", row.getOrDefault("updatedAt", ""));
        result.put("nextAttemptAt", parseLong(row.get("nextAttemptAt"), 0));
        result.put("lastError", row.getOrDefault("lastError", ""));
        result.put("destinationFileId", row.getOrDefault("destinationFileId", ""));
        // Preserve the existing managed.place receipt shape for callers while exposing the queue job.
        result.put("fileId", row.getOrDefault("destinationFileId", ""));
        result.put("size", parseLong(row.get("sourceSize"), 0));
        result.put("sha256", row.getOrDefault("sourceSha256", ""));
        if ("COMPLETED".equals(row.get("status"))) result.put("transferState", "COMMITTED");
        return result;
    }

    private ReentrantLock lockFor(String id) { return locks.computeIfAbsent(id, ignored -> new ReentrantLock(true)); }

    private static boolean isTerminal(String state) {
        return "COMPLETED".equals(state) || "ABORTED".equals(state) || "FAILED".equals(state);
    }

    private static boolean isPermanentFailure(Exception failure) {
        if (failure instanceof IllegalArgumentException || failure instanceof SecurityException) return true;
        String message = safeMessage(failure).toUpperCase(java.util.Locale.ROOT);
        return message.contains("HTTP 400") || message.contains("HTTP 401") || message.contains("HTTP 403")
                || message.contains("HTTP 404") || message.contains("HTTP 409") || message.contains("HTTP 422")
                || message.contains("DESTINATION ALREADY EXISTS") || message.contains("OVERWRITE");
    }

    private static void throwIfPermanentFailure(Map<String, Object> result) throws java.io.IOException {
        if ("FAILED".equals(result.get("status"))) {
            throw new java.io.IOException(String.valueOf(result.getOrDefault("lastError", "Managed transfer failed.")));
        }
    }

    private static String normalizeJobId(String id) {
        try {
            String normalized = UUID.fromString(id).toString();
            if (!normalized.equalsIgnoreCase(id)) throw new IllegalArgumentException();
            return normalized;
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("Transfer job ID must be a canonical UUID.", invalid);
        }
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank() || value.length() > 2048) throw new IllegalArgumentException(label + " is required.");
    }

    private static long parseLong(String value, long fallback) {
        try { return Long.parseLong(value); } catch (Exception invalid) { return fallback; }
    }

    private static String safeMessage(Exception failure) {
        String message = failure.getMessage();
        if (message == null || message.isBlank()) return failure.getClass().getSimpleName();
        return message.length() > 500 ? message.substring(0, 500) : message;
    }

    private record SourceSnapshot(Path path, long size, String sha256) { }

    private static final class SourceChangedException extends Exception {
        private SourceChangedException(String message) { super(message); }
    }

    private static final class SourceUnavailableException extends Exception {
        private SourceUnavailableException(String message) { super(message); }
    }

    private static final class HttpTransport implements TransferTransport {
        @Override public Map<String, Object> create(String endpoint, String transferId, String destinationPath,
                                                    long size, String sha256, NetworkMembershipService membership) throws Exception {
            return new NetworkPeerClient().createManagedTransfer(endpoint, transferId, destinationPath, size, sha256, membership);
        }
        @Override public Map<String, Object> resume(String endpoint, String transferId, Path source,
                                                    NetworkMembershipService membership, long maximumBytes) throws Exception {
            return new NetworkPeerClient().resumeManagedFile(endpoint, transferId, source, membership, maximumBytes);
        }
        @Override public Map<String, Object> status(String endpoint, String transferId,
                                                    NetworkMembershipService membership) throws Exception {
            return new NetworkPeerClient().transferStatus(endpoint, transferId, membership);
        }
        @Override public Map<String, Object> abort(String endpoint, String transferId,
                                                   NetworkMembershipService membership) throws Exception {
            return new NetworkPeerClient().abortTransfer(endpoint, transferId, membership);
        }
    }
}
