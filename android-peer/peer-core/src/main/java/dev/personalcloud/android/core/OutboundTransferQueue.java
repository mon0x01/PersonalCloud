package dev.personalcloud.android.core;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
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
 * Encrypted, durable Android sender queue. The source locator is stored in the Android
 * Keystore-backed StateStore domain; source bytes are always reopened from their provider.
 * A sender-generated UUID is persisted before the destination session is created, so a
 * process death at any point can safely replay the same transfer.
 */
public final class OutboundTransferQueue {
    private static final String DOMAIN = "outbound_transfers";
    private static final int MAX_RETAINED_JOBS = 500;
    private static final int MAX_AUTOMATIC_RETRIES_PER_PASS = 2;
    private static final long BASE_RETRY_MILLIS = 5_000L;
    private static final long MAX_RETRY_MILLIS = TimeUnit.HOURS.toMillis(1);
    private static final ReentrantLock STORE_LOCK = new ReentrantLock(true);
    private static final ConcurrentHashMap<String, ReentrantLock> JOB_LOCKS = new ConcurrentHashMap<>();

    @FunctionalInterface public interface EndpointResolver {
        String endpointFor(String memberId) throws Exception;
    }
    @FunctionalInterface public interface SourceResolver {
        PeerConnector.InputStreamSource open(String locator) throws Exception;
    }
    public interface TransferTransport {
        Map<String,Object> create(String endpoint, String transferId, String destinationPath,
                                  long size, String sha256) throws Exception;
        Map<String,Object> resume(String endpoint, String transferId,
                                  PeerConnector.InputStreamSource source, long size) throws Exception;
        Map<String,Object> status(String endpoint, String transferId) throws Exception;
        Map<String,Object> abort(String endpoint, String transferId) throws Exception;
    }

    private final StateStore store;
    private final EndpointResolver endpoints;
    private final SourceResolver sources;
    private final TransferTransport transport;
    private final long maximumBytes;

    public OutboundTransferQueue(StateStore store, EndpointResolver endpoints, SourceResolver sources,
                                 TransferTransport transport, long maximumBytes) {
        if (store == null || endpoints == null || sources == null || transport == null || maximumBytes < 0) {
            throw new IllegalArgumentException("Android outbound queue dependencies are invalid.");
        }
        this.store = store;
        this.endpoints = endpoints;
        this.sources = sources;
        this.transport = transport;
        this.maximumBytes = maximumBytes;
    }

    /** Persists the transfer ID and source metadata before making any network request. */
    public Map<String,Object> place(String memberId, String destinationPath, String sourceLocator) throws Exception {
        requireText(memberId, "Destination member ID");
        requireText(destinationPath, "Managed destination path");
        requireText(sourceLocator, "Android source URI");
        SourceSnapshot snapshot = inspectSource(sourceLocator, null, null);
        String id = UUID.randomUUID().toString();
        Map<String,Object> row = new LinkedHashMap<>();
        row.put("destinationNodeId", memberId);
        row.put("destinationPath", destinationPath);
        row.put("sourceLocator", sourceLocator);
        row.put("sourceSize", snapshot.size());
        row.put("sourceSha256", snapshot.sha256());
        row.put("createdAt", Instant.now().toString());
        row.put("updatedAt", Instant.now().toString());
        row.put("status", "QUEUED");
        row.put("attemptCount", 0L);
        row.put("nextAttemptAt", 0L);
        row.put("lastError", "");
        row.put("destinationFileId", "");
        row.put("receipt", Map.of());
        pruneTerminalHistory();
        saveJob(id, row);
        Map<String,Object> result = attempt(id);
        throwIfPermanentFailure(result);
        return result;
    }

    /** Manual retry bypasses backoff; NEEDS_ATTENTION is revalidated against the original digest. */
    public Map<String,Object> resume(String jobId) throws Exception {
        return attempt(normalizeJobId(jobId));
    }

    /** Reconciles a local interrupted state with the receiver's durable commit receipt. */
    public Map<String,Object> status(String jobId) throws Exception {
        String id = normalizeJobId(jobId);
        Map<String,Object> row = requireJob(id);
        Map<String,Object> result = asPublicMap(id, row);
        if (!isTerminal(string(row.get("status")))) {
            try {
                String endpoint = endpoints.endpointFor(string(row.get("destinationNodeId")));
                Map<String,Object> remote = transport.status(endpoint, id);
                result.put("receiver", remote);
                if ("COMMITTED".equals(remote.get("state"))) {
                    markCommitted(row, receiptFromStatus(remote));
                    saveJob(id, row);
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

    public Map<String,Object> abort(String jobId) throws Exception {
        String id = normalizeJobId(jobId);
        ReentrantLock lock = lockFor(id);
        lock.lock();
        try {
            Map<String,Object> row = requireJob(id);
            String state = string(row.get("status"));
            if ("COMPLETED".equals(state)) throw new IllegalStateException("A completed transfer cannot be aborted.");
            if ("ABORTED".equals(state)) return asPublicMap(id, row);
            if ("QUEUED".equals(state)) {
                setState(row, "ABORTED", "", 0L);
                saveJob(id, row);
                return asPublicMap(id, row);
            }
            try {
                abortOrReconcile(id, row, endpoints.endpointFor(string(row.get("destinationNodeId"))));
            } catch (Exception unavailable) {
                recordFailure(row, "ABORT_PENDING", unavailable);
                saveJob(id, row);
            }
            return asPublicMap(id, row);
        } finally {
            lock.unlock();
        }
    }

    public List<Map<String,Object>> list() throws Exception {
        Map<String,Map<String,Object>> rows = loadJobs();
        List<Map.Entry<String,Map<String,Object>>> entries = new ArrayList<>(rows.entrySet());
        entries.sort(Comparator.comparing((Map.Entry<String,Map<String,Object>> entry) ->
                string(entry.getValue().get("updatedAt"))).reversed());
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map.Entry<String,Map<String,Object>> entry : entries) result.add(asPublicMap(entry.getKey(), entry.getValue()));
        return List.copyOf(result);
    }

    /** Used by the service scheduler. Active rows are serialized by per-job locks. */
    public int retryDue() throws Exception {
        int attempted = 0;
        long now = System.currentTimeMillis();
        for (Map.Entry<String,Map<String,Object>> entry : loadJobs().entrySet()) {
            if (attempted >= MAX_AUTOMATIC_RETRIES_PER_PASS) break;
            Map<String,Object> snapshot = entry.getValue();
            String state = string(snapshot.get("status"));
            if (!isRetryable(state) || number(snapshot.get("nextAttemptAt"), Long.MAX_VALUE) > now) continue;
            String id = entry.getKey();
            ReentrantLock lock = lockFor(id);
            if (!lock.tryLock()) continue;
            try {
                Map<String,Object> current = requireJob(id);
                if (!isRetryable(string(current.get("status")))
                        || number(current.get("nextAttemptAt"), Long.MAX_VALUE) > System.currentTimeMillis()) continue;
                if ("ABORT_PENDING".equals(current.get("status"))) {
                    try { abortOrReconcile(id, current, endpoints.endpointFor(string(current.get("destinationNodeId")))); }
                    catch (Exception failure) { recordFailure(current, "ABORT_PENDING", failure); saveJob(id, current); }
                } else {
                    attemptLocked(id, current);
                }
                attempted++;
            } catch (Exception failure) {
                attempted++;
            } finally {
                lock.unlock();
            }
        }
        return attempted;
    }

    /** Retain a persisted SAF permission while any nonterminal job still references its URI. */
    public boolean hasActiveSource(String sourceLocator) throws Exception {
        for (Map<String,Object> row : loadJobs().values()) {
            if (sourceLocator.equals(string(row.get("sourceLocator")))
                    && !isTerminal(string(row.get("status")))) return true;
        }
        return false;
    }

    private Map<String,Object> attempt(String id) throws Exception {
        ReentrantLock lock = lockFor(id);
        lock.lock();
        try { return attemptLocked(id, requireJob(id)); }
        finally { lock.unlock(); }
    }

    private Map<String,Object> attemptLocked(String id, Map<String,Object> row) throws Exception {
        String state = string(row.get("status"));
        if (isTerminal(state)) return asPublicMap(id, row);
        try {
            String locator = string(row.get("sourceLocator"));
            SourceSnapshot source = inspectSource(locator, number(row.get("sourceSize"), -1L),
                    string(row.get("sourceSha256")));
            String endpoint = endpoints.endpointFor(string(row.get("destinationNodeId")));
            setState(row, "CREATING", "", 0L);
            saveJob(id, row);
            transport.create(endpoint, id, string(row.get("destinationPath")), source.size(), source.sha256());
            setState(row, "TRANSFERRING", "", 0L);
            saveJob(id, row);
            PeerConnector.InputStreamSource sourceStream = sources.open(locator);
            Map<String,Object> receipt = transport.resume(endpoint, id, sourceStream, source.size());
            markCommitted(row, receipt);
            saveJob(id, row);
            Map<String,Object> result = asPublicMap(id, row);
            result.put("receipt", receipt);
            return result;
        } catch (SourceChangedException changed) {
            setState(row, "NEEDS_ATTENTION", safeMessage(changed), 0L);
            saveJob(id, row);
            return asPublicMap(id, row);
        } catch (SourceUnavailableException unavailable) {
            recordFailure(row, "WAITING_SOURCE", unavailable);
            saveJob(id, row);
            return asPublicMap(id, row);
        } catch (Exception failure) {
            if (isPermanentFailure(failure)) {
                try { transport.abort(endpoints.endpointFor(string(row.get("destinationNodeId"))), id); }
                catch (Exception ignored) { /* Receiver session has a seven-day expiry. */ }
                setState(row, "FAILED", safeMessage(failure), 0L);
            } else {
                recordFailure(row, "INTERRUPTED", failure);
            }
            saveJob(id, row);
            return asPublicMap(id, row);
        }
    }

    private void abortOrReconcile(String id, Map<String,Object> row, String endpoint) throws Exception {
        try {
            Map<String,Object> remote = transport.status(endpoint, id);
            if ("COMMITTED".equals(remote.get("state"))) {
                markCommitted(row, receiptFromStatus(remote));
                saveJob(id, row);
                return;
            }
        } catch (Exception unavailable) {
            if (isMissingSession(unavailable)) {
                setState(row, "ABORTED", "", 0L);
                saveJob(id, row);
                return;
            }
        }
        try {
            transport.abort(endpoint, id);
            setState(row, "ABORTED", "", 0L);
        } catch (Exception failure) {
            if (isMissingSession(failure)) setState(row, "ABORTED", "", 0L);
            else recordFailure(row, "ABORT_PENDING", failure);
        }
        saveJob(id, row);
    }

    private static void markCommitted(Map<String,Object> row, Map<String,Object> receipt) {
        row.put("receipt", new LinkedHashMap<>(receipt));
        row.put("destinationFileId", string(receipt.get("fileId")));
        setState(row, "COMPLETED", "", 0L);
    }

    private static Map<String,Object> receiptFromStatus(Map<String,Object> remote) {
        Object value = remote.get("receipt");
        if (!(value instanceof Map<?,?> map)) throw new SecurityException("Receiver reports COMMITTED without a durable receipt.");
        Map<String,Object> receipt = new LinkedHashMap<>();
        for (Map.Entry<?,?> entry : map.entrySet()) if (entry.getKey() instanceof String key) receipt.put(key, entry.getValue());
        receipt.put("transferId", remote.getOrDefault("transferId", ""));
        receipt.put("transferState", "COMMITTED");
        return receipt;
    }

    private SourceSnapshot inspectSource(String locator, Long expectedSize, String expectedHash) throws Exception {
        if (locator == null || locator.isBlank()) throw new SourceChangedException("The original Android source URI is missing.");
        PeerConnector.InputStreamSource source;
        try { source = sources.open(locator); }
        catch (SecurityException revoked) { throw new SourceChangedException("Android no longer grants access to the original source URI."); }
        catch (FileNotFoundException | java.nio.file.NoSuchFileException missing) {
            throw new SourceUnavailableException("The original Android source is temporarily unavailable.");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long size = 0;
        try (InputStream input = source.open()) {
            if (input == null) throw new SourceUnavailableException("Android returned no stream for the original source URI.");
            byte[] buffer = new byte[256 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                size = Math.addExact(size, read);
                if (size > maximumBytes) throw new SourceChangedException("The Android source now exceeds this node's transfer limit.");
                digest.update(buffer, 0, read);
            }
        } catch (FileNotFoundException | java.nio.file.NoSuchFileException missing) {
            throw new SourceUnavailableException("The original Android source is temporarily unavailable.");
        } catch (SecurityException revoked) {
            throw new SourceChangedException("Android no longer grants access to the original source URI.");
        } catch (IOException transientRead) {
            throw new SourceUnavailableException("The original Android source could not be read; reconnect it to resume.");
        }
        String hash = HexFormat.of().formatHex(digest.digest());
        if (expectedSize != null && expectedSize.longValue() != size) {
            throw new SourceChangedException("The original Android source size changed; the transfer was not resumed.");
        }
        if (expectedHash != null && !expectedHash.isBlank() && !expectedHash.equals(hash)) {
            throw new SourceChangedException("The original Android source SHA-256 changed; the transfer was not resumed.");
        }
        return new SourceSnapshot(size, hash);
    }

    private void pruneTerminalHistory() throws Exception {
        Map<String,Map<String,Object>> rows = loadJobs();
        if (rows.size() < MAX_RETAINED_JOBS) return;
        List<Map.Entry<String,Map<String,Object>>> entries = new ArrayList<>(rows.entrySet());
        entries.sort(Comparator.comparing(entry -> string(entry.getValue().get("updatedAt"))));
        int excess = rows.size() - MAX_RETAINED_JOBS + 1;
        STORE_LOCK.lock();
        try {
            Map<String,Object> root = store.loadDomain(DOMAIN);
            Map<String,Object> jobs = objectMap(root.get("jobs"));
            for (Map.Entry<String,Map<String,Object>> entry : entries) {
                if (excess <= 0) break;
                if (!isTerminal(string(entry.getValue().get("status")))
                        && !"NEEDS_ATTENTION".equals(entry.getValue().get("status"))) continue;
                jobs.remove(entry.getKey());
                excess--;
            }
            if (excess > 0) throw new IllegalStateException("Android outbound transfer history is full of active jobs.");
            root.put("jobs", jobs);
            store.saveDomain(DOMAIN, root);
        } finally { STORE_LOCK.unlock(); }
    }

    private Map<String,Object> requireJob(String id) throws Exception {
        Map<String,Map<String,Object>> jobs = loadJobs();
        Map<String,Object> row = jobs.get(id);
        if (row == null) throw new IllegalArgumentException("Android outbound transfer job was not found: " + id);
        return row;
    }

    private Map<String,Map<String,Object>> loadJobs() throws Exception {
        STORE_LOCK.lock();
        try {
            Map<String,Object> root = store.loadDomain(DOMAIN);
            Map<String,Object> rawJobs = objectMap(root.get("jobs"));
            Map<String,Map<String,Object>> result = new LinkedHashMap<>();
            for (Map.Entry<String,Object> entry : rawJobs.entrySet()) {
                result.put(entry.getKey(), objectMap(entry.getValue()));
            }
            return result;
        } finally { STORE_LOCK.unlock(); }
    }

    private void saveJob(String id, Map<String,Object> row) throws Exception {
        STORE_LOCK.lock();
        try {
            Map<String,Object> root = store.loadDomain(DOMAIN);
            Map<String,Object> jobs = objectMap(root.get("jobs"));
            jobs.put(id, new LinkedHashMap<>(row));
            root.put("jobs", jobs);
            store.saveDomain(DOMAIN, root);
        } finally { STORE_LOCK.unlock(); }
    }

    private static Map<String,Object> asPublicMap(String id, Map<String,Object> row) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("jobId", id); result.put("transferId", id);
        result.put("status", string(row.get("status")));
        result.put("destinationNodeId", string(row.get("destinationNodeId")));
        result.put("destinationPath", string(row.get("destinationPath")));
        result.put("sourceSize", number(row.get("sourceSize"), 0L));
        result.put("sourceSha256", string(row.get("sourceSha256")));
        result.put("attemptCount", number(row.get("attemptCount"), 0L));
        result.put("createdAt", string(row.get("createdAt")));
        result.put("updatedAt", string(row.get("updatedAt")));
        result.put("nextAttemptAt", number(row.get("nextAttemptAt"), 0L));
        result.put("lastError", string(row.get("lastError")));
        result.put("destinationFileId", string(row.get("destinationFileId")));
        if ("COMPLETED".equals(row.get("status"))) result.put("transferState", "COMMITTED");
        return result;
    }

    private static void setState(Map<String,Object> row, String status, String error, long nextAttemptAt) {
        row.put("status", status); row.put("lastError", error == null ? "" : error);
        row.put("updatedAt", Instant.now().toString()); row.put("nextAttemptAt", nextAttemptAt);
    }

    private static void recordFailure(Map<String,Object> row, String status, Exception failure) {
        long attempts = number(row.get("attemptCount"), 0L) + 1L;
        long exponent = Math.min(10L, attempts - 1L);
        long delay = Math.min(MAX_RETRY_MILLIS, BASE_RETRY_MILLIS * (1L << exponent));
        row.put("attemptCount", attempts); row.put("lastAttemptAt", Instant.now().toString());
        setState(row, status, safeMessage(failure), System.currentTimeMillis() + delay);
    }

    private static boolean isRetryable(String state) {
        return "QUEUED".equals(state) || "CREATING".equals(state) || "TRANSFERRING".equals(state)
                || "INTERRUPTED".equals(state) || "WAITING_SOURCE".equals(state) || "ABORT_PENDING".equals(state);
    }
    private static boolean isTerminal(String state) {
        return "COMPLETED".equals(state) || "ABORTED".equals(state) || "FAILED".equals(state);
    }
    private static boolean isPermanentFailure(Exception failure) {
        if (failure instanceof IllegalArgumentException || failure instanceof SecurityException) return true;
        String message = failureMessages(failure).toUpperCase(java.util.Locale.ROOT);
        return message.contains("HTTP 400") || message.contains("HTTP 401") || message.contains("HTTP 403")
                || message.contains("HTTP 404") || message.contains("HTTP 409") || message.contains("HTTP 422")
                || message.contains("DESTINATION ALREADY EXISTS") || message.contains("OVERWRITE");
    }
    private static boolean isMissingSession(Exception failure) {
        String message = failureMessages(failure).toUpperCase(java.util.Locale.ROOT);
        return message.contains("HTTP 404") || message.contains("TRANSFER SESSION NOT FOUND")
                || message.contains("TRANSFER SESSION EXPIRED");
    }
    private static String failureMessages(Throwable failure) {
        StringBuilder result = new StringBuilder();
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current.getMessage() != null) result.append(' ').append(current.getMessage());
        }
        return result.toString();
    }
    private static void throwIfPermanentFailure(Map<String,Object> result) throws IOException {
        if ("FAILED".equals(result.get("status"))) throw new IOException(string(result.get("lastError")));
    }
    private static String normalizeJobId(String value) {
        try {
            String normalized = UUID.fromString(value).toString();
            if (!normalized.equalsIgnoreCase(value)) throw new IllegalArgumentException();
            return normalized;
        } catch (RuntimeException invalid) { throw new IllegalArgumentException("Android transfer job ID must be a canonical UUID.", invalid); }
    }
    private static void requireText(String value, String label) {
        if (value == null || value.isBlank() || value.length() > 2048) throw new IllegalArgumentException(label + " is required.");
    }
    private static String string(Object value) { return value == null ? "" : String.valueOf(value); }
    private static long number(Object value, long fallback) { return value instanceof Number n ? n.longValue() : fallback; }
    private static Map<String,Object> objectMap(Object value) {
        Map<String,Object> result = new LinkedHashMap<>();
        if (value instanceof Map<?,?> map) for (Map.Entry<?,?> entry : map.entrySet()) {
            if (entry.getKey() instanceof String key) result.put(key, entry.getValue());
        }
        return result;
    }
    private static ReentrantLock lockFor(String id) { return JOB_LOCKS.computeIfAbsent(id, ignored -> new ReentrantLock(true)); }
    private static String safeMessage(Exception failure) {
        String message = failure.getMessage();
        if (message == null || message.isBlank()) return failure.getClass().getSimpleName();
        return message.length() > 500 ? message.substring(0, 500) : message;
    }

    private record SourceSnapshot(long size, String sha256) { }
    private static final class SourceChangedException extends Exception {
        private static final long serialVersionUID = 1L;
        private SourceChangedException(String message) { super(message); }
    }
    private static final class SourceUnavailableException extends Exception {
        private static final long serialVersionUID = 1L;
        private SourceUnavailableException(String message) { super(message); }
    }
}
