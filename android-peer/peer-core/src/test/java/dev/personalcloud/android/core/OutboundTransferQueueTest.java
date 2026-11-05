package dev.personalcloud.android.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HexFormat;

/** Durable Android sender queue: process recovery, source permissions, retry and commit reconciliation. */
public final class OutboundTransferQueueTest {
    public static void main(String[] args) throws Exception {
        MemoryStore store = new MemoryStore();
        Map<String,byte[]> sources = new ConcurrentHashMap<>();
        byte[] bytes = new byte[180_123];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte)(i * 19 + 5);
        sources.put("content://provider/document/1", bytes);
        FakeTransport transport = new FakeTransport();
        OutboundTransferQueue.SourceResolver resolver = locator -> {
            byte[] selected = sources.get(locator);
            if (selected == null) throw new java.io.FileNotFoundException("selected Android document is not currently available");
            return () -> new ByteArrayInputStream(selected);
        };
        OutboundTransferQueue firstProcess = new OutboundTransferQueue(store,
                member -> "https://" + member + ":8879", resolver, transport, 2_000_000);

        Map<String,Object> interrupted = firstProcess.place("peer-android-0001", "phone/photo.bin", "content://provider/document/1");
        String id = String.valueOf(interrupted.get("jobId"));
        check("INTERRUPTED".equals(interrupted.get("status")), "an interrupted Android upload must be durably queued");
        check(id.equals(interrupted.get("transferId")), "Android queue uses its persisted sender-generated ID");
        check(!interrupted.containsKey("sourceLocator"), "public queue rows must not expose the persisted content URI");
        check(transport.sessions.containsKey(id), "receiver session exists after interruption");

        // A new service/queue instance restores the encrypted domain and replays the same UUID.
        OutboundTransferQueue restarted = new OutboundTransferQueue(store,
                member -> "https://" + member + ":8879", resolver, transport, 2_000_000);
        Map<String,Object> row = object(object(store.loadDomain("outbound_transfers").get("jobs")).get(id));
        row.put("status", "CREATING"); row.put("nextAttemptAt", 0L);
        putJob(store, id, row);
        check(restarted.retryDue() == 1, "service restart should recover orphaned CREATING jobs");
        Map<String,Object> completed = restarted.status(id);
        check("COMPLETED".equals(completed.get("status")), "restarted Android sender completes its transfer");
        check(transport.createCalls == 2 && transport.uniqueSessions == 1,
                "idempotent Android create replay must reuse one receiver session");
        check("android-file-1".equals(completed.get("destinationFileId")), "Android queue persists its receipt");

        // Receiver publication succeeded but the sender lost the response. Status must recover
        // the receipt rather than creating another file or leaving the job interrupted forever.
        transport.failAfterCommit = true;
        Map<String,Object> lost = restarted.place("peer-android-0001", "phone/lost-response.bin", "content://provider/document/1");
        String lostId = String.valueOf(lost.get("jobId"));
        check("INTERRUPTED".equals(lost.get("status")), "lost commit response is retained as interrupted");
        Map<String,Object> reconciled = restarted.status(lostId);
        check("COMPLETED".equals(reconciled.get("status"))
                        && "android-file-2".equals(reconciled.get("destinationFileId")),
                "Android sender must reconcile a receiver-side committed tombstone");
        check(transport.receipts == 2, "receipt reconciliation must not create a duplicate managed file");

        // A temporarily disconnected SAF document is retried when its provider becomes available.
        transport.failNextResume = true;
        Map<String,Object> waiting = restarted.place("peer-android-0001", "phone/waiting.bin", "content://provider/document/1");
        String waitingId = String.valueOf(waiting.get("jobId"));
        sources.remove("content://provider/document/1");
        check("WAITING_SOURCE".equals(restarted.resume(waitingId).get("status")),
                "missing Android provider data waits instead of discarding the transfer");
        sources.put("content://provider/document/1", bytes);
        check("COMPLETED".equals(restarted.resume(waitingId).get("status")),
                "restored SAF source resumes with the original digest");

        // Content mutation must never be silently sent into an old receiver session.
        transport.failNextResume = true;
        Map<String,Object> changed = restarted.place("peer-android-0001", "phone/changed.bin", "content://provider/document/1");
        String changedId = String.valueOf(changed.get("jobId"));
        byte[] altered = bytes.clone(); altered[altered.length / 2] ^= 0x6d;
        sources.put("content://provider/document/1", altered);
        check("NEEDS_ATTENTION".equals(restarted.resume(changedId).get("status")),
                "changed Android document is blocked by the original digest");
        sources.put("content://provider/document/1", bytes);
        check("COMPLETED".equals(restarted.resume(changedId).get("status")),
                "manual retry is permitted after the exact original document is restored");

        // Offline aborts remain durable; a later service pass completes the abort.
        transport.failNextResume = true;
        Map<String,Object> abortCandidate = restarted.place("peer-android-0001", "phone/abort.bin", "content://provider/document/1");
        String abortId = String.valueOf(abortCandidate.get("jobId"));
        transport.failNextAbort = true;
        check("ABORT_PENDING".equals(restarted.abort(abortId).get("status")), "offline Android abort remains queued");
        row = object(object(store.loadDomain("outbound_transfers").get("jobs")).get(abortId));
        row.put("nextAttemptAt", 0L); putJob(store, abortId, row);
        check(restarted.retryDue() == 1 && "ABORTED".equals(restarted.status(abortId).get("status")),
                "Android service retry pass completes a pending abort");

        check(restarted.list().size() == 5, "Android queue retains bounded operator-visible transfer history");
        check(!restarted.hasActiveSource("content://provider/document/1"), "all completed and aborted jobs release the source locator");
        System.out.println("PASS: Android encrypted sender queue, process recovery, stable session IDs, commit reconciliation, SAF source recovery, mutation rejection and durable abort.");
    }

    private static void putJob(MemoryStore store, String id, Map<String,Object> row) throws Exception {
        Map<String,Object> root = store.loadDomain("outbound_transfers");
        Map<String,Object> jobs = object(root.get("jobs"));
        jobs.put(id, row); root.put("jobs", jobs); store.saveDomain("outbound_transfers", root);
    }
    private static Map<String,Object> object(Object value) {
        Map<String,Object> result = new LinkedHashMap<>();
        if (value instanceof Map<?,?> map) for (Map.Entry<?,?> entry : map.entrySet())
            if (entry.getKey() instanceof String key) result.put(key, entry.getValue());
        return result;
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static final class MemoryStore implements StateStore {
        private final Map<String,Map<String,Object>> domains = new ConcurrentHashMap<>();
        @Override public synchronized Map<String,Object> load() { return new LinkedHashMap<>(); }
        @Override public synchronized void save(Map<String,Object> state) { }
        @Override public synchronized Map<String,Object> loadDomain(String domain) {
            return copy(domains.getOrDefault(domain, Map.of()));
        }
        @Override public synchronized void saveDomain(String domain, Map<String,Object> state) {
            domains.put(domain, copy(state));
        }
        private static Map<String,Object> copy(Map<String,Object> value) {
            Map<String,Object> result = new LinkedHashMap<>();
            for (Map.Entry<String,Object> entry : value.entrySet()) {
                Object item = entry.getValue();
                if (item instanceof Map<?,?> map) result.put(entry.getKey(), copy(object(map)));
                else result.put(entry.getKey(), item);
            }
            return result;
        }
    }

    private static final class FakeTransport implements OutboundTransferQueue.TransferTransport {
        private final Map<String,Map<String,Object>> sessions = new ConcurrentHashMap<>();
        private int createCalls;
        private int uniqueSessions;
        private int receipts;
        private boolean failNextResume = true;
        private boolean failAfterCommit;
        private boolean failNextAbort;

        @Override public synchronized Map<String,Object> create(String endpoint, String id, String path, long size, String hash) {
            createCalls++;
            Map<String,Object> existing = sessions.get(id);
            if (existing != null) {
                check(path.equals(existing.get("path")) && size == ((Number)existing.get("size")).longValue()
                                && hash.equals(existing.get("sha256")), "stable Android ID cannot be rebound to different metadata");
                return Map.copyOf(existing);
            }
            Map<String,Object> row = new LinkedHashMap<>();
            row.put("transferId", id); row.put("path", path); row.put("size", size);
            row.put("sha256", hash); row.put("state", "RECEIVING");
            sessions.put(id, row); uniqueSessions++;
            return Map.copyOf(row);
        }

        @Override public synchronized Map<String,Object> resume(String endpoint, String id,
                PeerConnector.InputStreamSource source, long expectedSize) throws Exception {
            if (failNextResume) { failNextResume = false; throw new IOException("simulated Android network interruption"); }
            Map<String,Object> row = sessions.get(id);
            check(row != null, "Android resume requires an existing receiver session");
            if ("COMMITTED".equals(row.get("state"))) return object(row.get("receipt"));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long count = 0;
            try (InputStream input = source.open()) {
                byte[] buffer = new byte[8192]; int read;
                while ((read = input.read(buffer)) != -1) { count += read; digest.update(buffer, 0, read); }
            }
            check(count == expectedSize && count == ((Number)row.get("size")).longValue(), "Android resume verifies source size");
            check(HexFormat.of().formatHex(digest.digest()).equals(row.get("sha256")), "Android resume verifies source hash");
            String fileId = "android-file-" + (++receipts);
            Map<String,Object> receipt = Map.of("transferId", id, "fileId", fileId,
                    "path", row.get("path"), "size", row.get("size"), "sha256", row.get("sha256"),
                    "transferState", "COMMITTED");
            row.put("state", "COMMITTED"); row.put("receipt", receipt);
            if (failAfterCommit) { failAfterCommit = false; throw new IOException("simulated lost Android commit response"); }
            return receipt;
        }

        @Override public synchronized Map<String,Object> status(String endpoint, String id) {
            Map<String,Object> row = sessions.get(id);
            if (row == null) throw new IllegalArgumentException("Transfer session not found.");
            return new LinkedHashMap<>(row);
        }

        @Override public synchronized Map<String,Object> abort(String endpoint, String id) throws Exception {
            if (failNextAbort) { failNextAbort = false; throw new IOException("simulated offline abort"); }
            Map<String,Object> row = sessions.get(id);
            if (row == null) throw new IllegalArgumentException("Transfer session not found.");
            row.put("state", "ABORTED");
            return Map.of("transferId", id, "aborted", true);
        }
    }
}
