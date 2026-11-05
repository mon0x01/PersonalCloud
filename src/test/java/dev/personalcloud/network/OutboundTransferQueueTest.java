package dev.personalcloud.network;

import dev.personalcloud.core.StateStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HexFormat;

/** Durable sender journal, idempotent session creation, restart retry and source-mutation tests. */
public final class OutboundTransferQueueTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("pc-outbound-queue-");
        try {
            StateStore store = new StateStore(root.resolve("data"));
            Path source = root.resolve("source.bin");
            byte[] bytes = new byte[196_777];
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i * 17);
            Files.write(source, bytes);
            FakeTransport transport = new FakeTransport();
            OutboundTransferQueue firstProcess = new OutboundTransferQueue(store, null,
                    ignored -> "https://member.example:8879", 1_000_000, transport);

            Map<String,Object> first = firstProcess.place("member-node-0001", "backup/source.bin", source);
            String id = String.valueOf(first.get("jobId"));
            check("INTERRUPTED".equals(first.get("status")), "network failure must persist an interrupted sender job");
            check(id.equals(first.get("transferId")), "job UUID must be the receiver session UUID");
            check(transport.sessions.containsKey(id), "receiver session was created before the interrupted upload");
            check(transport.createCalls == 1, "initial remote session creation count");

            // Re-open the same local data store as a fresh node process and force the retry due.
            StateStore restartedStore = new StateStore(root.resolve("data"));
            Map<String,String> persisted = restartedStore.getRecord("outboundTransfer", id);
            check(persisted != null && "INTERRUPTED".equals(persisted.get("status")), "sender job survives process restart");
            // Simulate abrupt process death after CREATING was persisted but before the
            // network request returned. The receiver may or may not have seen the first POST.
            // Stable-ID create makes replay safe, and startup recovery must not ignore this state.
            persisted.put("status", "CREATING");
            persisted.put("nextAttemptAt", "0");
            restartedStore.putRecord("outboundTransfer", id, persisted);
            OutboundTransferQueue restarted = new OutboundTransferQueue(restartedStore, null,
                    ignored -> "https://member.example:8879", 1_000_000, transport);
            check(restarted.retryDue() == 1, "startup retry pass should recover a crash-orphaned CREATING transfer");
            Map<String,Object> completed = restarted.status(id);
            check("COMPLETED".equals(completed.get("status")), "retry completes the transfer");
            check(transport.createCalls == 2, "retry reissues idempotent create using the same ID");
            check(transport.uniqueSessions == 1, "idempotent create must not allocate a second receiver session");
            check("remote-file-1".equals(completed.get("destinationFileId")), "committed receipt is persisted locally");

            // Simulate the receiver publishing the file and the sender dying before it saves the
            // receipt. A later status request must reconcile to COMPLETED without another upload.
            transport.failAfterRemoteCommit = true;
            Map<String,Object> lostReceipt = restarted.place("member-node-0001", "backup/lost-receipt.bin", source);
            String lostReceiptId = String.valueOf(lostReceipt.get("jobId"));
            check("INTERRUPTED".equals(lostReceipt.get("status")), "lost commit response remains locally recoverable");
            Map<String,Object> reconciled = restarted.status(lostReceiptId);
            check("COMPLETED".equals(reconciled.get("status")), "receiver commit tombstone reconciles sender after restart");
            check("remote-file-2".equals(reconciled.get("destinationFileId")), "reconciliation recovers original committed file ID");
            check(transport.receipts == 2, "reconciliation must not publish a second managed file");

            // A temporarily disconnected removable source should wait, then resume automatically
            // when the exact original file returns; changed contents remain blocked below.
            transport.failNextResume = true;
            Map<String,Object> waiting = restarted.place("member-node-0001", "backup/waiting-source.bin", source);
            String waitingId = String.valueOf(waiting.get("jobId"));
            Files.delete(source);
            Map<String,Object> noSource = restarted.resume(waitingId);
            check("WAITING_SOURCE".equals(noSource.get("status")), "temporarily missing source is retried rather than permanently blocked");
            Files.write(source, bytes);
            Map<String,Object> resumedSource = restarted.resume(waitingId);
            check("COMPLETED".equals(resumedSource.get("status")), "restoring the unchanged source resumes the job");

            // A source changed after interruption must never be resumed into the original session.
            transport.failNextResume = true;
            Map<String,Object> interruptedAgain = restarted.place("member-node-0001", "backup/changed.bin", source);
            String changedId = String.valueOf(interruptedAgain.get("jobId"));
            byte[] altered = bytes.clone();
            altered[altered.length / 2] ^= 0x55;
            Files.write(source, altered);
            Map<String,Object> blocked = restarted.resume(changedId);
            check("NEEDS_ATTENTION".equals(blocked.get("status")), "changed source must be blocked, not silently uploaded");
            check(String.valueOf(blocked.get("lastError")).contains("SHA-256 changed"), "source mutation is explained to the operator");
            Files.write(source, bytes);
            Map<String,Object> restoredOriginal = restarted.resume(changedId);
            check("COMPLETED".equals(restoredOriginal.get("status")), "manual resume succeeds after the exact original source is restored");

            // An offline abort remains pending and retries instead of forgetting remote staging.
            transport.failNextResume = true;
            Files.write(source, bytes);
            Map<String,Object> abortCandidate = restarted.place("member-node-0001", "backup/abort.bin", source);
            String abortId = String.valueOf(abortCandidate.get("jobId"));
            transport.failNextAbort = true;
            Map<String,Object> abortPending = restarted.abort(abortId);
            check("ABORT_PENDING".equals(abortPending.get("status")), "offline abort is retained for retry");
            Map<String,String> abortRow = restartedStore.getRecord("outboundTransfer", abortId);
            abortRow.put("nextAttemptAt", "0");
            restartedStore.putRecord("outboundTransfer", abortId, abortRow);
            check(restarted.retryDue() == 1, "pending abort is retried");
            check("ABORTED".equals(restarted.status(abortId).get("status")), "pending abort eventually completes");

            check(restarted.list().size() == 5, "all transfer jobs remain visible in durable history");
            System.out.println("PASS: sender transfer journal, crash-orphaned state recovery, stable IDs, automatic retry, receiver-commit reconciliation, removable-source recovery, source mutation rejection and durable abort.");
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192]; int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static final class FakeTransport implements OutboundTransferQueue.TransferTransport {
        private final Map<String,Map<String,Object>> sessions = new ConcurrentHashMap<>();
        private int createCalls;
        private int uniqueSessions;
        private boolean failNextResume = true;
        private boolean failNextAbort;
        private boolean failAfterRemoteCommit;
        private int receipts;

        @Override public synchronized Map<String,Object> create(String endpoint, String transferId, String destinationPath,
                                                                 long size, String sha256, NetworkMembershipService membership) {
            createCalls++;
            Map<String,Object> existing = sessions.get(transferId);
            if (existing != null) {
                check(destinationPath.equals(existing.get("path")) && size == ((Number)existing.get("size")).longValue()
                        && sha256.equals(existing.get("sha256")), "stable ID cannot be rebound to other file metadata");
                return Map.copyOf(existing);
            }
            Map<String,Object> created = new LinkedHashMap<>();
            created.put("transferId", transferId); created.put("path", destinationPath);
            created.put("size", size); created.put("sha256", sha256); created.put("state", "RECEIVING");
            sessions.put(transferId, created); uniqueSessions++;
            return Map.copyOf(created);
        }

        @Override public synchronized Map<String,Object> resume(String endpoint, String transferId, Path source,
                                                                 NetworkMembershipService membership, long maximumBytes) throws Exception {
            if (failNextResume) { failNextResume = false; throw new IOException("simulated network interruption"); }
            Map<String,Object> row = sessions.get(transferId);
            check(row != null, "resume requires existing receiver session");
            if ("COMMITTED".equals(row.get("state"))) {
                Object value = row.get("receipt");
                if (!(value instanceof Map<?,?> existingReceipt)) throw new AssertionError("Committed session lacks receipt");
                Map<String,Object> receipt = new LinkedHashMap<>();
                for (Map.Entry<?,?> entry : existingReceipt.entrySet()) {
                    if (entry.getKey() instanceof String key) receipt.put(key, entry.getValue());
                }
                return receipt;
            }
            check(Files.size(source) == ((Number)row.get("size")).longValue(), "resume file size matches receiver session");
            check(sha256(source).equals(row.get("sha256")), "resume file digest matches receiver session");
            row.put("state", "COMMITTED");
            String fileId = "remote-file-" + (++receipts);
            Map<String,Object> receipt = Map.of("transferId", transferId, "fileId", fileId,
                    "path", row.get("path"), "size", row.get("size"), "sha256", row.get("sha256"),
                    "transferState", "COMMITTED");
            row.put("receipt", receipt);
            if (failAfterRemoteCommit) {
                failAfterRemoteCommit = false;
                throw new IOException("simulated connection loss after receiver commit");
            }
            return receipt;
        }

        @Override public synchronized Map<String,Object> status(String endpoint, String transferId,
                                                                 NetworkMembershipService membership) {
            Map<String,Object> row = sessions.get(transferId);
            if (row == null) throw new IllegalArgumentException("Transfer session not found.");
            return Map.copyOf(row);
        }

        @Override public synchronized Map<String,Object> abort(String endpoint, String transferId,
                                                                NetworkMembershipService membership) throws Exception {
            if (failNextAbort) { failNextAbort = false; throw new IOException("simulated offline abort"); }
            Map<String,Object> row = sessions.get(transferId);
            if (row == null) throw new IllegalArgumentException("Transfer session not found.");
            row.put("state", "ABORTED");
            return Map.of("transferId", transferId, "aborted", true);
        }
    }
}
