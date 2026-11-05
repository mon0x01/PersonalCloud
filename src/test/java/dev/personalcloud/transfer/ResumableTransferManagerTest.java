package dev.personalcloud.transfer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;

/** Restart, idempotency, integrity, ownership and commit tests for durable transfer sessions. */
public final class ResumableTransferManagerTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("pc-transfer-test-");
        AtomicReference<byte[]> committed = new AtomicReference<>();
        AtomicInteger commitCalls = new AtomicInteger();
        ResumableTransferManager.Committer sink = (transferId, uploader, path, input, size, hash) -> {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            input.transferTo(out);
            byte[] bytes = out.toByteArray();
            if (bytes.length != size || !sha(bytes).equals(hash)) throw new AssertionError("Commit callback received invalid content.");
            committed.set(bytes);
            return Map.of("fileId", "remote-file-" + commitCalls.incrementAndGet(),
                    "path", path, "size", size, "sha256", hash);
        };
        try {
            byte[] content = new byte[150_123];
            for (int i = 0; i < content.length; i++) content[i] = (byte)(i * 31);
            String fullHash = sha(content);
            ResumableTransferManager first = new ResumableTransferManager(root, "owner", 1_000_000, 65_536, sink);
            String stableId = java.util.UUID.randomUUID().toString();
            Map<String,Object> stable = first.create("peer-a", stableId, "incoming/stable.bin", content.length, fullHash);
            Map<String,Object> stableRetry = first.create("peer-a", stableId, "incoming/stable.bin", content.length, fullHash);
            if (!stableId.equals(stable.get("transferId")) || !stableId.equals(stableRetry.get("transferId"))) {
                throw new AssertionError("Stable sender-generated transfer ID was not idempotent.");
            }
            try {
                first.create("peer-a", stableId, "incoming/other.bin", content.length, fullHash);
                throw new AssertionError("Stable transfer ID was reused with different metadata.");
            } catch (SecurityException expected) { }
            try {
                first.create("peer-b", stableId, "incoming/stable.bin", content.length, fullHash);
                throw new AssertionError("Another uploader reused a transfer ID.");
            } catch (SecurityException expected) { }
            first.abort("peer-a", stableId);
            Map<String,Object> created = first.create("peer-a", "incoming/data.bin", content.length, fullHash);
            String id = String.valueOf(created.get("transferId"));

            byte[] c0 = Arrays.copyOfRange(content, 0, 65_536);
            String h0 = sha(c0);
            first.receiveChunk("peer-a", id, 0, c0.length, h0, new ByteArrayInputStream(c0));
            first.receiveChunk("peer-a", id, 0, c0.length, h0, new ByteArrayInputStream(c0)); // retry is idempotent
            try {
                first.status("peer-b", id);
                throw new AssertionError("Another member accessed the transfer.");
            } catch (SecurityException expected) { }

            // Simulate a process restart: journal and first chunk are discovered from disk.
            ResumableTransferManager restarted = new ResumableTransferManager(root, "owner", 1_000_000, 65_536, sink);
            Map<String,Object> status = restarted.status("peer-a", id);
            if (!((java.util.List<?>)status.get("receivedChunks")).contains(0)) throw new AssertionError("Persisted chunk was not recovered.");
            try {
                restarted.commit("peer-a", id);
                throw new AssertionError("Incomplete transfer committed.");
            } catch (IllegalStateException expected) { }

            byte[] c1 = Arrays.copyOfRange(content, 65_536, 131_072);
            byte[] c2 = Arrays.copyOfRange(content, 131_072, content.length);
            restarted.receiveChunk("peer-a", id, 1, c1.length, sha(c1), new ByteArrayInputStream(c1));
            try {
                restarted.receiveChunk("peer-a", id, 2, c2.length, "0".repeat(64), new ByteArrayInputStream(c2));
                throw new AssertionError("Corrupt chunk was accepted.");
            } catch (SecurityException expected) { }
            restarted.receiveChunk("peer-a", id, 2, c2.length, sha(c2), new ByteArrayInputStream(c2));
            Map<String,Object> result = restarted.commit("peer-a", id);
            if (!"COMMITTED".equals(result.get("transferState"))) throw new AssertionError("Commit state missing.");
            if (!Arrays.equals(content, committed.get())) throw new AssertionError("Committed bytes differ from source.");
            Map<String,Object> committedStatus = restarted.status("peer-a", id);
            if (!"COMMITTED".equals(committedStatus.get("state"))) throw new AssertionError("Commit receipt tombstone was not retained.");
            Object receiptValue = committedStatus.get("receipt");
            if (!(receiptValue instanceof Map<?,?> receipt) || !"remote-file-1".equals(receipt.get("fileId"))) {
                throw new AssertionError("The durable commit receipt was not exposed by status.");
            }
            ResumableTransferManager afterCommitRestart = new ResumableTransferManager(root, "owner", 1_000_000, 65_536, sink);
            Map<String,Object> reopened = afterCommitRestart.create("peer-a", id, "incoming/data.bin", content.length, fullHash);
            if (!"COMMITTED".equals(reopened.get("state"))) throw new AssertionError("Idempotent create did not reopen the committed receipt.");
            Map<String,Object> repeatedCommit = afterCommitRestart.commit("peer-a", id);
            if (!"remote-file-1".equals(repeatedCommit.get("fileId")) || commitCalls.get() != 1) {
                throw new AssertionError("Commit replay did not return the original receipt without republishing.");
            }
            try {
                afterCommitRestart.abort("peer-a", id);
                throw new AssertionError("A committed transfer was allowed to be aborted.");
            } catch (IllegalStateException expected) { }

            Map<String,Object> empty = afterCommitRestart.create("peer-a", "incoming/empty.bin", 0, sha(new byte[0]));
            afterCommitRestart.commit("peer-a", String.valueOf(empty.get("transferId")));
            if (committed.get().length != 0) throw new AssertionError("Zero-byte transfer failed.");

            Map<String,Object> abort = afterCommitRestart.create("peer-a", "incoming/abort.bin", 1, sha(new byte[]{7}));
            afterCommitRestart.abort("peer-a", String.valueOf(abort.get("transferId")));
            try {
                afterCommitRestart.status("peer-a", String.valueOf(abort.get("transferId")));
                throw new AssertionError("Aborted session remained available.");
            } catch (IllegalArgumentException expected) { }
            System.out.println("PASS: resumable transfer restart, chunk idempotency, ownership, integrity, durable commit receipt replay, zero-byte commit and abort.");
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
