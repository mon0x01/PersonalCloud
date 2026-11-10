package dev.personalcloud.transfer;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

/** Per-member session and staging-budget bounds for durable transfers. */
public final class TransferQuotaTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-transfer-quota-");
        try {
            String hash = sha(new byte[10]);
            ResumableTransferManager.Committer sink = (transferId, uploader, path, input, size, digest) ->
                    Map.of("fileId", transferId, "path", path, "size", size, "sha256", digest);

            ResumableTransferManager sessions = new ResumableTransferManager(
                    Files.createDirectory(base.resolve("sessions")), "owner", 100_000, 65_536, sink);
            String firstPeerA = "";
            for (int i = 0; i < 4; i++) {
                Map<String, Object> created = sessions.create("peer-a", "peer-a/file-" + i + ".bin", 10, hash);
                if (i == 0) firstPeerA = String.valueOf(created.get("transferId"));
            }
            expectSessionFailure(() -> sessions.create("peer-a", "peer-a/overflow.bin", 10, hash),
                    "one member must not occupy unbounded transfer sessions");

            for (String peer : java.util.List.of("peer-b", "peer-c", "peer-d")) {
                for (int i = 0; i < 4; i++) {
                    sessions.create(peer, peer + "/file-" + i + ".bin", 10, hash);
                }
            }
            expectSessionFailure(() -> sessions.create("peer-e", "peer-e/overflow.bin", 10, hash),
                    "the node must not create unbounded transfer sessions across members");

            sessions.abort("peer-a", firstPeerA);
            sessions.create("peer-a", "peer-a/released.bin", 10, hash);

            ResumableTransferManager budget = new ResumableTransferManager(
                    Files.createDirectory(base.resolve("budget")), "owner", 1000, 65_536, sink);
            budget.create("peer-a", "peer-a/first.bin", 1000, sha(new byte[1000]));
            budget.create("peer-a", "peer-a/second.bin", 1000, sha(new byte[1000]));
            expectSessionFailure(() -> budget.create("peer-a", "peer-a/third.bin", 1000, sha(new byte[1000])),
                    "reserved staging must be bounded even when the per-member session count allows more work");

            System.out.println("PASS: transfer sessions are bounded per member and per node, and reserved staging honors a fixed budget.");
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
    }

    private static void expectSessionFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalStateException expected) {
            // Expected: the bounded receiver fails closed.
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
