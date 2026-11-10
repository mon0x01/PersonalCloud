package dev.personalcloud.storage;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.StateStore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;

/**
 * Controlled fault injection for managed-file publication. These tests model
 * interrupted writes, verification failures, destination conflicts and a
 * persistence failure after the file link is published. They are deterministic
 * software faults, not a substitute for real power-loss or disk-full hardware
 * testing.
 */
public final class StorageFaultInjectionTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-storage-fault-");
        Path data = Files.createDirectory(base.resolve("data"));
        Path storage = Files.createDirectory(base.resolve("storage"));
        try {
            AppConfig config = new AppConfig("Fault Test", "owner-node", "127.0.0.1", 0,
                    data, storage, null, null, 1024 * 1024);
            StateStore store = new StateStore(data);
            ManagedStorageService managed = new ManagedStorageService(store, config);

            byte[] committedBytes = "complete managed payload".getBytes(StandardCharsets.UTF_8);
            Map<String, Object> committed = managed.receive("member-a", "documents/complete.txt",
                    new ByteArrayInputStream(committedBytes), committedBytes.length, sha(committedBytes));
            check("member-a".equals(committed.get("uploaderNodeId")), "a verified file must be recorded");
            check(Arrays.equals(committedBytes, Files.readAllBytes(storage.resolve("documents/complete.txt"))),
                    "a verified file must be published byte-for-byte");

            byte[] prefix = "partial".getBytes(StandardCharsets.UTF_8);
            InputStream interrupted = new InputStream() {
                private int position;
                @Override public int read() throws IOException {
                    if (position < prefix.length) return prefix[position++];
                    throw new IOException("injected source interruption");
                }
            };
            expectFailure(() -> managed.receive("member-a", "documents/interrupted.txt", interrupted,
                            1024, sha(prefix)), "an interrupted source must not publish a managed file");
            check(!Files.exists(storage.resolve("documents/interrupted.txt")),
                    "an interrupted source must leave no destination file");
            check(noStagingFiles(storage), "an interrupted source must clean its staging file");

            byte[] mismatched = "mismatched payload".getBytes(StandardCharsets.UTF_8);
            expectFailure(() -> managed.receive("member-a", "documents/mismatch.txt",
                            new ByteArrayInputStream(mismatched), mismatched.length, sha(new byte[]{1, 2, 3})),
                    "a digest mismatch must reject the managed file");
            check(!Files.exists(storage.resolve("documents/mismatch.txt")),
                    "a digest mismatch must never publish a destination file");
            check(noStagingFiles(storage), "a digest mismatch must clean its staging file");

            expectFailure(() -> managed.receive("member-a", "documents/complete.txt",
                            new ByteArrayInputStream(committedBytes), committedBytes.length, sha(committedBytes)),
                    "an existing destination must not be overwritten");
            check(Arrays.equals(committedBytes, Files.readAllBytes(storage.resolve("documents/complete.txt"))),
                    "a rejected overwrite must preserve the original bytes");

            Path blocker = Files.writeString(storage.resolve("blocked"), "not a directory");
            expectFailure(() -> managed.receive("member-a", "blocked/file.txt",
                            new ByteArrayInputStream(committedBytes), committedBytes.length, sha(committedBytes)),
                    "an unavailable destination parent must fail closed");
            check("not a directory".equals(Files.readString(blocker)),
                    "a failed destination must not alter an unrelated existing entry");
            check(noStagingFiles(storage), "a destination failure must clean its staging file");

            ManagedStorageService restarted = new ManagedStorageService(new StateStore(data), config);
            check(restarted.listLocal().stream().anyMatch(row -> "documents/complete.txt".equals(row.get("path"))),
                    "a committed managed file must survive a service restart");

            // Inject a persistence failure after the destination link has been
            // published. The partial commit must be rolled back completely, and
            // the original committed file must remain intact.
            Path dataBackup = base.resolve("data-backup");
            Files.move(data, dataBackup);
            Files.writeString(data, "not a directory");
            byte[] persistenceBytes = "record will fail".getBytes(StandardCharsets.UTF_8);
            expectFailure(() -> managed.receive("member-a", "documents/persistence.txt",
                            new ByteArrayInputStream(persistenceBytes), persistenceBytes.length, sha(persistenceBytes)),
                    "a state persistence failure after publication must fail the receive");
            check(!Files.exists(storage.resolve("documents/persistence.txt")),
                    "a partial commit must remove the published destination");
            check(noStagingFiles(storage), "a partial commit must clean its staging file");
            Files.delete(data);
            Files.move(dataBackup, data);
            check(Arrays.equals(committedBytes, Files.readAllBytes(storage.resolve("documents/complete.txt"))),
                    "the pre-existing managed file must remain intact after a partial commit");

            ManagedStorageService recovered = new ManagedStorageService(new StateStore(data), config);
            check(recovered.listLocal().stream().noneMatch(row -> "documents/persistence.txt".equals(row.get("path"))),
                    "a rolled-back partial commit must not appear in the catalogue");
            check(recovered.listLocal().stream().anyMatch(row -> "documents/complete.txt".equals(row.get("path"))),
                    "the catalogue must still expose the original committed file after recovery");

            System.out.println("PASS: managed storage rejects interrupted, corrupted, conflicting and partially committed writes without losing original files.");
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
    }

    private static boolean noStagingFiles(Path storage) throws Exception {
        try (var paths = Files.list(storage)) {
            return paths.noneMatch(path -> path.getFileName().toString().startsWith(".personalcloud-incoming-"));
        }
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (Exception expected) {
            // Expected: the controlled fault fails the operation closed.
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
