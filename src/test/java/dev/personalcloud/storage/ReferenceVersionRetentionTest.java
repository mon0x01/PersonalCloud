package dev.personalcloud.storage;

import dev.personalcloud.core.StateStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Retention-order and cancellation tests for referenced-file recovery snapshots. */
public final class ReferenceVersionRetentionTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-reference-version-test-");
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path managed = Files.createDirectory(workspace.resolve("managed"));
            Path documents = Files.createDirectory(workspace.resolve("user-documents"));
            StateStore store = new StateStore(data);
            ReferenceStorageService references = new ReferenceStorageService(store, data, managed);
            ReferenceRoot root = references.register("Documents", documents);
            ReferenceVersionService versions = new ReferenceVersionService(data, references);

            String firstSnapshotId = "";
            String newestSnapshotId = "";
            String newestContent = "";
            for (int i = 1; i <= 21; i++) {
                String content = "snapshot-" + i;
                Path source = Files.writeString(documents.resolve("history.txt"), content);
                // Keep creator timestamps strictly ordered so retention ordering
                // is deterministic even on coarse filesystem clocks.
                Files.setLastModifiedTime(source, java.nio.file.attribute.FileTime.fromMillis(1_700_000_000_000L + i));
                Map<String, Object> snapshot = versions.snapshotAndDelete(root.id(), "history.txt", 1024);
                String id = String.valueOf(snapshot.get("snapshotId"));
                if (firstSnapshotId.isEmpty()) firstSnapshotId = id;
                newestSnapshotId = id;
                newestContent = content;
                check(!Files.exists(documents.resolve("history.txt")),
                        "a successful snapshot must delete the original referenced file");
                Thread.sleep(2);
            }

            List<Map<String, Object>> retained = versions.list();
            check(retained.size() == 20, "per-path snapshot retention must be bounded at 20: " + retained.size());
            String evictedId = firstSnapshotId;
            String retainedNewestId = newestSnapshotId;
            check(retained.stream().noneMatch(item -> evictedId.equals(item.get("snapshotId"))),
                    "retention must evict the oldest snapshot instead of a newer recovery point");
            check(retained.stream().anyMatch(item -> retainedNewestId.equals(item.get("snapshotId"))),
                    "retention must keep the newest recovery point");

            Map<String, Object> restored = versions.restore(retainedNewestId);
            check(retainedNewestId.equals(restored.get("snapshotId")), "the newest snapshot must be restorable");
            check(newestContent.equals(Files.readString(documents.resolve("history.txt"))),
                    "the newest retained snapshot must contain the latest content");

            expectFailure(() -> versions.restore(evictedId),
                    "an evicted snapshot must no longer be restorable");

            // A cancelled snapshot must never publish metadata or delete the
            // original file, even though staging work may have started.
            Path protectedFile = Files.writeString(documents.resolve("protected.txt"), "must remain intact");
            int before = versions.list().size();
            expectFailure(() -> versions.snapshotAndDelete(root.id(), "protected.txt", 4),
                    "an oversized referenced file must cancel snapshot and deletion");
            check(Files.exists(protectedFile) && "must remain intact".equals(Files.readString(protectedFile)),
                    "a cancelled snapshot must leave the original file unchanged");
            check(versions.list().size() == before,
                    "a cancelled snapshot must not publish partial metadata");
            try (var entries = Files.list(data.resolve("reference-versions"))) {
                check(entries.noneMatch(entry -> entry.getFileName().toString().endsWith(".tmp")),
                        "cancelled snapshot staging files must be cleaned up");
            }

            System.out.println("PASS: referenced snapshots evict oldest first, retain the newest recovery point, and cancel partial snapshots without touching originals.");
        } finally {
            try (var paths = Files.walk(workspace)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException | IllegalStateException expected) {
            // Expected: invalid, evicted or cancelled snapshot work fails closed.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
