package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

public final class StorageWatcherTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("personalcloud-watcher-test-");
        try (StorageWatcher watcher = new StorageWatcher(root)) {
            long initial = watcher.revision();
            Files.writeString(root.resolve("external.txt"), "external file change");
            awaitRevision(watcher, initial, "file create/modify");
            long afterFile = watcher.revision();
            Path nested = Files.createDirectory(root.resolve("nested"));
            awaitRevision(watcher, afterFile, "directory create");
            long afterDirectory = watcher.revision();
            Files.writeString(nested.resolve("child.txt"), "nested external file");
            awaitRevision(watcher, afterDirectory, "new nested directory registration");
        } finally {
            try (var paths = Files.walk(root)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: storage WatchService detects external file changes, new folders, and changes inside newly registered folders.");
    }

    private static void awaitRevision(StorageWatcher watcher, long previous, String label) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(4).toNanos();
        while (System.nanoTime() < deadline) {
            if (watcher.revision() > previous) return;
            Thread.sleep(25);
        }
        throw new AssertionError("Storage watcher did not detect " + label + ".");
    }
}
