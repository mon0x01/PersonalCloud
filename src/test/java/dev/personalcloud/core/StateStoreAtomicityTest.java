package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Failure-injection tests for the in-memory/disk consistency boundary. */
public final class StateStoreAtomicityTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-state-atomicity-");
        Path dataDirectory = Files.createDirectory(base.resolve("data"));
        Path movedDirectory = base.resolve("data-moved");
        try {
            StateStore store = new StateStore(dataDirectory);
            store.put("stable", "before");
            store.putRecord("sample", "record-1", Map.of("value", "before"));

            // Make the configured parent unwritable in a deterministic way: replace it with a file.
            Files.move(dataDirectory, movedDirectory);
            Files.writeString(dataDirectory, "not a directory");

            expectPersistenceFailure(() -> store.put("stable", "after"));
            expectPersistenceFailure(() -> store.remove("stable"));
            expectPersistenceFailure(() -> store.putRecord("sample", "record-1", Map.of("value", "after")));
            expectPersistenceFailure(() -> store.removeRecord("sample", "record-1"));

            Files.delete(dataDirectory);
            Files.move(movedDirectory, dataDirectory);
            check("before".equals(store.get("stable")), "failed key mutations must leave the persisted value unchanged");
            check("before".equals(store.getRecord("sample", "record-1").get("value")),
                    "failed record mutations must leave the persisted record unchanged");
            StateStore reopened = new StateStore(dataDirectory);
            check("before".equals(reopened.get("stable")), "reopened store must observe original key state");
            check("before".equals(reopened.getRecord("sample", "record-1").get("value")),
                    "reopened store must observe original record state");
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: StateStore rolls back key and record mutations when lock/persistence fails.");
    }

    private static void expectPersistenceFailure(ThrowingAction action) throws Exception {
        try { action.run(); throw new AssertionError("Expected persistence failure."); }
        catch (java.nio.file.FileSystemException expected) { }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
