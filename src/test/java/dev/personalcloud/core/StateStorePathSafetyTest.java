package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;

/** Rejects filesystem indirection at state and lock boundaries. */
public final class StateStorePathSafetyTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-state-path-safety-");
        try {
            Path data = Files.createDirectory(base.resolve("data"));
            Path outside = Files.writeString(base.resolve("outside"), "must-not-be-followed");

            Files.createSymbolicLink(data.resolve("state.properties.lock"), outside);
            expectSecurity(() -> new StateStore(data), "lock symlink must be rejected");
            Files.delete(data.resolve("state.properties.lock"));

            Files.createSymbolicLink(data.resolve("state.properties"), outside);
            expectSecurity(() -> new StateStore(data), "state symlink must be rejected");
            Files.delete(data.resolve("state.properties"));

            Files.createSymbolicLink(data.resolve("state.properties.bak"), outside);
            expectSecurity(() -> new StateStore(data), "backup symlink must be rejected");
            Files.delete(data.resolve("state.properties.bak"));

            Path linkedDirectory = base.resolve("linked-data");
            Files.createSymbolicLink(linkedDirectory, data);
            expectSecurity(() -> new StateStore(linkedDirectory), "state directory symlink must be rejected");
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: StateStore rejects symlinked state, backup, lock and data-directory paths.");
    }

    private static void expectSecurity(ThrowingAction action, String message) throws Exception {
        try { action.run(); throw new AssertionError(message); }
        catch (SecurityException expected) { }
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
