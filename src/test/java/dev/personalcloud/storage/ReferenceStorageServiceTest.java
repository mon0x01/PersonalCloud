package dev.personalcloud.storage;

import dev.personalcloud.core.StateStore;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/** Dependency-free regression tests for V2 zero-copy referenced storage. */
public final class ReferenceStorageServiceTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-reference-test-");
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path managed = Files.createDirectory(workspace.resolve("managed"));
            Path reference = Files.createDirectory(workspace.resolve("existing-documents"));
            Path nested = Files.createDirectory(reference.resolve("Projects"));
            Path original = Files.writeString(nested.resolve("Design Notes.md"), "existing file stays in place\n");
            byte[] originalBytes = Files.readAllBytes(original);
            String originalSha = sha256(originalBytes);

            StateStore store = new StateStore(data);
            ReferenceStorageService service = new ReferenceStorageService(store, data, managed);

            ReferenceRoot root = service.register("Documents", reference);
            check(root.availability() == ReferenceRoot.Availability.AVAILABLE, "new root should be available");
            check(Files.exists(original), "registration must not move the original file");
            check(Files.isSameFile(original, reference.resolve("Projects/Design Notes.md")), "registration must preserve the original inode/path");
            check(countRegularFiles(managed) == 0, "registration must not copy data into managed storage");

            List<StorageEntry> topLevel = service.listEntries(root.id(), "");
            check(topLevel.size() == 1, "top-level listing should show the Projects directory");
            check(topLevel.get(0).kind() == StorageEntry.Kind.DIRECTORY, "directory kind should be reported");
            check(topLevel.get(0).relativePath().equals("Projects"), "portable relative path should be returned");

            List<StorageEntry> projectEntries = service.listEntries(root.id(), "Projects");
            check(projectEntries.size() == 1, "nested listing should show one file");
            StorageEntry entry = projectEntries.get(0);
            check(entry.kind() == StorageEntry.Kind.FILE, "file kind should be reported");
            check(entry.name().equals("Design Notes.md"), "file name should be preserved");
            check(entry.sizeBytes() == originalBytes.length, "metadata should report original size");

            try (InputStream stream = service.openFile(root.id(), "Projects/Design Notes.md")) {
                check(java.util.Arrays.equals(stream.readAllBytes(), originalBytes), "read stream must return original bytes");
            }
            check(service.sha256(root.id(), "Projects/Design Notes.md").equals(originalSha), "SHA-256 should match original bytes");
            check(service.search("design", 20).size() == 1, "search should match file names case-insensitively");
            check(service.search("projects", 20).stream().anyMatch(item -> item.kind() == StorageEntry.Kind.DIRECTORY),
                    "search should include matching directories");

            // State-backed registration must survive reconstructing the service.
            ReferenceStorageService restarted = new ReferenceStorageService(new StateStore(data), data, managed);
            check(restarted.listRoots().size() == 1, "registered roots should persist across restart");
            check(restarted.listRoots().get(0).id().equals(root.id()), "root identity should remain stable");

            expectFailure(() -> restarted.listEntries(root.id(), "../data"), "path traversal must be rejected");
            expectFailure(() -> restarted.listEntries(root.id(), "/etc"), "absolute paths must be rejected");
            expectFailure(() -> restarted.listEntries(root.id(), "Projects/./Design Notes.md"), "dot segments must be rejected");
            expectFailure(() -> restarted.search("a", 20), "one-character searches must be rejected");
            expectFailure(() -> restarted.search("design", 201), "unbounded search results must be rejected");

            Path outside = Files.writeString(workspace.resolve("outside-secret.txt"), "must not be exposed\n");
            Path link = reference.resolve("escape.txt");
            try {
                Files.createSymbolicLink(link, outside);
                check(restarted.listEntries(root.id(), "").stream().noneMatch(item -> item.name().equals("escape.txt")),
                        "symbolic links must not appear in listings");
                expectFailure(() -> restarted.openFile(root.id(), "escape.txt"), "symbolic-link reads must be rejected");
            } catch (UnsupportedOperationException | java.nio.file.FileSystemException | SecurityException unsupported) {
                // Some CI filesystems prohibit symlink creation; traversal tests still run.
            }

            expectFailure(() -> restarted.register("Managed overlap", managed.resolve(".")),
                    "managed storage must not be re-registered as reference storage");
            expectFailure(() -> restarted.register("Data overlap", data),
                    "application data must not be registered as user storage");
            expectFailure(() -> restarted.register("Nested overlap", reference.resolve("Projects")),
                    "overlapping reference roots must be rejected");
            expectFailure(() -> restarted.register("Documents", Files.createDirectory(workspace.resolve("another-documents"))),
                    "display names must be unique");

            restarted.unregister(root.id());
            check(restarted.listRoots().isEmpty(), "unregister should remove the reference record");
            check(Files.exists(original), "unregister must not delete the original file");
            check(java.util.Arrays.equals(Files.readAllBytes(original), originalBytes), "unregister must not alter original bytes");

            ReferenceRoot missing = restarted.register("Temporary", reference);
            Path moved = workspace.resolve("renamed-documents");
            Files.move(reference, moved);
            check(restarted.listRoots().stream().filter(item -> item.id().equals(missing.id())).findFirst().orElseThrow().availability()
                    == ReferenceRoot.Availability.MISSING, "unavailable references should be visible as missing");
        } finally {
            deleteTree(workspace);
        }
        System.out.println("PASS: referenced storage is zero-copy, persistent, read-only, searchable, bounded, and rejects unsafe paths.");
    }

    private static long countRegularFiles(Path root) throws Exception {
        try (var paths = Files.walk(root)) { return paths.filter(Files::isRegularFile).count(); }
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void expectFailure(ThrowingRunnable operation, String message) throws Exception {
        try {
            operation.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException | SecurityException | java.io.IOException expected) {
            // Expected rejection.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (Exception ignored) { }
            });
        }
    }

    @FunctionalInterface private interface ThrowingRunnable { void run() throws Exception; }
}
