package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public final class VersionServiceTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("personalcloud-version-test-");
        Path storage = Files.createDirectory(base.resolve("storage"));
        Path data = Files.createDirectory(base.resolve("data"));
        try (FileService files = new FileService(storage)) {
            VersionService versions = new VersionService(data, files);
            Path source = storage.resolve("history.txt");
            String finalContent = "snapshot-21";
            for (int i = 1; i <= 21; i++) {
                String content = "snapshot-" + i;
                Files.writeString(source, content);
                versions.snapshot("history.txt", "MANUAL", 1024);
                finalContent = content;
            }
            List<Map<String, Object>> history = versions.list("history.txt");
            if (history.size() != 20) throw new AssertionError("Per-path snapshot retention is not bounded: " + history.size());
            String newestId = String.valueOf(history.get(0).get("id"));
            versions.restore(newestId, "history-restored.txt", 1024);
            String restored = Files.readString(storage.resolve("history-restored.txt"));
            if (!finalContent.equals(restored)) throw new AssertionError("Latest snapshot restore content mismatch.");
        } finally {
            try (var paths = Files.walk(base)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: version snapshot retention is bounded per path and latest snapshot restores with integrity verification.");
    }
}
