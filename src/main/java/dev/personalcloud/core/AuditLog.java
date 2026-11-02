package dev.personalcloud.core;

import dev.personalcloud.net.Json;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Append-only local security/activity log. Secrets and file contents must never be passed here. */
public final class AuditLog {
    private static final long MAX_BYTES = 5L * 1024 * 1024;
    private final Path file;

    public AuditLog(Path dataDirectory) throws Exception {
        file = dataDirectory.resolve("activity.jsonl");
        if (!Files.exists(file)) Files.createFile(file);
        SecretFiles.restrict(file);
    }

    public synchronized void record(String event, String actor, String detail) {
        try {
            if (Files.size(file) > MAX_BYTES) {
                Path previous = file.resolveSibling("activity.previous.jsonl");
                Files.move(file, previous, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                Files.createFile(file);
                SecretFiles.restrict(previous);
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("time", Instant.now().toString());
            row.put("event", event);
            row.put("actor", actor == null ? "unknown" : actor);
            row.put("detail", detail == null ? "" : detail);
            Files.writeString(file, Json.stringify(row) + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            SecretFiles.restrict(file);
        } catch (Exception ignored) {
            // Audit failure must not turn a successful file operation into an ambiguous HTTP response.
        }
    }

    public synchronized List<Map<String, Object>> recent(int limit) {
        try {
            List<String> lines = Files.readAllLines(file);
            List<Map<String, Object>> result = new ArrayList<>();
            for (int i = Math.max(0, lines.size() - Math.max(1, Math.min(limit, 200))); i < lines.size(); i++) {
                try { result.add(Json.object(lines.get(i))); } catch (Exception ignored) { }
            }
            java.util.Collections.reverse(result);
            return result;
        } catch (Exception ignored) { return List.of(); }
    }
}
