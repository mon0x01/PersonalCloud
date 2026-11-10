package dev.personalcloud.core;

import dev.personalcloud.net.Json;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Audit-log concurrency, rotation, retention and symlink-safety tests. */
public final class AuditLogConcurrencyTest {
    public static void main(String[] args) throws Exception {
        concurrentInstancesAppendWholeRecords();
        rotationRetainsNewestAndReadsBothFiles();
        malformedAndSymlinkedLogsFailSafely();
        System.out.println("PASS: audit records remain whole across concurrent instances, rotation preserves "
                + "newest-first reads, malformed lines are skipped and symlinked logs are rejected.");
    }

    private static void concurrentInstancesAppendWholeRecords() throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-audit-concurrency-");
        try {
            AuditLog first = new AuditLog(workspace, 1024 * 1024);
            AuditLog second = new AuditLog(workspace, 1024 * 1024);
            int threads = 8;
            int perThread = 40;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> futures = new ArrayList<>();
            for (int thread = 0; thread < threads; thread++) {
                int index = thread;
                futures.add(pool.submit(() -> {
                    start.await();
                    AuditLog log = index % 2 == 0 ? first : second;
                    for (int event = 0; event < perThread; event++) {
                        log.record("EVENT", "actor-" + index, "seq=" + event);
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) future.get();
            pool.shutdown();

            List<String> lines = Files.readAllLines(workspace.resolve("activity.jsonl"), StandardCharsets.UTF_8);
            check(lines.size() == threads * perThread,
                    "every concurrent append must produce exactly one complete line");
            Set<String> identities = new HashSet<>();
            for (String line : lines) {
                Map<String, Object> row = Json.object(line);
                String identity = row.get("actor") + "/" + row.get("detail");
                check(identities.add(identity), "concurrent audit lines must not be duplicated or interleaved");
            }
            check(identities.size() == threads * perThread,
                    "all concurrent audit records must survive without corruption");
        } finally {
            deleteTree(workspace);
        }
    }

    private static void rotationRetainsNewestAndReadsBothFiles() throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-audit-rotation-");
        try {
            AuditLog log = new AuditLog(workspace, 250);
            for (int index = 0; index < 12; index++) {
                log.record("E" + index, "rotation-actor", "detail-" + index + "-" + "x".repeat(40));
            }
            check(Files.exists(workspace.resolve("activity.previous.jsonl")),
                    "rotation must retain the previous audit file");
            List<Map<String, Object>> recent = log.recent(200);
            check(!recent.isEmpty(), "recent audit history must include rotated records");
            check("E11".equals(recent.get(0).get("event")), "recent audit history must be newest-first");
            List<Integer> indexes = new ArrayList<>();
            for (Map<String, Object> row : recent) {
                indexes.add(Integer.parseInt(String.valueOf(row.get("event")).substring(1)));
            }
            for (int index = 1; index < indexes.size(); index++) {
                check(indexes.get(index) == indexes.get(index - 1) - 1,
                        "retained audit records must remain in chronological order");
            }
            check(recent.size() <= 200, "audit reads must remain bounded");
            check(log.recent(1).size() == 1, "the audit read limit must be honored");

            // Concurrent appends with aggressive rotation must still leave only
            // parseable whole lines in both retained files.
            AuditLog rotating = new AuditLog(workspace, 300);
            ExecutorService pool = Executors.newFixedThreadPool(4);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> futures = new ArrayList<>();
            for (int thread = 0; thread < 4; thread++) {
                int index = thread;
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int event = 0; event < 30; event++) {
                        rotating.record("ROTATE", "writer-" + index, "seq=" + event);
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) future.get();
            pool.shutdown();
            for (String file : List.of("activity.jsonl", "activity.previous.jsonl")) {
                Path path = workspace.resolve(file);
                if (!Files.exists(path)) continue;
                for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                    if (!line.isBlank()) Json.object(line);
                }
            }
            check(!rotating.recent(200).isEmpty(), "rotated audit history must remain readable");
        } finally {
            deleteTree(workspace);
        }
    }

    private static void malformedAndSymlinkedLogsFailSafely() throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-audit-integrity-");
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Files.writeString(data.resolve("activity.jsonl"),
                    "{\"event\":\"FIRST\",\"actor\":\"a\",\"detail\":\"1\"}\n"
                            + "not-json\n"
                            + "{\"event\":\"SECOND\",\"actor\":\"b\",\"detail\":\"2\"}\n",
                    StandardCharsets.UTF_8);
            AuditLog log = new AuditLog(data, 1024 * 1024);
            List<Map<String, Object>> rows = log.recent(10);
            check(rows.size() == 2, "malformed audit lines must be skipped");
            check("SECOND".equals(rows.get(0).get("event")) && "FIRST".equals(rows.get(1).get("event")),
                    "valid audit records around a malformed line must survive");

            Path symlinkData = Files.createDirectory(workspace.resolve("symlink-data"));
            Path target = workspace.resolve("outside-audit.jsonl");
            Files.writeString(target, "do not follow", StandardCharsets.UTF_8);
            Files.createSymbolicLink(symlinkData.resolve("activity.jsonl"), target);
            expectSecurity(() -> new AuditLog(symlinkData, 1024),
                    "a symlinked audit log must be rejected");
            check(Files.isSymbolicLink(symlinkData.resolve("activity.jsonl")),
                    "rejecting a symlinked log must not replace the link");
            check("do not follow".equals(Files.readString(target, StandardCharsets.UTF_8)),
                    "rejecting a symlinked log must not modify its target");
        } finally {
            deleteTree(workspace);
        }
    }

    private static void expectSecurity(ThrowingRunnable operation, String message) throws Exception {
        try {
            operation.run();
            throw new AssertionError(message);
        } catch (SecurityException expected) { }
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
