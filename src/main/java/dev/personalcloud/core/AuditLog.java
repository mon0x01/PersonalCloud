package dev.personalcloud.core;

import dev.personalcloud.net.Json;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only local security/activity log. Secrets and file contents must never
 * be passed here.
 *
 * <p>The protocol server, local-control server and future native adapters may
 * each hold an AuditLog instance for the same data directory. Appends and
 * rotations are serialized with a JVM lock and an operating-system file lock so
 * two components cannot interleave a record or race a rotation. Every append is
 * forced to disk before the operation returns; audit loss must not silently
 * follow a reported success.</p>
 */
public final class AuditLog {
    private static final long DEFAULT_MAX_BYTES = 5L * 1024 * 1024;
    private static final int MAX_RECENT = 200;
    private static final ConcurrentHashMap<Path, ReentrantLock> JVM_LOCKS = new ConcurrentHashMap<>();

    private final Path file;
    private final Path previous;
    private final Path lockFile;
    private final long maxBytes;
    private final ReentrantLock jvmLock;

    public AuditLog(Path dataDirectory) throws Exception {
        this(dataDirectory, DEFAULT_MAX_BYTES);
    }

    AuditLog(Path dataDirectory, long maxBytes) throws Exception {
        if (dataDirectory == null) throw new IllegalArgumentException("An audit data directory is required.");
        if (maxBytes < 1) throw new IllegalArgumentException("Audit rotation size must be positive.");
        Path supplied = dataDirectory.toAbsolutePath().normalize();
        Files.createDirectories(supplied);
        if (Files.isSymbolicLink(supplied) || !Files.isDirectory(supplied, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("PersonalCloud audit directory must be a real directory, not a symbolic link.");
        }
        Path canonical = supplied.toRealPath();
        this.file = canonical.resolve("activity.jsonl");
        this.previous = canonical.resolve("activity.previous.jsonl");
        this.lockFile = canonical.resolve("activity.lock");
        this.maxBytes = maxBytes;
        this.jvmLock = JVM_LOCKS.computeIfAbsent(lockFile, ignored -> new ReentrantLock(true));
        ensureRegularIfPresent(file, "audit log");
        ensureRegularIfPresent(previous, "audit rotation log");
        ensureRegularIfPresent(lockFile, "audit lock");
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) Files.createFile(file);
        SecretFiles.restrict(file);
        SecretFiles.restrict(previous);
        SecretFiles.restrict(lockFile);
    }

    public void record(String event, String actor, String detail) {
        try {
            append(event, actor, detail);
        } catch (Exception ignored) {
            // Audit failure must not turn a successful file operation into an ambiguous HTTP response.
        }
    }

    /** Newest-first audit records from the current and one retained rotation. */
    public synchronized List<Map<String, Object>> recent(int limit) {
        int bounded = Math.max(1, Math.min(limit, MAX_RECENT));
        try {
            jvmLock.lockInterruptibly();
            try (FileChannel lockChannel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                 FileLock ignored = lockChannel.lock()) {
                SecretFiles.restrict(lockFile);
                ensureRegularIfPresent(file, "audit log");
                ensureRegularIfPresent(previous, "audit rotation log");
                List<Map<String, Object>> rows = new ArrayList<>();
                readRows(previous, rows);
                readRows(file, rows);
                List<Map<String, Object>> result = new ArrayList<>();
                for (int index = rows.size() - 1; index >= 0 && result.size() < bounded; index--) {
                    result.add(rows.get(index));
                }
                return List.copyOf(result);
            } finally {
                jvmLock.unlock();
            }
        } catch (Exception unavailable) {
            return List.of();
        }
    }

    private void append(String event, String actor, String detail) throws Exception {
        jvmLock.lockInterruptibly();
        try (FileChannel lockChannel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
             FileLock ignored = lockChannel.lock()) {
            SecretFiles.restrict(lockFile);
            ensureRegularIfPresent(file, "audit log");
            ensureRegularIfPresent(previous, "audit rotation log");
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) Files.createFile(file);
            if (Files.size(file) >= maxBytes) rotate();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("time", Instant.now().toString());
            row.put("event", event);
            row.put("actor", actor == null ? "unknown" : actor);
            row.put("detail", detail == null ? "" : detail);
            byte[] bytes = (Json.stringify(row) + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(false);
            }
            SecretFiles.restrict(file);
        } finally {
            jvmLock.unlock();
        }
    }

    private void rotate() throws Exception {
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.move(file, previous, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(file, previous, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) Files.createFile(file);
        SecretFiles.restrict(file);
        SecretFiles.restrict(previous);
    }

    private static void readRows(Path path, List<Map<String, Object>> rows) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return;
        try {
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                try {
                    rows.add(Json.object(line));
                } catch (RuntimeException malformed) {
                    // A torn historical line must not hide later valid records.
                }
            }
        } catch (IOException unreadable) {
            // A missing or unreadable rotation is treated as empty.
        }
    }

    private static void ensureRegularIfPresent(Path path, String label) {
        if (Files.isSymbolicLink(path)) {
            throw new SecurityException("PersonalCloud " + label + " cannot be a symbolic link.");
        }
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("PersonalCloud " + label + " must be a regular file.");
        }
    }
}
