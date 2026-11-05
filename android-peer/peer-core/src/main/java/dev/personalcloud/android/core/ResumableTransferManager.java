package dev.personalcloud.android.core;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.BiFunction;

/**
 * Durable, chunked receiver for direct peer-to-peer managed-file transfers.
 * Session metadata and verified chunks survive process restarts. A session is
 * bound to its authenticated uploader node; commit delegates final publication
 * to the platform's existing no-overwrite managed-storage implementation.
 */
public final class ResumableTransferManager {
    public static final int DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024;
    private static final long SESSION_TTL_MILLIS = 7L * 24 * 60 * 60 * 1000;
    private static final int MAX_SESSIONS = 16;

    @FunctionalInterface
    public interface Committer {
        Map<String, Object> commit(String transferId, String uploaderNodeId, String relativePath,
                                   InputStream content, long size, String sha256) throws Exception;
    }

    private final Path root;
    private final String ownerNodeId;
    private final long maxFileBytes;
    private final int chunkBytes;
    private final Committer committer;
    private final java.util.concurrent.locks.ReentrantLock[] sessionLocks = createSessionLocks();

    public ResumableTransferManager(Path dataDirectory, String ownerNodeId, long maxFileBytes,
                                    Committer committer) throws Exception {
        this(dataDirectory, ownerNodeId, maxFileBytes, DEFAULT_CHUNK_BYTES, committer);
    }

    public ResumableTransferManager(Path dataDirectory, String ownerNodeId, long maxFileBytes,
                                    int chunkBytes, Committer committer) throws Exception {
        if (ownerNodeId == null || ownerNodeId.isBlank()) throw new IllegalArgumentException("Owner node identity is required.");
        if (maxFileBytes < 0 || chunkBytes < 64 * 1024 || chunkBytes > 16 * 1024 * 1024) {
            throw new IllegalArgumentException("Invalid transfer size limits.");
        }
        this.ownerNodeId = ownerNodeId;
        this.maxFileBytes = maxFileBytes;
        this.chunkBytes = chunkBytes;
        this.committer = Objects.requireNonNull(committer);
        Files.createDirectories(dataDirectory);
        if (Files.isSymbolicLink(dataDirectory)) throw new SecurityException("Transfer data directory cannot be a symbolic link.");
        this.root = dataDirectory.toRealPath();
        restrictDirectory(this.root);
        cleanupExpired();
    }

    public synchronized Map<String, Object> create(String uploaderNodeId, String relativePath,
                                                    long size, String sha256) throws Exception {
        return create(uploaderNodeId, UUID.randomUUID().toString(), relativePath, size, sha256);
    }

    /** Creates or idempotently reopens a session using a sender-generated stable UUID. */
    public synchronized Map<String, Object> create(String uploaderNodeId, String requestedTransferId,
                                                    String relativePath, long size, String sha256) throws Exception {
        requireUploader(uploaderNodeId);
        String id = normalizeTransferId(requestedTransferId);
        String path = normalizePath(relativePath);
        String digest = normalizeHash(sha256);
        if (size < 0 || size > maxFileBytes) throw new IllegalArgumentException("Transfer size exceeds this node's limit.");
        cleanupExpired();
        Path requestedDirectory = sessionDirectory(id);
        if (Files.exists(requestedDirectory, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(requestedDirectory) || !Files.isDirectory(requestedDirectory, LinkOption.NOFOLLOW_LINKS)) {
                throw new SecurityException("Transfer identifier is occupied by an unsafe filesystem entry.");
            }
            Path existingJournal = requestedDirectory.resolve("session.properties");
            verifyRegular(existingJournal, "transfer journal");
            Properties existing = new Properties();
            try (InputStream input = Files.newInputStream(existingJournal, LinkOption.NOFOLLOW_LINKS)) { existing.load(input); }
            if (!uploaderNodeId.equals(existing.getProperty("uploader"))
                    || !path.equals(existing.getProperty("path"))
                    || size != number(existing, "size")
                    || !digest.equals(existing.getProperty("sha256"))) {
                throw new SecurityException("Transfer identifier already belongs to a different session.");
            }
            return statusFor(id, existing);
        }
        List<Path> active = sessionDirectories();
        long activeCount = 0;
        long reserved = 0;
        for (Path existingDir : active) {
            Path journal = existingDir.resolve("session.properties");
            if (!Files.isRegularFile(journal, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(journal)) continue;
            Properties existing = new Properties();
            try (InputStream input = Files.newInputStream(journal, LinkOption.NOFOLLOW_LINKS)) { existing.load(input); }
            if (!"COMMITTED".equals(existing.getProperty("state"))) {
                activeCount++;
                reserved = Math.addExact(reserved, number(existing, "size"));
            }
        }
        if (activeCount >= MAX_SESSIONS) throw new IllegalStateException("This node has reached its active transfer-session limit.");
        long reservationLimit = maxFileBytes > Long.MAX_VALUE / 2 ? Long.MAX_VALUE : maxFileBytes * 2;
        if (size > reservationLimit - Math.min(reserved, reservationLimit)) {
            throw new IllegalStateException("Active transfer sessions exceed the receiver's reserved staging budget.");
        }
        if (size > Files.getFileStore(root).getUsableSpace()) {
            throw new IllegalStateException("Not enough free space in the transfer staging volume.");
        }
        Path dir = sessionDirectory(id);
        Files.createDirectory(dir);
        restrictDirectory(dir);
        Properties p = new Properties();
        p.setProperty("uploader", uploaderNodeId);
        p.setProperty("path", path);
        p.setProperty("size", Long.toString(size));
        p.setProperty("sha256", digest);
        p.setProperty("chunkBytes", Integer.toString(chunkBytes));
        p.setProperty("createdAt", Long.toString(System.currentTimeMillis()));
        p.setProperty("state", "RECEIVING");
        save(dir, p);
        return statusFor(id, p);
    }

    public Map<String, Object> receiveChunk(String uploaderNodeId, String id, int index,
                                                          long contentLength, String expectedSha256,
                                                          InputStream input) throws Exception {
        java.util.concurrent.locks.ReentrantLock sessionLock = lockFor(id);
        sessionLock.lock();
        try {
        Properties p = requireSession(uploaderNodeId, id);
        if ("COMMITTED".equals(p.getProperty("state"))) throw new IllegalStateException("Transfer is already committed.");
        long size = number(p, "size");
        int chunks = chunkCount(size);
        if (index < 0 || index >= chunks) throw new IllegalArgumentException("Chunk index is outside the transfer.");
        long expectedLength = Math.min((long) chunkBytes, size - (long) index * chunkBytes);
        if (contentLength != expectedLength) throw new IllegalArgumentException("Chunk length does not match its expected range.");
        String expectedHash = normalizeHash(expectedSha256);
        Path dir = sessionDirectory(id);
        Path target = dir.resolve(chunkName(index));
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            verifyRegular(target, "chunk");
            String existingHash = sha256(target);
            if (!existingHash.equals(expectedHash) || Files.size(target) != expectedLength) {
                throw new SecurityException("A different payload was already committed for this chunk.");
            }
            return statusFor(id, p);
        }

        Path temp = dir.resolve(chunkName(index) + ".tmp-" + UUID.randomUUID());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try {
            try (OutputStream output = Files.newOutputStream(temp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[64 * 1024];
                while (copied < expectedLength) {
                    int read = input.read(buffer, 0, (int)Math.min(buffer.length, expectedLength - copied));
                    if (read < 0) throw new EOFException("Chunk ended before its declared length.");
                    if (read == 0) continue;
                    copied = Math.addExact(copied, read);
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
                output.flush();
            }
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) { channel.force(true); }
            restrictFile(temp);
            String actual = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedLength || !MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    expectedHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new SecurityException("Chunk failed its length or SHA-256 verification.");
            }
            try {
                // Hard-link publication is atomic and create-if-absent on the same filesystem.
                Files.createLink(target, temp);
                Files.delete(temp);
            } catch (FileAlreadyExistsException race) {
                if (!sha256(target).equals(expectedHash) || Files.size(target) != expectedLength) {
                    throw new SecurityException("Conflicting chunk raced with this transfer.");
                }
            } catch (UnsupportedOperationException unsupported) {
                throw new IOException("Transfer storage does not support atomic no-overwrite chunk publication.", unsupported);
            }
            // The chunk file is the durable source of truth. The journal is advisory and can be rebuilt.
            p.setProperty("chunk." + index, actual);
            save(dir, p);
            return statusFor(id, p);
        } finally {
            Files.deleteIfExists(temp);
        }

        } finally {
            sessionLock.unlock();
        }

    }

    public Map<String, Object> status(String uploaderNodeId, String id) throws Exception {
        java.util.concurrent.locks.ReentrantLock sessionLock = lockFor(id);
        sessionLock.lock();
        try {
        return statusFor(id, requireSession(uploaderNodeId, id));

        } finally {
            sessionLock.unlock();
        }

    }

    public Map<String, Object> commit(String uploaderNodeId, String id) throws Exception {
        java.util.concurrent.locks.ReentrantLock sessionLock = lockFor(id);
        sessionLock.lock();
        try {
        Properties p = requireSession(uploaderNodeId, id);
        if ("COMMITTED".equals(p.getProperty("state"))) return committedReceipt(id, p);
        long size = number(p, "size");
        int count = chunkCount(size);
        Path dir = sessionDirectory(id);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        for (int i = 0; i < count; i++) {
            Path chunk = dir.resolve(chunkName(i));
            if (!Files.exists(chunk, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Transfer is incomplete; missing chunk " + i + ".");
            verifyRegular(chunk, "chunk");
            long expected = Math.min((long) chunkBytes, size - (long) i * chunkBytes);
            if (Files.size(chunk) != expected) throw new SecurityException("A persisted chunk has an invalid size.");
            try (InputStream input = Files.newInputStream(chunk, LinkOption.NOFOLLOW_LINKS)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    digest.update(buffer, 0, read);
                }
            }
        }
        String actual = HexFormat.of().formatHex(digest.digest());
        if (copied != size || !actual.equals(p.getProperty("sha256"))) {
            throw new SecurityException("Assembled transfer failed full-file size or SHA-256 verification.");
        }
        Map<String, Object> committed;
        try (InputStream input = new ChunkSequenceInputStream(dir, count)) {
            committed = committer.commit(id, uploaderNodeId, p.getProperty("path"), input, size, actual);
        }
        // Persist the publication receipt before releasing staged chunks. If the process dies
        // after the managed file is published but before the sender saves its receipt, the next
        // status/create/commit call can recover the exact same result without retransferring bytes.
        p.setProperty("state", "COMMITTED");
        p.setProperty("committedAt", Long.toString(System.currentTimeMillis()));
        for (String key : List.of("fileId", "path", "size", "sha256")) {
            Object value = committed.get(key);
            if (value != null && (value instanceof String || value instanceof Number)) {
                p.setProperty("receipt." + key, String.valueOf(value));
            }
        }
        save(dir, p);
        for (int i = 0; i < count; i++) Files.deleteIfExists(dir.resolve(chunkName(i)));
        return committedReceipt(id, p);

        } finally {
            sessionLock.unlock();
        }

    }

    public void abort(String uploaderNodeId, String id) throws Exception {
        java.util.concurrent.locks.ReentrantLock sessionLock = lockFor(id);
        sessionLock.lock();
        try {
        Properties p = requireSession(uploaderNodeId, id);
        if ("COMMITTED".equals(p.getProperty("state"))) {
            throw new IllegalStateException("A committed managed file cannot be aborted; use managed-file deletion instead.");
        }
        deleteTree(sessionDirectory(id));

        } finally {
            sessionLock.unlock();
        }

    }

    private Map<String, Object> statusFor(String id, Properties p) throws Exception {
        long size = number(p, "size");
        int count = chunkCount(size);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("transferId", id);
        result.put("path", p.getProperty("path"));
        result.put("size", size);
        result.put("sha256", p.getProperty("sha256"));
        if ("COMMITTED".equals(p.getProperty("state"))) {
            result.put("state", "COMMITTED");
            result.put("chunkSize", chunkBytes);
            result.put("chunkCount", count);
            result.put("receivedChunks", List.of());
            result.put("receivedBytes", size);
            result.put("remainingBytes", 0L);
            result.put("receipt", receiptMap(p));
            result.put("committedAt", p.getProperty("committedAt", ""));
            return result;
        }
        List<Integer> received = new ArrayList<>();
        long receivedBytes = 0;
        for (int i = 0; i < count; i++) {
            Path chunk = sessionDirectory(id).resolve(chunkName(i));
            if (Files.exists(chunk, LinkOption.NOFOLLOW_LINKS)) {
                verifyRegular(chunk, "chunk");
                long expected = Math.min((long) chunkBytes, size - (long) i * chunkBytes);
                if (Files.size(chunk) != expected) throw new SecurityException("Persisted chunk size is invalid.");
                received.add(i);
                receivedBytes += expected;
            }
        }
        result.put("state", received.size() == count ? "READY_TO_COMMIT" : "RECEIVING");
        result.put("chunkSize", chunkBytes);
        result.put("chunkCount", count);
        result.put("receivedChunks", List.copyOf(received));
        result.put("receivedBytes", receivedBytes);
        result.put("remainingBytes", size - receivedBytes);
        return result;
    }

    private static Map<String, Object> receiptMap(Properties p) {
        Map<String, Object> receipt = new LinkedHashMap<>();
        receipt.put("fileId", p.getProperty("receipt.fileId", ""));
        receipt.put("path", p.getProperty("receipt.path", p.getProperty("path", "")));
        receipt.put("size", parseReceiptLong(p.getProperty("receipt.size"), number(p, "size")));
        receipt.put("sha256", p.getProperty("receipt.sha256", p.getProperty("sha256", "")));
        return receipt;
    }

    private static long parseReceiptLong(String value, long fallback) {
        try { return Long.parseLong(value); } catch (Exception invalid) { return fallback; }
    }

    private static Map<String, Object> committedReceipt(String id, Properties p) {
        Map<String, Object> result = new LinkedHashMap<>(receiptMap(p));
        result.put("transferId", id);
        result.put("transferState", "COMMITTED");
        return result;
    }

    private Properties requireSession(String uploader, String id) throws Exception {
        requireUploader(uploader);
        if (id == null || !id.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Invalid transfer identifier.");
        Path dir = sessionDirectory(id);
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(dir)) throw new IllegalArgumentException("Transfer session not found.");
        Path journal = dir.resolve("session.properties");
        verifyRegular(journal, "transfer journal");
        Properties p = new Properties();
        try (InputStream input = Files.newInputStream(journal, LinkOption.NOFOLLOW_LINKS)) { p.load(input); }
        if (!uploader.equals(p.getProperty("uploader"))) throw new SecurityException("Transfer session belongs to another network member.");
        long expiryBase = "COMMITTED".equals(p.getProperty("state"))
                ? number(p, "committedAt") : number(p, "createdAt");
        if (System.currentTimeMillis() - expiryBase > SESSION_TTL_MILLIS) {
            deleteTree(dir);
            throw new IllegalArgumentException("Transfer session expired.");
        }
        return p;
    }

    private void cleanupExpired() throws Exception {
        for (Path dir : sessionDirectories()) {
            String id = dir.getFileName().toString();
            java.util.concurrent.locks.ReentrantLock sessionLock = lockFor(id);
            sessionLock.lock();
            try {
                Path journal = dir.resolve("session.properties");
                if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
                    throw new SecurityException("Unsafe transfer session entry detected.");
                }
                if (!Files.exists(journal, LinkOption.NOFOLLOW_LINKS)) {
                    // Recover a process crash between creating the session directory and writing its journal.
                    deleteTree(dir);
                    continue;
                }
                verifyRegular(journal, "transfer journal");
                Properties p = new Properties();
                try (InputStream input = Files.newInputStream(journal, LinkOption.NOFOLLOW_LINKS)) { p.load(input); }
                long expiryBase = "COMMITTED".equals(p.getProperty("state"))
                        ? number(p, "committedAt") : number(p, "createdAt");
                if (System.currentTimeMillis() - expiryBase > SESSION_TTL_MILLIS) deleteTree(dir);
            } finally {
                sessionLock.unlock();
            }
        }
    }

    private List<Path> sessionDirectories() throws Exception {
        try (var paths = Files.list(root)) {
            return paths.filter(path -> path.getFileName().toString().matches("[0-9a-fA-F-]{36}")).toList();
        }
    }

    private Path sessionDirectory(String id) throws Exception {
        Path dir = root.resolve(id).normalize();
        if (!dir.getParent().equals(root)) throw new SecurityException("Transfer session escapes its storage root.");
        return dir;
    }

    private void save(Path dir, Properties p) throws Exception {
        Path journal = dir.resolve("session.properties");
        Path temp = dir.resolve("session.properties.tmp-" + UUID.randomUUID());
        try {
            try (OutputStream output = Files.newOutputStream(temp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                p.store(output, "PersonalCloud resumable transfer journal");
            }
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) { channel.force(true); }
            restrictFile(temp);
            try { Files.move(temp, journal, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException unavailable) { Files.move(temp, journal, StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(temp); }
    }

    private int chunkCount(long size) {
        if (size == 0) return 0;
        return Math.toIntExact((size + chunkBytes - 1) / chunkBytes);
    }

    private static java.util.concurrent.locks.ReentrantLock[] createSessionLocks() {
        java.util.concurrent.locks.ReentrantLock[] locks = new java.util.concurrent.locks.ReentrantLock[64];
        for (int i = 0; i < locks.length; i++) locks[i] = new java.util.concurrent.locks.ReentrantLock(true);
        return locks;
    }

    private java.util.concurrent.locks.ReentrantLock lockFor(String sessionId) {
        return sessionLocks[Math.floorMod(sessionId.hashCode(), sessionLocks.length)];
    }

    private void requireUploader(String uploader) {
        if (uploader == null || uploader.isBlank() || uploader.equals(ownerNodeId)) {
            throw new SecurityException("An authenticated remote network member is required.");
        }
    }

    private static String normalizeTransferId(String id) {
        if (id == null) throw new IllegalArgumentException("A transfer identifier is required.");
        try {
            String normalized = UUID.fromString(id).toString();
            if (!normalized.equalsIgnoreCase(id)) throw new IllegalArgumentException("Transfer identifier must be a canonical UUID.");
            return normalized;
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Transfer identifier must be a canonical UUID.", invalid);
        }
    }

    private static long number(Properties p, String key) {
        try { return Long.parseLong(p.getProperty(key)); }
        catch (Exception invalid) { throw new SecurityException("Transfer journal contains invalid " + key + "."); }
    }

    private static String normalizePath(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("A managed destination path is required.");
        String path = value.replace('\\', '/');
        if (path.startsWith("/") || path.matches("^[A-Za-z]:.*") || path.indexOf('\0') >= 0 || path.length() > 1024) {
            throw new IllegalArgumentException("Managed destination must be a safe relative path.");
        }
        for (String part : path.split("/", -1)) {
            if (part.isBlank() || part.equals(".") || part.equals("..") || part.length() > 255) {
                throw new IllegalArgumentException("Managed destination contains an unsafe path segment.");
            }
        }
        return path;
    }

    private static String normalizeHash(String value) {
        String hash = value == null ? "" : value.toLowerCase(Locale.ROOT);
        if (!hash.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("A SHA-256 digest is required.");
        return hash;
    }

    private static String chunkName(int index) { return String.format(Locale.ROOT, "chunk-%08d.bin", index); }

    private static void restrictDirectory(Path path) {
        try {
            Files.setPosixFilePermissions(path, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        } catch (Exception unsupported) { /* Android app-private storage or non-POSIX provider. */ }
    }

    private static void restrictFile(Path path) {
        try {
            Files.setPosixFilePermissions(path, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (Exception unsupported) { /* Android app-private storage or non-POSIX provider. */ }
    }

    private static void verifyRegular(Path path, String label) {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("Unsafe " + label + " in transfer storage.");
        }
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void deleteTree(Path directory) throws Exception {
        if (Files.isSymbolicLink(directory)) throw new SecurityException("Refusing to follow a transfer-directory symbolic link.");
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) return;
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                if (Files.isSymbolicLink(path)) throw new SecurityException("Symbolic link found in transfer session.");
                Files.deleteIfExists(path);
            }
        }
    }

    /** Reopens verified chunks sequentially so commit never needs a second full-size assembly copy. */
    private static final class ChunkSequenceInputStream extends InputStream {
        private final Path directory;
        private final int count;
        private int index;
        private InputStream current;
        private boolean closed;

        private ChunkSequenceInputStream(Path directory, int count) {
            this.directory = directory;
            this.count = count;
        }

        private boolean advance() throws IOException {
            while (!closed && (current == null || index < count)) {
                if (current != null) {
                    current.close();
                    current = null;
                }
                if (index >= count) return false;
                Path chunk = directory.resolve(chunkName(index++));
                if (Files.isSymbolicLink(chunk) || !Files.isRegularFile(chunk, LinkOption.NOFOLLOW_LINKS)) {
                    throw new SecurityException("Unsafe transfer chunk during commit.");
                }
                current = Files.newInputStream(chunk, LinkOption.NOFOLLOW_LINKS);
                return true;
            }
            return current != null;
        }

        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int read = read(one, 0, 1);
            return read < 0 ? -1 : one[0] & 0xff;
        }

        @Override public int read(byte[] bytes, int offset, int length) throws IOException {
            if (closed) throw new IOException("Transfer stream is closed.");
            if (length == 0) return 0;
            while (true) {
                if (current == null) {
                    if (index >= count) return -1;
                    advance();
                }
                int read = current.read(bytes, offset, length);
                if (read >= 0) return read;
                current.close();
                current = null;
            }
        }

        @Override public void close() throws IOException {
            closed = true;
            if (current != null) current.close();
        }
    }
}
