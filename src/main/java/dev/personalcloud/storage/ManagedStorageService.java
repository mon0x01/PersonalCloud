package dev.personalcloud.storage;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.SecretFiles;
import dev.personalcloud.core.StateStore;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Whole-file storage physically owned by this node; incoming files are atomically committed after digest verification. */
public final class ManagedStorageService {
    private static final String RECORD = "managedFile";
    private static final int MAX_FILES = 10_000;
    private final StateStore store;
    private final Path root;
    private final String ownerNodeId;
    private final long maxFileBytes;

    public ManagedStorageService(StateStore store, AppConfig config) throws Exception {
        this.store = store;
        this.ownerNodeId = config.nodeId();
        this.maxFileBytes = config.maxFileBytes();
        Files.createDirectories(config.storageRoot());
        if (Files.isSymbolicLink(config.storageRoot())) throw new SecurityException("Managed storage root cannot be a symbolic link.");
        this.root = config.storageRoot().toRealPath();
    }

    public synchronized Map<String, Object> receive(String uploaderNodeId, String relativePath, InputStream input,
                                                     long expectedSize, String expectedSha256) throws Exception {
        return receiveInternal(null, uploaderNodeId, relativePath, input, expectedSize, expectedSha256);
    }

    /** Idempotent commit boundary for a durable resumable-transfer session. */
    public synchronized Map<String,Object> receiveTransfer(String transferId, String uploaderNodeId, String relativePath,
                                                            InputStream input, long expectedSize, String expectedSha256) throws Exception {
        if (transferId == null || !transferId.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("A valid transfer ID is required.");
        return receiveInternal(transferId, uploaderNodeId, relativePath, input, expectedSize, expectedSha256);
    }

    private Map<String,Object> receiveInternal(String transferId, String uploaderNodeId, String relativePath,
                                               InputStream input, long expectedSize, String expectedSha256) throws Exception {
        if (uploaderNodeId == null || uploaderNodeId.isBlank() || uploaderNodeId.equals(ownerNodeId)) {
            throw new SecurityException("An authenticated remote member is required to place managed storage.");
        }
        if (expectedSize < 0 || expectedSize > maxFileBytes) throw new IllegalArgumentException("Managed file exceeds this node's per-file storage limit.");
        if (expectedSha256 == null || !expectedSha256.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("A valid SHA-256 digest is required.");
        String relative = normalizeRelative(relativePath);
        if (transferId != null) {
            for (Map<String,String> existing : store.records(RECORD)) {
                if (!transferId.equals(existing.get("transferId"))) continue;
                if (!uploaderNodeId.equals(existing.get("uploaderNodeId"))
                        || !relative.equals(existing.get("relativePath"))
                        || !Long.toString(expectedSize).equals(existing.get("size"))
                        || !expectedSha256.equals(existing.get("sha256"))) {
                    throw new SecurityException("Transfer ID was already committed with different metadata.");
                }
                return publicRecord(existing.get("_id"), existing);
            }
        }
        Path target = resolve(relative, false);
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("A managed file already exists at the requested destination; overwriting is disabled.");
        Path parent = target.getParent();
        if (parent == null || !parent.startsWith(root)) throw new SecurityException("Managed destination escapes the storage root.");
        createSafeDirectories(parent);
        target = resolve(relative, false);
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("A managed file already exists at the requested destination; overwriting is disabled.");
        if (store.records(RECORD).size() >= MAX_FILES) throw new IllegalStateException("This node reached its managed-file catalogue limit.");
        long usable = Files.getFileStore(root).getUsableSpace();
        if (expectedSize > usable) throw new IllegalStateException("This node does not have enough free storage for the requested file.");

        Path temporary = Files.createTempFile(parent, ".personalcloud-incoming-", ".part");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try {
            try (InputStream source = input; OutputStream output = Files.newOutputStream(temporary,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                byte[] buffer = new byte[256 * 1024];
                int read;
                while ((read = source.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > expectedSize || copied > maxFileBytes) throw new IllegalArgumentException("Incoming managed file exceeded its signed size limit.");
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
            }
            String actualHash = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedSize || !MessageDigest.isEqual(actualHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    expectedSha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new SecurityException("Incoming managed file failed size or SHA-256 verification.");
            }
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Destination appeared during transfer; no file was overwritten.");
            // Publish the fully verified file atomically without replacing a racing destination.
            Files.createLink(target, temporary);
            Files.delete(temporary);
            String id = UUID.randomUUID().toString();
            Map<String, String> row = new LinkedHashMap<>();
            row.put("ownerNodeId", ownerNodeId);
            row.put("uploaderNodeId", uploaderNodeId);
            row.put("relativePath", relative);
            row.put("size", Long.toString(copied));
            row.put("sha256", actualHash);
            row.put("createdAt", Instant.now().toString());
            if (transferId != null) row.put("transferId", transferId);
            row.put("status", "AVAILABLE");
            try { store.putRecord(RECORD, id, row); }
            catch (Exception persistenceFailure) {
                Files.deleteIfExists(target);
                throw persistenceFailure;
            }
            return publicRecord(id, row);
        } finally { Files.deleteIfExists(temporary); }
    }

    public synchronized List<Map<String, Object>> listForMember(String memberId) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        requireAuthenticatedMember(memberId);
        for (Map<String, String> row : store.records(RECORD)) {
            Map<String, Object> item = publicRecord(row.get("_id"), row);
            try {
                Path file = resolve(row.get("relativePath"), true);
                item.put("availability", "AVAILABLE");
                item.put("modified", Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS).toInstant().toString());
            } catch (Exception missing) { item.put("availability", "MISSING"); }
            result.add(item);
        }
        result.sort(Comparator.comparing(item -> String.valueOf(item.get("createdAt"))));
        return List.copyOf(result);
    }

    public synchronized Map<String, Object> statForMember(String memberId, String fileId) throws Exception {
        Map<String, String> row = requireOwnedRecord(memberId, fileId);
        Path file = resolve(row.get("relativePath"), true);
        Map<String, Object> result = publicRecord(fileId, row);
        result.put("modified", Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS).toInstant().toString());
        result.put("kind", "FILE");
        result.put("name", file.getFileName().toString());
        return result;
    }

    public synchronized InputStream openForMember(String memberId, String fileId) throws Exception {
        Map<String, String> row = requireOwnedRecord(memberId, fileId);
        Path file = resolve(row.get("relativePath"), true);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(file)) throw new IllegalStateException("Managed file is unavailable.");
        return Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS);
    }

    public synchronized void deleteForMember(String memberId, String fileId) throws Exception {
        Map<String, String> row = requireOwnedRecord(memberId, fileId);
        Path file = resolve(row.get("relativePath"), true);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new SecurityException("Managed file is no longer a regular file.");
        Files.delete(file);
        store.removeRecord(RECORD, fileId);
    }

    public synchronized Map<String, Object> statLocal(String fileId) throws Exception {
        Map<String, String> row = store.getRecord(RECORD, fileId);
        if (row == null) throw new IllegalArgumentException("Managed file not found.");
        Path file = resolve(row.get("relativePath"), true);
        Map<String, Object> result = publicRecord(fileId, row);
        result.put("kind", "FILE");
        result.put("name", file.getFileName().toString());
        result.put("modified", Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS).toInstant().toString());
        result.put("availability", "AVAILABLE");
        return result;
    }

    public synchronized byte[] readLocalRange(String fileId, long offset, int length) throws Exception {
        if (offset < 0 || length < 0 || length > 8 * 1024 * 1024) throw new IllegalArgumentException("Managed file range is outside the permitted bounds.");
        Path file = resolve(requireLocalRecord(fileId).get("relativePath"), true);
        long size = Files.size(file);
        if (offset >= size || length == 0) return new byte[0];
        int actual = (int) Math.min((long) length, size - offset);
        try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            input.skipNBytes(offset);
            return input.readNBytes(actual);
        }
    }

    private Map<String, String> requireLocalRecord(String fileId) {
        Map<String, String> row = store.getRecord(RECORD, fileId);
        if (row == null) throw new IllegalArgumentException("Managed file not found.");
        return row;
    }

    public synchronized List<Map<String, Object>> listLocal() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : store.records(RECORD)) result.add(publicRecord(row.get("_id"), row));
        return List.copyOf(result);
    }

    private Map<String, String> requireOwnedRecord(String memberId, String fileId) {
        requireAuthenticatedMember(memberId);
        Map<String, String> row = store.getRecord(RECORD, fileId);
        if (row == null) throw new IllegalArgumentException("Managed file not found on this device.");
        return row;
    }

    private static void requireAuthenticatedMember(String memberId) {
        // The HTTP boundary authenticates active network membership before reaching this service.
        if (memberId == null || memberId.isBlank()) throw new SecurityException("An authenticated PersonalCloud network member is required.");
    }

    private Path resolve(String relative, boolean mustExist) throws Exception {
        String safe = normalizeRelative(relative);
        Path current = root;
        for (String segment : safe.split("/")) {
            current = current.resolve(segment).normalize();
            if (!current.startsWith(root) || Files.isSymbolicLink(current)) throw new SecurityException("Managed path contains a symbolic link or escapes the storage root.");
        }
        if (mustExist && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Managed file is unavailable.");
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS) && !current.toRealPath().startsWith(root)) throw new SecurityException("Managed path escapes the storage root.");
        return current;
    }

    private void createSafeDirectories(Path directory) throws Exception {
        Path current = root;
        for (Path segment : root.relativize(directory)) {
            current = current.resolve(segment);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(current) || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                    throw new SecurityException("Managed destination contains an unsafe directory component.");
                }
            } else Files.createDirectory(current);
            if (!current.toRealPath().startsWith(root)) throw new SecurityException("Managed destination escapes the storage root.");
        }
    }

    private static String normalizeRelative(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("A managed destination path is required.");
        String path = value.replace('\\', '/');
        if (path.startsWith("/") || path.matches("^[A-Za-z]:.*") || path.indexOf('\0') >= 0 || path.length() > 1024) {
            throw new IllegalArgumentException("Managed destination must be a relative path of at most 1024 characters.");
        }
        for (String segment : path.split("/", -1)) {
            if (segment.isBlank() || segment.equals(".") || segment.equals("..") || segment.length() > 255) {
                throw new IllegalArgumentException("Managed destination contains an unsafe path segment.");
            }
        }
        return path;
    }

    private static Map<String, Object> publicRecord(String id, Map<String, String> row) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("fileId", id);
        result.put("ownerNodeId", row.getOrDefault("ownerNodeId", ""));
        result.put("uploaderNodeId", row.getOrDefault("uploaderNodeId", ""));
        result.put("path", row.getOrDefault("relativePath", ""));
        result.put("size", Long.parseLong(row.getOrDefault("size", "0")));
        result.put("sha256", row.getOrDefault("sha256", ""));
        result.put("createdAt", row.getOrDefault("createdAt", ""));
        return result;
    }
}
