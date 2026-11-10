package dev.personalcloud.storage;

import dev.personalcloud.core.SecretFiles;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/** Owner-local safety snapshots for files deleted through an explicit DOWNLOAD+DELETE grant. */
public final class ReferenceVersionService {
    private static final int MAX_VERSIONS_PER_PATH = 20;
    private static final int MAX_TOTAL_VERSIONS = 500;
    private static final long MAX_TOTAL_BYTES = 10L * 1024 * 1024 * 1024;
    private final Path root;
    private final ReferenceStorageService references;

    public ReferenceVersionService(Path dataDirectory, ReferenceStorageService references) throws Exception {
        root = dataDirectory.resolve("reference-versions").toAbsolutePath().normalize();
        this.references = references;
        Files.createDirectories(root);
        SecretFiles.restrictDirectory(root);
        try (var paths = Files.list(root)) {
            for (Path file : paths.filter(path -> path.getFileName().toString().endsWith(".tmp")).toList()) Files.deleteIfExists(file);
        }
    }

    public synchronized Map<String, Object> snapshotAndDelete(String referenceId, String relativePath, long maxBytes) throws Exception {
        Map<String, Object> before = references.inspect(referenceId, relativePath);
        if (!"FILE".equals(before.get("kind"))) throw new IllegalArgumentException("Only individual referenced files can be deleted remotely.");
        long expectedSize = ((Number) before.get("size")).longValue();
        if (expectedSize > maxBytes) throw new IllegalArgumentException("File exceeds the configured safety-snapshot limit; deletion was cancelled.");
        String id = UUID.randomUUID().toString();
        Path blobTemp = root.resolve(id + ".blob.tmp");
        Path metaTemp = root.resolve(id + ".properties.tmp");
        Path blob = root.resolve(id + ".blob");
        Path meta = root.resolve(id + ".properties");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try (InputStream input = references.openFile(referenceId, relativePath);
             OutputStream output = Files.newOutputStream(blobTemp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                copied = Math.addExact(copied, read);
                if (copied > maxBytes) throw new IllegalArgumentException("Snapshot exceeded the configured safety limit; deletion was cancelled.");
                digest.update(buffer, 0, read);
                output.write(buffer, 0, read);
            }
            output.flush();
        } catch (Exception failure) {
            Files.deleteIfExists(blobTemp);
            throw failure;
        }
        String sha256 = HexFormat.of().formatHex(digest.digest());
        if (copied != expectedSize) {
            Files.deleteIfExists(blobTemp);
            throw new IllegalStateException("Referenced file changed while its deletion snapshot was created; deletion was cancelled.");
        }
        Map<String, Object> after = references.inspect(referenceId, relativePath);
        if (!sameVersion(before, after)) {
            Files.deleteIfExists(blobTemp);
            throw new IllegalStateException("Referenced file changed during snapshot creation; deletion was cancelled.");
        }
        Properties properties = new Properties();
        properties.setProperty("id", id);
        properties.setProperty("referenceId", referenceId);
        properties.setProperty("path", relativePath);
        properties.setProperty("name", String.valueOf(before.get("name")));
        properties.setProperty("createdAt", java.time.Instant.now().toString());
        properties.setProperty("size", Long.toString(copied));
        properties.setProperty("modified", String.valueOf(before.get("modified")));
        properties.setProperty("sha256", sha256);
        try (OutputStream output = Files.newOutputStream(metaTemp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            properties.store(output, "PersonalCloud referenced-file deletion recovery snapshot");
            output.flush();
        }
        force(blobTemp);
        force(metaTemp);
        SecretFiles.restrict(blobTemp);
        SecretFiles.restrict(metaTemp);
        try {
            Files.move(blobTemp, blob, StandardCopyOption.ATOMIC_MOVE);
            Files.move(metaTemp, meta, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception failure) {
            Files.deleteIfExists(blobTemp);
            Files.deleteIfExists(metaTemp);
            Files.deleteIfExists(blob);
            Files.deleteIfExists(meta);
            throw failure;
        }
        SecretFiles.restrict(blob);
        SecretFiles.restrict(meta);
        try {
            references.deleteFileIfUnchanged(referenceId, relativePath, expectedSize,
                    String.valueOf(before.get("modified")), sha256);
        } catch (Exception failure) {
            // Keep the snapshot even when deletion is cancelled; it is a verified recovery point.
            throw failure;
        }
        prune(referenceId, relativePath);
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("snapshotId", id);
        result.put("referenceId", referenceId);
        result.put("path", relativePath);
        result.put("size", copied);
        result.put("sha256", sha256);
        result.put("deleted", true);
        return result;
    }

    public synchronized List<Map<String, Object>> list() throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        try (var paths = Files.list(root)) {
            for (Path metadata : paths.filter(path -> path.getFileName().toString().endsWith(".properties")).toList()) {
                Properties p = load(metadata);
                Map<String, Object> item = new java.util.LinkedHashMap<>();
                item.put("snapshotId", p.getProperty("id", ""));
                item.put("referenceId", p.getProperty("referenceId", ""));
                item.put("path", p.getProperty("path", ""));
                item.put("size", Long.parseLong(p.getProperty("size", "0")));
                item.put("sha256", p.getProperty("sha256", ""));
                item.put("createdAt", p.getProperty("createdAt", ""));
                result.add(item);
            }
        }
        result.sort(Comparator.comparing(item -> String.valueOf(item.get("createdAt"))));
        return List.copyOf(result);
    }

    public synchronized Map<String, Object> restore(String snapshotId) throws Exception {
        if (snapshotId == null || !snapshotId.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Invalid reference snapshot ID.");
        Path metadata = root.resolve(snapshotId + ".properties");
        Path blob = root.resolve(snapshotId + ".blob");
        if (!Files.isRegularFile(metadata) || !Files.isRegularFile(blob)) throw new IllegalArgumentException("Reference recovery snapshot was not found or is incomplete.");
        Properties p = load(metadata);
        if (!snapshotId.equals(p.getProperty("id"))) throw new SecurityException("Recovery snapshot metadata identity does not match its filename.");
        String referenceId = p.getProperty("referenceId", "");
        String relativePath = p.getProperty("path", "");
        long size = Long.parseLong(p.getProperty("size", "-1"));
        String hash = p.getProperty("sha256", "");
        if (size < 0 || !hash.matches("[a-f0-9]{64}") || Files.size(blob) != size) throw new SecurityException("Recovery snapshot metadata failed validation.");
        try (InputStream input = Files.newInputStream(blob)) {
            references.restoreFileFromSnapshot(referenceId, relativePath, input, size, hash);
        }
        return Map.of("snapshotId", snapshotId, "referenceId", referenceId, "path", relativePath,
                "size", size, "sha256", hash, "restored", true);
    }

    private void prune(String referenceId, String path) throws Exception {
        List<Snapshot> snapshots = new ArrayList<>();
        try (var paths = Files.list(root)) {
            for (Path metadata : paths.filter(file -> file.getFileName().toString().endsWith(".properties")).toList()) {
                Properties p = load(metadata);
                snapshots.add(new Snapshot(metadata, root.resolve(p.getProperty("id") + ".blob"),
                        p.getProperty("referenceId", ""), p.getProperty("path", ""),
                        Long.parseLong(p.getProperty("size", "0")), p.getProperty("createdAt", "")));
            }
        }
        snapshots.sort(Comparator.comparing(Snapshot::createdAt));
        // Retention must evict the oldest snapshots, never the newest ones. A
        // previous implementation walked newest-first and could delete the
        // recovery point that was just created while retaining older blobs.
        java.util.Map<String, Integer> perPath = new java.util.LinkedHashMap<>();
        for (Snapshot snapshot : snapshots) {
            perPath.merge(snapshot.referenceId() + "\u0000" + snapshot.path(), 1, Integer::sum);
        }
        java.util.Set<Snapshot> removed = new java.util.HashSet<>();
        for (Snapshot snapshot : snapshots) { // oldest first within each path
            String key = snapshot.referenceId() + "\u0000" + snapshot.path();
            int count = perPath.getOrDefault(key, 0);
            if (count > MAX_VERSIONS_PER_PATH) {
                Files.deleteIfExists(snapshot.blob());
                Files.deleteIfExists(snapshot.metadata());
                removed.add(snapshot);
                perPath.put(key, count - 1);
            }
        }
        List<Snapshot> remaining = snapshots.stream()
                .filter(snapshot -> !removed.contains(snapshot))
                .sorted(Comparator.comparing(Snapshot::createdAt))
                .toList();
        long total = 0;
        for (Snapshot snapshot : remaining) total += snapshot.size();
        int totalCount = remaining.size();
        for (Snapshot snapshot : remaining) { // oldest first
            if (totalCount <= MAX_TOTAL_VERSIONS && total <= MAX_TOTAL_BYTES) break;
            Files.deleteIfExists(snapshot.blob());
            Files.deleteIfExists(snapshot.metadata());
            totalCount--;
            total -= snapshot.size();
        }
    }

    private static boolean sameVersion(Map<String, Object> a, Map<String, Object> b) {
        return a.get("size").equals(b.get("size")) && a.get("modified").equals(b.get("modified"));
    }
    private static Properties load(Path path) throws Exception {
        Properties properties = new Properties();
        try (var input = Files.newInputStream(path)) { properties.load(input); }
        return properties;
    }
    private static void force(Path path) throws Exception {
        try (var channel = java.nio.channels.FileChannel.open(path, StandardOpenOption.WRITE)) { channel.force(true); }
    }
    private record Snapshot(Path metadata, Path blob, String referenceId, String path, long size, String createdAt) { }
}
