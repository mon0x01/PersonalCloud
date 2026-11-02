package dev.personalcloud.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/** Local, owner-controlled snapshots. Version blobs never leave the owning node. */
public final class VersionService {
    private static final int MAX_VERSIONS_PER_PATH = 20;
    private static final int MAX_TOTAL_VERSIONS = 500;
    private static final long MAX_TOTAL_BYTES = 10L * 1024 * 1024 * 1024;
    private final Path root;
    private final FileService files;

    public VersionService(Path dataDirectory, FileService files) throws Exception {
        this.root = dataDirectory.resolve("versions").toAbsolutePath().normalize();
        this.files = files;
        Files.createDirectories(root);
        SecretFiles.restrict(root);
        // Remove incomplete temporary artifacts left by a process or power failure.
        try (var paths = Files.list(root)) {
            for (Path path : paths.filter(p -> p.getFileName().toString().endsWith(".tmp")).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    public synchronized Map<String, Object> snapshot(String relativePath, String reason, long maxBytes) throws Exception {
        String path = files.validateAndGetRelativeFile(relativePath);
        Map<String, Object> before = files.metadata(path);
        long expectedSize = ((Number) before.get("size")).longValue();
        if (expectedSize > maxBytes) {
            throw new IllegalArgumentException("File is larger than the configured version-snapshot limit; deletion was not performed.");
        }
        String id = UUID.randomUUID().toString();
        Path blobTemp = root.resolve(id + ".blob.tmp");
        Path blob = root.resolve(id + ".blob");
        Path metaTemp = root.resolve(id + ".properties.tmp");
        Path meta = root.resolve(id + ".properties");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try (InputStream input = files.open(path);
             OutputStream output = Files.newOutputStream(blobTemp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                copied += read;
                if (copied > maxBytes) throw new IllegalArgumentException("Snapshot exceeds the configured version limit.");
                digest.update(buffer, 0, read);
                output.write(buffer, 0, read);
            }
            output.flush();
        } catch (Exception error) {
            Files.deleteIfExists(blobTemp);
            throw error;
        }
        if (copied != expectedSize) {
            Files.deleteIfExists(blobTemp);
            throw new IllegalStateException("File changed while its version snapshot was being created; deletion was cancelled.");
        }
        String sha256 = HexFormat.of().formatHex(digest.digest());
        String createdAt = Instant.now().toString();
        Properties properties = new Properties();
        properties.setProperty("id", id);
        properties.setProperty("path", path);
        properties.setProperty("reason", reason == null ? "MANUAL" : reason);
        properties.setProperty("createdAt", createdAt);
        properties.setProperty("size", Long.toString(copied));
        properties.setProperty("sha256", sha256);
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(blobTemp, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        try (OutputStream output = Files.newOutputStream(metaTemp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            properties.store(output, "PersonalCloud local file version");
            output.flush();
        }
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(metaTemp, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        SecretFiles.restrict(blobTemp);
        SecretFiles.restrict(metaTemp);
        try {
            Files.move(blobTemp, blob, StandardCopyOption.ATOMIC_MOVE);
            Files.move(metaTemp, meta, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception error) {
            Files.deleteIfExists(blobTemp);
            Files.deleteIfExists(blob);
            Files.deleteIfExists(metaTemp);
            Files.deleteIfExists(meta);
            throw error;
        }
        SecretFiles.restrict(blob);
        SecretFiles.restrict(meta);
        prune(path);
        return publicVersion(properties);
    }

    public synchronized List<Map<String, Object>> list(String relativePath) throws Exception {
        String filter = relativePath == null || relativePath.isBlank() ? null : relativePath.replace('\\', '/');
        List<Properties> properties = loadAll();
        return properties.stream()
                .filter(p -> filter == null || filter.equals(p.getProperty("path")))
                .sorted(Comparator.comparing((Properties p) -> p.getProperty("createdAt", "")).reversed())
                .limit(250)
                .map(VersionService::publicVersion)
                .toList();
    }

    public synchronized Map<String, Object> restore(String id, String destination, long maxBytes) throws Exception {
        Properties metadata = load(id);
        Path blob = blobPath(id);
        if (!Files.isRegularFile(blob)) throw new IllegalStateException("Version content is missing.");
        long size = Long.parseLong(metadata.getProperty("size", "-1"));
        if (size < 0 || size > maxBytes || Files.size(blob) != size) throw new IllegalStateException("Version content size is invalid or exceeds the restore limit.");
        String expectedHash = metadata.getProperty("sha256", "");
        String actualHash = sha256(blob);
        if (!MessageDigest.isEqual(expectedHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII), actualHash.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("Version integrity check failed; restore was cancelled.");
        }
        String target = destination == null || destination.isBlank() ? metadata.getProperty("path") : destination;
        try (InputStream input = Files.newInputStream(blob)) {
            long written = files.upload(target, input, maxBytes, true);
            return Map.of("ok", true, "path", target, "bytes", written, "sha256", actualHash);
        }
    }

    private void prune(String path) throws Exception {
        List<Properties> samePath = loadAll().stream()
                .filter(p -> path.equals(p.getProperty("path")))
                .sorted(Comparator.comparing(p -> p.getProperty("createdAt", "")))
                .toList();
        int excess = samePath.size() - MAX_VERSIONS_PER_PATH;
        for (int i = 0; i < excess; i++) {
            String id = samePath.get(i).getProperty("id");
            Files.deleteIfExists(blobPath(id));
            Files.deleteIfExists(metaPath(id));
        }
        List<Properties> all = loadAll().stream()
                .sorted(Comparator.comparing(p -> p.getProperty("createdAt", "")))
                .toList();
        int globalExcess = all.size() - MAX_TOTAL_VERSIONS;
        for (int i = 0; i < globalExcess; i++) {
            String id = all.get(i).getProperty("id");
            Files.deleteIfExists(blobPath(id));
            Files.deleteIfExists(metaPath(id));
        }
        // A count-only limit is not a disk-space limit. Keep local recovery bounded
        // even when snapshots are individually large.
        List<Properties> remaining = loadAll().stream()
                .sorted(Comparator.comparing(p -> p.getProperty("createdAt", "")))
                .toList();
        long totalBytes = 0;
        for (Properties p : remaining) {
            try { totalBytes = Math.addExact(totalBytes, Long.parseLong(p.getProperty("size", "0"))); }
            catch (NumberFormatException | ArithmeticException invalidSize) { totalBytes = Long.MAX_VALUE; }
        }
        for (Properties p : remaining) {
            if (totalBytes <= MAX_TOTAL_BYTES) break;
            String id = p.getProperty("id");
            long size;
            try { size = Math.max(0, Long.parseLong(p.getProperty("size", "0"))); }
            catch (NumberFormatException invalidSize) { size = 0; }
            Files.deleteIfExists(blobPath(id));
            Files.deleteIfExists(metaPath(id));
            totalBytes = Math.max(0, totalBytes - size);
        }
    }

    private List<Properties> loadAll() throws Exception {
        List<Properties> result = new ArrayList<>();
        try (var paths = Files.list(root)) {
            for (Path path : paths.filter(p -> p.getFileName().toString().endsWith(".properties")).toList()) {
                Properties p = new Properties();
                try (InputStream input = Files.newInputStream(path)) { p.load(input); }
                if (p.getProperty("id") != null && p.getProperty("path") != null) result.add(p);
            }
        }
        return result;
    }

    private Properties load(String id) throws Exception {
        if (id == null || !id.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Invalid version identifier.");
        Path file = metaPath(id);
        if (!Files.isRegularFile(file)) throw new IllegalArgumentException("Version not found.");
        Properties p = new Properties();
        try (InputStream input = Files.newInputStream(file)) { p.load(input); }
        if (!id.equals(p.getProperty("id"))) throw new IllegalArgumentException("Version metadata is invalid.");
        return p;
    }

    private Path blobPath(String id) { return root.resolve(id + ".blob").normalize(); }
    private Path metaPath(String id) { return root.resolve(id + ".properties").normalize(); }

    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static Map<String, Object> publicVersion(Properties p) {
        return Map.of("id", p.getProperty("id"), "path", p.getProperty("path"),
                "reason", p.getProperty("reason", "MANUAL"), "createdAt", p.getProperty("createdAt"),
                "size", Long.parseLong(p.getProperty("size", "0")), "sha256", p.getProperty("sha256"));
    }
}
