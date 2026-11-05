package dev.personalcloud.storage;

import dev.personalcloud.core.StateStore;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Registers user-selected directories by reference. Registration never copies, moves, encrypts,
 * deletes, or otherwise mutates the referenced files. The service exposes bounded metadata and
 * read streams for future OS adapters (Linux FUSE and Android DocumentsProvider).
 */
public final class ReferenceStorageService {
    private static final String PREFIX = "referenceRoot";
    private static final int MAX_ROOTS = 64;
    private static final int MAX_SEARCH_RESULTS = 200;
    private static final int MAX_SEARCH_VISITS = 100_000;

    private final StateStore store;
    private final Path dataDirectory;
    private final Path managedStorageRoot;

    public ReferenceStorageService(StateStore store, Path dataDirectory, Path managedStorageRoot) throws Exception {
        this.store = store;
        this.dataDirectory = canonicalExistingDirectory(dataDirectory, "Application data directory");
        this.managedStorageRoot = canonicalExistingDirectory(managedStorageRoot, "Managed storage root");
        ensureDisjoint(this.dataDirectory, this.managedStorageRoot,
                "Application data and managed storage must not overlap.");
    }

    /** Register a directory in place. Only its canonical path and display metadata are persisted. */
    public synchronized ReferenceRoot register(String displayName, Path suppliedPath) throws Exception {
        String name = validateDisplayName(displayName);
        Path root = canonicalUserDirectory(suppliedPath);
        ensureSafeRoot(root);

        List<Map<String, String>> existing = store.records(PREFIX);
        if (existing.size() >= MAX_ROOTS) throw new IllegalStateException("A maximum of " + MAX_ROOTS + " referenced roots is supported.");
        for (Map<String, String> row : existing) {
            Path current = Path.of(row.get("path")).toAbsolutePath().normalize();
            if (pathsOverlap(root, current)) {
                throw new IllegalArgumentException("This directory overlaps an existing PersonalCloud storage root. Register a non-overlapping directory instead.");
            }
            if (name.equalsIgnoreCase(row.getOrDefault("name", ""))) {
                throw new IllegalArgumentException("A referenced directory with that display name already exists.");
            }
        }

        String id = UUID.randomUUID().toString();
        String createdAt = Instant.now().toString();
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("schemaVersion", "1");
        fields.put("name", name);
        fields.put("path", root.toString());
        fields.put("createdAt", createdAt);
        store.putRecord(PREFIX, id, fields);
        return new ReferenceRoot(id, name, ReferenceRoot.Availability.AVAILABLE, createdAt);
    }

    /**
     * Resolves a selected regular file to an already registered directory reference. This is
     * metadata-only: it never copies or opens the file, and it refuses symlink aliases so a
     * file-manager action cannot accidentally grant access outside the selected root.
     */
    public synchronized Map<String, Object> locateFile(Path suppliedFile) throws Exception {
        if (suppliedFile == null) throw new IllegalArgumentException("A file path is required.");
        Path absolute = suppliedFile.toAbsolutePath().normalize();
        if (!Files.exists(absolute, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(absolute)
                || !Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The selected path must be an existing regular file, not a symbolic link.");
        }
        Path real = absolute.toRealPath();
        if (!absolute.equals(real)) {
            throw new SecurityException("Symbolic-link path components are not accepted for reference sharing.");
        }
        BasicFileAttributes attrs = Files.readAttributes(real, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!Files.isReadable(real) || !attrs.isRegularFile()) throw new IllegalArgumentException("The selected file is not readable.");

        for (Map<String, String> row : store.records(PREFIX)) {
            String id = row.get("_id");
            Path rootPath;
            try { rootPath = Path.of(row.get("path")).toAbsolutePath().normalize(); }
            catch (Exception invalid) { continue; }
            if (!Files.isDirectory(rootPath, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(rootPath)) continue;
            Path canonicalRoot = rootPath.toRealPath();
            if (!rootPath.equals(canonicalRoot) || !real.startsWith(canonicalRoot) || real.equals(canonicalRoot)) continue;
            Path relative = canonicalRoot.relativize(real);
            if (relative.getNameCount() < 1 || relative.isAbsolute()) continue;
            return Map.of(
                    "referenceId", id,
                    "referenceName", row.getOrDefault("name", "Referenced directory"),
                    "relativePath", relative.toString().replace(real.getFileSystem().getSeparator(), "/"),
                    "fileName", real.getFileName().toString(),
                    "size", attrs.size(),
                    "modified", attrs.lastModifiedTime().toInstant().toString());
        }
        throw new IllegalArgumentException("The selected file is not inside a registered PersonalCloud reference directory. Register its containing directory first.");
    }

    /** Removing a reference never deletes or changes the original directory or its contents. */
    public synchronized void unregister(String id) throws Exception {
        requireId(id);
        if (store.getRecord(PREFIX, id) == null) throw new IllegalArgumentException("Referenced directory not found.");
        store.removeRecord(PREFIX, id);
    }

    public synchronized List<ReferenceRoot> listRoots() {
        List<ReferenceRoot> result = new ArrayList<>();
        for (Map<String, String> row : store.records(PREFIX)) {
            Path path;
            try {
                path = Path.of(row.get("path")).toAbsolutePath().normalize();
            } catch (Exception invalid) {
                result.add(new ReferenceRoot(row.get("_id"), row.getOrDefault("name", "Unnamed directory"),
                        ReferenceRoot.Availability.MISSING, row.getOrDefault("createdAt", "")));
                continue;
            }
            ReferenceRoot.Availability availability;
            if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
                availability = ReferenceRoot.Availability.MISSING;
            } else if (!Files.isReadable(path) || !Files.isExecutable(path)) {
                availability = ReferenceRoot.Availability.NOT_READABLE;
            } else {
                availability = ReferenceRoot.Availability.AVAILABLE;
            }
            result.add(new ReferenceRoot(row.get("_id"), row.getOrDefault("name", "Unnamed directory"),
                    availability, row.getOrDefault("createdAt", "")));
        }
        result.sort(Comparator.comparing(ReferenceRoot::name, String.CASE_INSENSITIVE_ORDER));
        return List.copyOf(result);
    }

    /** Lists immediate children only; symbolic links and special files are intentionally omitted. */
    public List<StorageEntry> listEntries(String rootId, String relativeDirectory) throws Exception {
        Root root = requireRoot(rootId);
        Path directory = resolve(root, relativeDirectory, true);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The requested path is not a directory.");
        }
        List<StorageEntry> entries = new ArrayList<>();
        try (DirectoryStream<Path> children = Files.newDirectoryStream(directory)) {
            for (Path child : children) {
                if (Files.isSymbolicLink(child)) continue;
                BasicFileAttributes attributes;
                try {
                    attributes = Files.readAttributes(child, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                } catch (Exception ignored) {
                    // A file can disappear or become inaccessible during enumeration.
                    continue;
                }
                StorageEntry.Kind kind;
                long size;
                if (attributes.isDirectory()) {
                    kind = StorageEntry.Kind.DIRECTORY;
                    size = 0;
                } else if (attributes.isRegularFile()) {
                    kind = StorageEntry.Kind.FILE;
                    size = attributes.size();
                } else {
                    continue;
                }
                entries.add(new StorageEntry(root.id(), root.name(), portableRelative(root.path(), child),
                        child.getFileName().toString(), kind, size, attributes.lastModifiedTime().toInstant().toString()));
            }
        }
        entries.sort(Comparator.comparing((StorageEntry entry) -> entry.kind() == StorageEntry.Kind.FILE)
                .thenComparing(StorageEntry::name, String.CASE_INSENSITIVE_ORDER));
        return List.copyOf(entries);
    }

    /** Searches names and relative paths only. It never indexes file contents. */
    public List<StorageEntry> search(String query, int limit) throws Exception {
        String term = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        if (term.length() < 2) throw new IllegalArgumentException("Search requires at least two characters.");
        if (term.length() > 128) throw new IllegalArgumentException("Search query is too long.");
        if (limit < 1 || limit > MAX_SEARCH_RESULTS) throw new IllegalArgumentException("Search limit must be between 1 and " + MAX_SEARCH_RESULTS + ".");

        List<StorageEntry> result = new ArrayList<>();
        int visited = 0;
        for (Map<String, String> row : store.records(PREFIX)) {
            if (result.size() >= limit || visited >= MAX_SEARCH_VISITS) break;
            Root root;
            try { root = requireRoot(row.get("_id")); }
            catch (IllegalArgumentException | java.io.IOException unavailable) { continue; }
            try (var paths = Files.walk(root.path())) {
                var iterator = paths.iterator();
                while (iterator.hasNext() && result.size() < limit && visited < MAX_SEARCH_VISITS) {
                    Path path = iterator.next();
                    if (path.equals(root.path()) || Files.isSymbolicLink(path)) continue;
                    visited++;
                    BasicFileAttributes attributes;
                    try { attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); }
                    catch (Exception ignored) { continue; }
                    StorageEntry.Kind kind;
                    long size;
                    if (attributes.isRegularFile()) { kind = StorageEntry.Kind.FILE; size = attributes.size(); }
                    else if (attributes.isDirectory()) { kind = StorageEntry.Kind.DIRECTORY; size = 0; }
                    else continue;
                    String relative = portableRelative(root.path(), path);
                    if (!path.getFileName().toString().toLowerCase(Locale.ROOT).contains(term)
                            && !relative.toLowerCase(Locale.ROOT).contains(term)) continue;
                    result.add(new StorageEntry(root.id(), root.name(), relative, path.getFileName().toString(),
                            kind, size, attributes.lastModifiedTime().toInstant().toString()));
                }
            }
        }
        result.sort(Comparator.comparing(StorageEntry::name, String.CASE_INSENSITIVE_ORDER));
        return List.copyOf(result);
    }

    /** Returns bounded metadata for a referenced file or directory, including the root itself. */
    public Map<String, Object> inspect(String rootId, String relativePath) throws Exception {
        Root root = requireRoot(rootId);
        Path target = resolve(root, relativePath, true);
        BasicFileAttributes attrs = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isRegularFile() && !attrs.isDirectory()) throw new IllegalArgumentException("Referenced path is not a regular file or directory.");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("storageId", root.id());
        result.put("storageName", root.name());
        result.put("path", portableRelative(root.path(), target));
        result.put("name", target.equals(root.path()) ? root.name() : target.getFileName().toString());
        result.put("kind", attrs.isDirectory() ? "DIRECTORY" : "FILE");
        result.put("size", attrs.isRegularFile() ? attrs.size() : 0L);
        result.put("modified", attrs.lastModifiedTime().toInstant().toString());
        return result;
    }

    public Map<String, Object> metadata(String rootId, String relativePath) throws Exception {
        Root root = requireRoot(rootId);
        Path file = resolve(root, relativePath, true);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Referenced file not found.");
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("storageId", root.id());
        result.put("storageName", root.name());
        result.put("path", portableRelative(root.path(), file));
        result.put("name", file.getFileName().toString());
        result.put("size", attrs.size());
        result.put("modified", attrs.lastModifiedTime().toInstant().toString());
        return result;
    }

    /** Opens a read-only stream to the original file. No temporary or permanent copy is created. */
    public InputStream openFile(String rootId, String relativePath) throws Exception {
        Root root = requireRoot(rootId);
        Path file = resolve(root, relativePath, true);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(file)) {
            throw new IllegalArgumentException("Referenced file is not a readable regular file.");
        }
        return Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS);
    }

    /** Restores a previously deleted file only when the destination is absent and the snapshot digest matches. */
    public synchronized void restoreFileFromSnapshot(String rootId, String relativePath, InputStream snapshot,
                                                      long expectedSize, String expectedSha256) throws Exception {
        if (snapshot == null || expectedSize < 0 || expectedSha256 == null || !expectedSha256.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Invalid recovery snapshot metadata.");
        }
        Root root = requireRoot(rootId);
        Path target = resolve(root, relativePath, false);
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("The original path already exists; restore will not overwrite it.");
        Path parent = target.getParent();
        if (parent == null || !parent.startsWith(root.path())) throw new SecurityException("Recovery path escapes the referenced directory.");
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(parent)) {
            throw new IllegalStateException("The original parent directory is unavailable; restore will not create or follow an unsafe directory.");
        }
        Path verifiedParent = parent.toRealPath();
        if (!verifiedParent.startsWith(root.realPath())) throw new SecurityException("Recovery path escapes the referenced directory.");
        Path temporary = Files.createTempFile(parent, ".personalcloud-restore-", ".tmp");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try {
            try (InputStream input = snapshot; OutputStream output = Files.newOutputStream(temporary,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > expectedSize) throw new IllegalStateException("Recovery snapshot exceeds its recorded size.");
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedSize || !MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    expectedSha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new SecurityException("Recovery snapshot failed its size or SHA-256 integrity check.");
            }
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("The original path appeared during restore; no file was overwritten.");
            // Publish the fully verified file atomically without replacing a racing destination.
            Files.createLink(target, temporary);
            Files.delete(temporary);
        } finally { Files.deleteIfExists(temporary); }
    }

    /** Deletes an original referenced file only when its metadata and digest still match a verified snapshot. */
    public synchronized void deleteFileIfUnchanged(String rootId, String relativePath, long expectedSize,
                                                    String expectedModified, String expectedSha256) throws Exception {
        Root root = requireRoot(rootId);
        Path file = resolve(root, relativePath, true);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)) {
            throw new SecurityException("Refusing to delete a path that is no longer a regular file.");
        }
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attrs.size() != expectedSize || !attrs.lastModifiedTime().toInstant().toString().equals(expectedModified)) {
            throw new IllegalStateException("Referenced file changed after its recovery snapshot; deletion was cancelled.");
        }
        String actualDigest = sha256(rootId, relativePath);
        if (!MessageDigest.isEqual(actualDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                expectedSha256.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("Referenced file contents changed after its recovery snapshot; deletion was cancelled.");
        }
        Files.delete(file);
    }

    public String sha256(String rootId, String relativePath) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = openFile(rootId, relativePath)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private Root requireRoot(String id) throws Exception {
        requireId(id);
        Map<String, String> row = store.getRecord(PREFIX, id);
        if (row == null) throw new IllegalArgumentException("Referenced directory not found.");
        String stored = row.get("path");
        if (stored == null || stored.isBlank()) throw new IllegalStateException("Referenced directory metadata is invalid.");
        Path path = Path.of(stored).toAbsolutePath().normalize();
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new StorageUnavailableException("Referenced directory is offline or unavailable.");
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("Referenced directory is no longer a safe directory. Remove and register it again.");
        }
        Path real = path.toRealPath();
        if (!real.equals(path)) throw new SecurityException("Referenced directory identity changed. Remove and register it again.");
        if (!Files.isReadable(path) || !Files.isExecutable(path)) throw new StorageUnavailableException("Referenced directory is not readable.");
        return new Root(id, row.getOrDefault("name", "Referenced directory"), path, real);
    }

    private Path resolve(Root root, String relativePath, boolean mustExist) throws Exception {
        String relative = relativePath == null ? "" : relativePath;
        if (relative.indexOf('\0') >= 0 || relative.startsWith("/") || relative.startsWith("\\")
                || relative.matches("^[A-Za-z]:.*")) {
            throw new IllegalArgumentException("Only storage-relative paths are accepted.");
        }
        Path current = root.path();
        if (!relative.isBlank()) {
            String portable = relative.replace('\\', '/');
            for (String segment : portable.split("/", -1)) {
                if (segment.isBlank() || segment.equals(".") || segment.equals("..")) {
                    throw new IllegalArgumentException("Path contains an invalid segment.");
                }
                current = current.resolve(segment).normalize();
                if (!current.startsWith(root.path())) throw new SecurityException("Path escapes the referenced directory.");
                if (Files.isSymbolicLink(current)) throw new SecurityException("Symbolic links are not accessible through PersonalCloud.");
            }
        }
        if (!current.startsWith(root.path())) throw new SecurityException("Path escapes the referenced directory.");
        if (mustExist && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Referenced path does not exist.");
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            Path real = current.toRealPath();
            if (!real.startsWith(root.realPath())) throw new SecurityException("Path escapes the referenced directory.");
        }
        return current;
    }

    private void ensureSafeRoot(Path root) throws Exception {
        ensureDisjoint(root, dataDirectory, "Application data cannot be registered as user storage.");
        ensureDisjoint(root, managedStorageRoot, "The managed PersonalCloud storage directory cannot also be registered as a reference.");
    }

    private static Path canonicalUserDirectory(Path supplied) throws Exception {
        if (supplied == null) throw new IllegalArgumentException("A directory path is required.");
        Path absolute = supplied.toAbsolutePath().normalize();
        if (!Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("The selected directory does not exist.");
        if (Files.isSymbolicLink(absolute)) throw new IllegalArgumentException("A symbolic link cannot be registered as a storage root.");
        if (!Files.isDirectory(absolute, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("The selected path is not a directory.");
        if (!Files.isReadable(absolute) || !Files.isExecutable(absolute)) throw new IllegalArgumentException("The selected directory is not readable.");
        return absolute.toRealPath();
    }

    private static Path canonicalExistingDirectory(Path supplied, String label) throws Exception {
        Path absolute = supplied.toAbsolutePath().normalize();
        Files.createDirectories(absolute);
        return absolute.toRealPath();
    }

    private static void ensureDisjoint(Path left, Path right, String message) {
        if (pathsOverlap(left, right)) throw new IllegalArgumentException(message);
    }

    private static boolean pathsOverlap(Path left, Path right) {
        return left.startsWith(right) || right.startsWith(left);
    }

    private static String validateDisplayName(String value) {
        if (value == null) throw new IllegalArgumentException("A display name is required.");
        String name = value.trim();
        if (name.isBlank() || name.length() > 64 || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf('\n') >= 0 || name.indexOf('\r') >= 0 || name.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Display name must contain 1–64 printable characters.");
        }
        return name;
    }

    private static void requireId(String id) {
        if (id == null || !id.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Invalid reference ID.");
    }

    private static String portableRelative(Path root, Path child) {
        return root.relativize(child).toString().replace(child.getFileSystem().getSeparator(), "/");
    }

    private record Root(String id, String name, Path path, Path realPath) { }
}
