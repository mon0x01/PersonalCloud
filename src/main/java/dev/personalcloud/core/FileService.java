package dev.personalcloud.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class FileService implements AutoCloseable {
    private final Path root;
    private final Path realRoot;
    private final FileIndexer indexer;
    private final StorageWatcher watcher;

    public FileService(Path root) throws Exception {
        this.root = root.toAbsolutePath().normalize();
        Files.createDirectories(this.root);
        this.realRoot = this.root.toRealPath();
        this.indexer = new FileIndexer(this.root);
        this.watcher = new StorageWatcher(this.root);
    }

    public Path root() { return root; }

    public long storageRevision() { return watcher.revision(); }

    @Override public void close() { watcher.close(); }

    public FileIndexer indexer() { return indexer; }

    public List<Map<String, Object>> listFiles() throws Exception {
        List<Map<String, Object>> files = new ArrayList<>();
        for (FileMetadata metadata : indexer.index()) files.add(metadata.toMap());
        return files;
    }

    /** Lists directories separately from files so folder-level sharing is discoverable in the UI. */
    public List<Map<String, Object>> listFolders() throws Exception {
        List<Map<String, Object>> folders = new ArrayList<>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(item -> !item.equals(root))
                    .filter(item -> Files.isDirectory(item, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(item)).toList()) {
                try {
                    Path real = path.toRealPath();
                    if (!real.startsWith(realRoot)) continue;
                    folders.add(Map.of("name", path.getFileName().toString(), "path", relative(path)));
                } catch (Exception ignored) {
                    // A folder may disappear or become inaccessible while the index is being refreshed.
                }
            }
        }
        folders.sort(Comparator.comparing(item -> String.valueOf(item.get("path")).toLowerCase(java.util.Locale.ROOT)));
        return folders;
    }

    public String validateAndGetRelativeFile(String relativePath) throws Exception {
        Path file = resolve(relativePath);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The selected path is not a regular file inside the storage root.");
        }
        return relative(file);
    }

    public String validateAndGetRelativeSharePath(String relativePath) throws Exception {
        Path path = resolve(relativePath);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The selected path must be a regular file or directory inside the storage root.");
        }
        return relative(path);
    }

    public boolean isDirectory(String relativePath) throws Exception {
        return Files.isDirectory(resolve(relativePath), LinkOption.NOFOLLOW_LINKS);
    }

    public Map<String, Object> metadata(String relativePath) throws Exception {
        Path file = resolve(relativePath);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("File not found in storage root.");
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return Map.of("path", relative(file), "name", file.getFileName().toString(), "size", attrs.size(),
                "modified", attrs.lastModifiedTime().toInstant().toString());
    }

    public InputStream open(String relativePath) throws Exception {
        return Files.newInputStream(resolveRegularFile(relativePath));
    }

    public String sha256(String relativePath) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(resolveRegularFile(relativePath), LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    public void delete(String relativePath) throws Exception {
        Files.delete(resolveRegularFile(relativePath));
    }

    /** Move or rename a file/folder without overwriting an existing destination. */
    public String move(String sourcePath, String destinationPath) throws Exception {
        Path source = resolveEntry(sourcePath);
        Path target = resolveDestination(destinationPath, false);
        if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS) && target.startsWith(source)) {
            throw new IllegalArgumentException("A folder cannot be moved inside itself.");
        }
        if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
            try (var paths = Files.walk(source)) {
                if (paths.anyMatch(Files::isSymbolicLink)) {
                    throw new IllegalArgumentException("Folders containing symbolic links cannot be moved by PersonalCloud.");
                }
            }
        }
        // Do not request ATOMIC_MOVE here: some providers may replace an existing target
        // even when REPLACE_EXISTING was not supplied. The default operation preserves no-clobber semantics.
        Files.move(source, target);
        return relative(target);
    }

    /** Reads only bounded text previews; HTML/SVG and other active content is served as plain text. */
    public String previewText(String relativePath, int maxBytes) throws Exception {
        Path file = resolveRegularFile(relativePath);
        long size = Files.size(file);
        if (size > maxBytes) throw new IllegalArgumentException("Preview is limited to " + maxBytes + " bytes. Download the file instead.");
        String name = file.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        boolean text = java.util.List.of(".txt", ".md", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".java", ".js", ".css", ".html", ".properties", ".sh", ".py", ".sql")
                .stream().anyMatch(name::endsWith);
        if (!text) throw new IllegalArgumentException("Preview is available only for supported text files.");
        byte[] bytes;
        try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(maxBytes + 1);
        }
        if (bytes.length > maxBytes) throw new IllegalArgumentException("Preview is limited to " + maxBytes + " bytes. Download the file instead.");
        String content = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        if (content.indexOf('\u0000') >= 0) throw new IllegalArgumentException("Binary files cannot be previewed as text.");
        return content;
    }

    public long upload(String relativePath, InputStream input, long maxBytes) throws Exception {
        return upload(relativePath, input, maxBytes, false);
    }

    public long upload(String relativePath, InputStream input, long maxBytes, boolean createParents) throws Exception {
        Path target = resolveDestination(relativePath, createParents);
        Path parent = target.getParent();
        Path temp = parent.resolve(".personalcloud-upload-" + java.util.UUID.randomUUID() + ".tmp");
        long total = 0;
        try {
            try (OutputStream output = Files.newOutputStream(temp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[64 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    total = Math.addExact(total, count);
                    if (total > maxBytes) throw new IllegalArgumentException("Upload exceeds the configured maximum of " + maxBytes + " bytes.");
                    output.write(buffer, 0, count);
                }
                output.flush();
            }
            // Publish the completed inode atomically without replacing an existing destination.
            // Files.move(temp, target) is not sufficient here: on some providers its existence
            // check and rename can race, allowing a competing writer to replace the winner.
            // The temporary file is in the same directory, so hard-link creation is an atomic
            // create-if-absent operation. If the filesystem does not support hard links, fail
            // closed; never fall back to an overwrite-prone move.
            Files.createLink(target, temp);
            Files.delete(temp);
            return total;
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    public void createFolder(String relativePath) throws Exception {
        Path destination = resolveDestination(relativePath);
        Files.createDirectory(destination);
    }

    private Path resolveDestination(String relativePath) throws Exception {
        return resolveDestination(relativePath, false);
    }

    private Path resolveDestination(String relativePath, boolean createParents) throws Exception {
        if (relativePath == null || relativePath.isBlank()) throw new IllegalArgumentException("A destination path is required.");
        Path supplied;
        try { supplied = Path.of(relativePath); }
        catch (Exception error) { throw new IllegalArgumentException("Destination path is invalid."); }
        if (supplied.isAbsolute() || relativePath.matches("^[A-Za-z]:.*")) throw new IllegalArgumentException("Absolute paths are not accepted.");
        List<String> segments = new ArrayList<>();
        for (Path part : supplied) {
            String segment = part.toString();
            if (segment.isBlank() || segment.equals(".") || segment.equals("..") || segment.indexOf('\u0000') >= 0) {
                throw new IllegalArgumentException("Destination path contains an invalid path segment.");
            }
            segments.add(segment);
        }
        if (segments.isEmpty()) throw new IllegalArgumentException("Destination path is invalid.");
        Path current = root;
        for (int i = 0; i < segments.size(); i++) {
            String segment = segments.get(i);
            current = current.resolve(segment).normalize();
            if (!current.startsWith(root)) throw new IllegalArgumentException("Destination must remain inside the storage root.");
            if (i < segments.size() - 1) {
                if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                    if (Files.isSymbolicLink(current) || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                        throw new IllegalArgumentException("Destination parent is not a safe directory.");
                    }
                    if (!current.toRealPath().startsWith(realRoot)) throw new IllegalArgumentException("Destination escapes the storage root.");
                } else if (createParents) {
                    Files.createDirectory(current);
                } else {
                    throw new IllegalArgumentException("Destination folder does not exist.");
                }
            }
        }
        if (current.equals(root)) throw new IllegalArgumentException("Destination must be inside the storage root.");
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("A file or folder with that name already exists.");
        return current;
    }

    private Path resolveEntry(String relativePath) throws Exception {
        Path path = resolve(relativePath);
        if (Files.isSymbolicLink(path)) throw new IllegalArgumentException("Symbolic links cannot be moved.");
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Only regular files and folders can be moved.");
        }
        return path;
    }

    private Path resolveRegularFile(String relativePath) throws Exception {
        Path file = resolve(relativePath);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("File not found in storage root.");
        return file;
    }

    private Path resolve(String relativePath) throws Exception {
        if (relativePath == null || relativePath.isBlank()) throw new IllegalArgumentException("A file path is required.");
        Path supplied;
        try { supplied = Path.of(relativePath); }
        catch (Exception error) { throw new IllegalArgumentException("Path is invalid."); }
        if (supplied.isAbsolute() || relativePath.matches("^[A-Za-z]:.*")) throw new IllegalArgumentException("Absolute paths are not accepted.");
        Path resolved = root;
        for (Path part : supplied) {
            String segment = part.toString();
            if (segment.isBlank() || segment.equals(".") || segment.equals("..") || segment.indexOf('\u0000') >= 0) {
                throw new IllegalArgumentException("Path contains an invalid segment.");
            }
            resolved = resolved.resolve(segment);
            if (Files.isSymbolicLink(resolved)) throw new IllegalArgumentException("Symbolic links are not accessible through PersonalCloud.");
        }
        resolved = resolved.normalize();
        if (!resolved.startsWith(root) || resolved.equals(root)) throw new IllegalArgumentException("Path escapes the storage root.");
        if (!Files.exists(resolved, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("File does not exist.");
        Path real = resolved.toRealPath();
        if (!real.startsWith(realRoot)) throw new IllegalArgumentException("Path escapes the storage root.");
        return resolved;
    }

    private String relative(Path path) {
        return root.relativize(path).toString().replace(path.getFileSystem().getSeparator(), "/");
    }
}
