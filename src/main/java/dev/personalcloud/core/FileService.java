package dev.personalcloud.core;

import java.io.InputStream;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class FileService {
    private final Path root;
    private final Path realRoot;
    private final FileIndexer indexer;

    public FileService(Path root) throws Exception {
        this.root = root.toAbsolutePath().normalize();
        Files.createDirectories(this.root);
        this.realRoot = this.root.toRealPath();
        this.indexer = new FileIndexer(this.root);
    }

    public Path root() { return root; }

    public List<Map<String, Object>> listFiles() throws Exception {
        List<Map<String, Object>> files = new ArrayList<>();
        for (FileMetadata metadata : indexer.index()) files.add(metadata.toMap());
        return files;
    }

    public String validateAndGetRelativeFile(String relativePath) throws Exception {
        Path file = resolve(relativePath);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The selected path is not a regular file inside the storage root.");
        }
        return relative(file);
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

    public void delete(String relativePath) throws Exception {
        Files.delete(resolveRegularFile(relativePath));
    }

    private Path resolveRegularFile(String relativePath) throws Exception {
        Path file = resolve(relativePath);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("File not found in storage root.");
        return file;
    }

    private Path resolve(String relativePath) throws Exception {
        if (relativePath == null || relativePath.isBlank()) throw new IllegalArgumentException("A file path is required.");
        Path supplied = Path.of(relativePath);
        if (supplied.isAbsolute()) throw new IllegalArgumentException("Absolute paths are not accepted.");
        Path resolved = root.resolve(supplied).normalize();
        if (!resolved.startsWith(root)) throw new IllegalArgumentException("Path escapes the storage root.");
        if (!Files.exists(resolved, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("File does not exist.");
        Path real = resolved.toRealPath();
        if (!real.startsWith(realRoot)) throw new IllegalArgumentException("Path escapes the storage root, including through a symbolic-link directory.");
        return resolved;
    }

    private String relative(Path path) {
        return root.relativize(path).toString().replace(path.getFileSystem().getSeparator(), "/");
    }
}
