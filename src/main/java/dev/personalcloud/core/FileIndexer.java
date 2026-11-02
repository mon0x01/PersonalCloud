package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Scans one storage directory and converts its regular files into FileMetadata objects. */
public final class FileIndexer {
    private final Path directory;
    private final Path realDirectory;

    public FileIndexer(Path directory) throws Exception {
        this.directory = directory.toAbsolutePath().normalize();
        if (!Files.exists(this.directory)) throw new IllegalArgumentException("Storage path does not exist: " + this.directory);
        if (!Files.isDirectory(this.directory)) throw new IllegalArgumentException("Storage path is not a directory: " + this.directory);
        this.realDirectory = this.directory.toRealPath();
    }

    public List<FileMetadata> index() throws Exception {
        List<FileMetadata> result = new ArrayList<>();
        try (var paths = Files.walk(directory)) {
            paths.filter(path -> !path.equals(directory))
                    // A process may crash during an upload; never expose its incomplete temporary file.
                    .filter(path -> !isUploadTemporary(path))
                    .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .forEach(path -> {
                        try {
                            Path realPath = path.toRealPath();
                            if (!realPath.startsWith(realDirectory)) return;
                            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                            String relative = directory.relativize(path).toString().replace(path.getFileSystem().getSeparator(), "/");
                            result.add(new FileMetadata(path.getFileName().toString(), relative,
                                    attributes.size(), attributes.lastModifiedTime().toInstant().toString()));
                        } catch (Exception ignored) {
                            // Files can disappear or become inaccessible while a directory is being indexed.
                        }
                    });
        }
        result.sort(Comparator.comparing(item -> item.getFilePath().toLowerCase()));
        return result;
    }

    private static boolean isUploadTemporary(Path path) {
        String name = path.getFileName().toString();
        return name.startsWith(".personalcloud-upload-") && name.endsWith(".tmp");
    }
}
