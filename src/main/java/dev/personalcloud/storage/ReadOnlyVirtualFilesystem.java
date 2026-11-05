package dev.personalcloud.storage;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.List;
import java.util.Objects;

/**
 * Stable, strict read-only filesystem boundary used by native OS adapters.
 *
 * The adapter receives kernel paths only; this class converts them into the canonical virtual
 * namespace, enforces bounded reads, and refuses to open stale/offline file content. Directories
 * backed by cached metadata remain browsable while their owning device is offline.
 */
public final class ReadOnlyVirtualFilesystem {
    public static final int MAX_READ_BYTES = 8 * 1024 * 1024;

    private final ReferenceFileSystemModel model;

    public ReadOnlyVirtualFilesystem(ReferenceFileSystemModel model) {
        this.model = Objects.requireNonNull(model, "model");
    }

    public List<String> list(String kernelPath) throws IOException {
        String path = normalize(kernelPath);
        ReferenceFileSystemModel.Attributes attributes = model.attributes(path);
        if (!attributes.directory()) throw new IOException("Not a directory: " + path);
        return model.list(path);
    }

    public ReferenceFileSystemModel.Attributes attributes(String kernelPath) throws IOException {
        return model.attributes(normalize(kernelPath));
    }

    /** Validate an open without reading data. All native adapters must open remote data read-only. */
    public ReferenceFileSystemModel.Attributes openForRead(String kernelPath) throws IOException {
        String path = normalize(kernelPath);
        ReferenceFileSystemModel.Attributes attributes = model.attributes(path);
        if (attributes.directory()) throw new IOException("Cannot open a directory as a file: " + path);
        if (!attributes.available()) throw new IOException("File owner is offline; cached metadata is visible but file content is unavailable: " + path);
        return attributes;
    }

    public byte[] read(String kernelPath, long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) {
            throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        }
        String path = normalize(kernelPath);
        openForRead(path);
        return model.read(path, offset, length);
    }

    /** Convert a FUSE/OS absolute path to the canonical virtual path without permitting traversal. */
    public static String normalize(String kernelPath) throws NoSuchFileException {
        if (kernelPath == null || kernelPath.isEmpty() || !kernelPath.startsWith("/")) {
            throw new NoSuchFileException(String.valueOf(kernelPath));
        }
        if (kernelPath.indexOf('\0') >= 0 || kernelPath.indexOf('\\') >= 0) throw new NoSuchFileException(kernelPath);
        StringBuilder normalized = new StringBuilder();
        for (String segment : kernelPath.substring(1).split("/", -1)) {
            if (segment.isEmpty()) continue;
            if (segment.equals(".") || segment.equals("..")) throw new NoSuchFileException(kernelPath);
            normalized.append('/').append(segment);
        }
        return normalized.isEmpty() ? "/" : normalized.toString();
    }
}
