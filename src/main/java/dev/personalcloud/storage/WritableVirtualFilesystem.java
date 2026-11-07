package dev.personalcloud.storage;

import dev.personalcloud.control.LocalControlClient;
import dev.personalcloud.core.SecretFiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Native-adapter view over the read-only reference namespace plus the writable
 * eligible-storage namespace of active remote peers.
 *
 * <p>Read-only paths are delegated to {@link ReferenceFileSystemModel}. Writable
 * paths live under {@code /Devices/<device>/Filesystem/<root>/...} and are always
 * executed by the owning peer through the authenticated protocol; this class
 * never writes to remote storage directly and never bypasses owner policy.</p>
 */
public final class WritableVirtualFilesystem {
    public static final int MAX_READ_BYTES = ReadOnlyVirtualFilesystem.MAX_READ_BYTES;
    private static final String DEVICES = "Devices";
    private static final String REFERENCES = "References";
    private static final String MANAGED = "Distributed-Storage";
    private static final String FILESYSTEM = "Filesystem";

    private final ReferenceFileSystemModel reference;
    private final LocalControlClient client;

    public WritableVirtualFilesystem(ReferenceFileSystemModel reference, LocalControlClient client) {
        if (reference == null || client == null) throw new IllegalArgumentException("Reference model and control client are required.");
        this.reference = reference;
        this.client = client;
    }

    public List<String> list(String kernelPath) throws IOException {
        String path = ReadOnlyVirtualFilesystem.normalize(kernelPath);
        List<String> parts = segments(path);
        if (parts.isEmpty()) return List.of(DEVICES);
        if (!DEVICES.equals(parts.get(0))) throw new NoSuchFileException(path);
        if (parts.size() == 1) return reference.list("/Devices");
        Map<String, Object> device = reference.requireDeviceRow(parts.get(1));
        if (parts.size() == 2) {
            List<String> entries = new ArrayList<>(reference.list(path));
            if (remoteFilesystemAvailable(device)) entries.add(FILESYSTEM);
            return List.copyOf(entries);
        }
        if (FILESYSTEM.equals(parts.get(2))) {
            requireRemoteFilesystem(device);
            if (parts.size() == 3) {
                return rootEntries(device).stream().map(RootInfo::displayName)
                        .sorted(String.CASE_INSENSITIVE_ORDER).toList();
            }
            RootInfo root = requireRoot(device, parts.get(3));
            String relative = parts.size() <= 4 ? "" : String.join("/", parts.subList(4, parts.size()));
            List<String> names = new ArrayList<>();
            List<Map<String, Object>> entries;
            try {
                entries = client.browseRemoteFilesystem(memberId(device), root.rootId(), relative);
            } catch (IOException failure) {
                throw missingOr(failure, path);
            }
            for (Map<String, Object> entry : entries) {
                String name = text(entry.get("name"));
                if (!name.isEmpty()) names.add(name);
            }
            names.sort(String.CASE_INSENSITIVE_ORDER);
            return List.copyOf(names);
        }
        return reference.list(path);
    }

    public ReferenceFileSystemModel.Attributes attributes(String kernelPath) throws IOException {
        String path = ReadOnlyVirtualFilesystem.normalize(kernelPath);
        List<String> parts = segments(path);
        if (parts.isEmpty() || (parts.size() == 1 && DEVICES.equals(parts.get(0)))) {
            return new ReferenceFileSystemModel.Attributes(true, 0, "", true);
        }
        if (!DEVICES.equals(parts.get(0)) || parts.size() < 2) throw new NoSuchFileException(path);
        Map<String, Object> device = reference.requireDeviceRow(parts.get(1));
        if (parts.size() == 2) return new ReferenceFileSystemModel.Attributes(true, 0, "", deviceOnline(device));
        if (parts.size() == 3 && (REFERENCES.equals(parts.get(2)) || MANAGED.equals(parts.get(2)))) {
            return reference.attributes(path);
        }
        if (FILESYSTEM.equals(parts.get(2))) {
            requireRemoteFilesystem(device);
            if (parts.size() == 3) return new ReferenceFileSystemModel.Attributes(true, 0, "", true);
            RootInfo root = requireRoot(device, parts.get(3));
            if (parts.size() == 4) return new ReferenceFileSystemModel.Attributes(true, 0, "", true);
            String relative = String.join("/", parts.subList(4, parts.size()));
            Map<String, Object> metadata;
            try {
                metadata = client.statRemoteFilesystem(memberId(device), root.rootId(), relative);
            } catch (IOException failure) {
                throw missingOr(failure, path);
            }
            boolean directory = "DIRECTORY".equalsIgnoreCase(text(metadata.get("kind")));
            return new ReferenceFileSystemModel.Attributes(directory,
                    directory ? 0 : number(metadata.get("size")), text(metadata.get("modified")), true);
        }
        return reference.attributes(path);
    }

    public ReferenceFileSystemModel.Attributes openForRead(String kernelPath) throws IOException {
        ReferenceFileSystemModel.Attributes attributes = attributes(kernelPath);
        if (attributes.directory()) throw new IOException("Cannot open a directory as a file: " + kernelPath);
        if (!attributes.available()) throw new IOException("File owner is offline; cached metadata is visible but file content is unavailable: " + kernelPath);
        return attributes;
    }

    public byte[] read(String kernelPath, long offset, int length) throws IOException {
        if (offset < 0) throw new IllegalArgumentException("Read offset cannot be negative.");
        if (length < 0 || length > MAX_READ_BYTES) {
            throw new IllegalArgumentException("Read length must be between 0 and " + MAX_READ_BYTES + " bytes.");
        }
        RemotePath remote = remotePath(kernelPath);
        if (remote == null) return reference.read(kernelPath, offset, length);
        openForRead(kernelPath);
        return client.readRemoteFilesystemRange(remote.memberId(), remote.rootId(), remote.relative(), offset, length);
    }

    /** True only for paths that the owning peer exposes through eligible storage. */
    public boolean isWritable(String kernelPath) {
        return remotePath(kernelPath) != null;
    }

    /** Checks existence through the owner's authorized directory listing. */
    public boolean exists(String kernelPath) throws IOException {
        RemotePath remote = remotePath(kernelPath);
        if (remote == null) return false;
        return remoteExists(remote.memberId(), remote.rootId(), remote.relative(), 0);
    }

    private boolean remoteExists(String memberId, String rootId, String relative, int depth) throws IOException {
        if (relative.isEmpty()) return true;
        if (depth > 64) throw new IOException("Eligible-storage path is too deeply nested.");
        String parent = parentOf(relative);
        String name = lastSegment(relative);
        List<Map<String, Object>> entries;
        try {
            entries = client.browseRemoteFilesystem(memberId, rootId, parent);
        } catch (IOException failure) {
            if (!parent.isEmpty() && !remoteExists(memberId, rootId, parent, depth + 1)) return false;
            throw failure;
        }
        for (Map<String, Object> entry : entries) {
            if (name.equals(text(entry.get("name")))) return true;
        }
        return false;
    }

    /**
     * Maps an owner error to a missing-path error only when the path is genuinely
     * absent. A failed existence probe never masks the original owner failure.
     */
    private IOException missingOr(IOException failure, String kernelPath) {
        try {
            if (!exists(kernelPath)) return new NoSuchFileException(kernelPath);
        } catch (IOException ignored) {
            // Preserve the original failure when reachability or authorization is the cause.
        }
        return failure;
    }

    public void createFile(String kernelPath) throws IOException {
        RemotePath remote = requireWritable(kernelPath);
        Path staging = createStaging();
        try {
            Files.write(staging, new byte[0]);
            client.uploadRemoteFilesystemFile(remote.memberId(), remote.rootId(), remote.relative(), staging, false, "");
        } finally {
            deleteStaging(staging);
        }
    }

    public void createDirectory(String kernelPath) throws IOException {
        RemotePath remote = requireWritable(kernelPath);
        client.createRemoteFilesystemDirectory(remote.memberId(), remote.rootId(), remote.relative());
    }

    public void move(String kernelPath, String newKernelPath) throws IOException {
        RemotePath from = requireWritable(kernelPath);
        RemotePath to = requireWritable(newKernelPath);
        if (!from.memberId().equals(to.memberId()) || !from.rootId().equals(to.rootId())) {
            throw new IOException("PersonalCloud cannot move entries across devices or eligible roots.");
        }
        client.moveRemoteFilesystemEntry(from.memberId(), from.rootId(), from.relative(), to.relative(), false, "", "");
    }

    public void delete(String kernelPath, boolean recursive) throws IOException {
        RemotePath remote = requireWritable(kernelPath);
        client.deleteRemoteFilesystemEntry(remote.memberId(), remote.rootId(), remote.relative(), recursive, "");
    }

    /** Downloads the current remote bytes into a new local staging path. */
    public void download(String kernelPath, Path destination) throws IOException {
        RemotePath remote = requireWritable(kernelPath);
        client.downloadRemoteFilesystemFile(remote.memberId(), remote.rootId(), remote.relative(), destination);
    }

    /** Publishes a completed local staging file. Existing bytes are replaced only when requested. */
    public void upload(String kernelPath, Path staging, boolean overwrite) throws IOException {
        RemotePath remote = requireWritable(kernelPath);
        client.uploadRemoteFilesystemFile(remote.memberId(), remote.rootId(), remote.relative(), staging, overwrite, "");
    }

    public Path createStaging() throws IOException {
        Path directory = Files.createTempDirectory("personalcloud-fuse-");
        SecretFiles.restrictDirectory(directory);
        return directory.resolve("data");
    }

    public void deleteStaging(Path staging) {
        if (staging == null) return;
        try { Files.deleteIfExists(staging); } catch (IOException ignored) { }
        Path parent = staging.getParent();
        if (parent != null && parent.getFileName() != null
                && parent.getFileName().toString().startsWith("personalcloud-fuse-")) {
            try { Files.deleteIfExists(parent); } catch (IOException ignored) { }
        }
    }

    private RemotePath requireWritable(String kernelPath) throws IOException {
        RemotePath remote = remotePath(kernelPath);
        if (remote == null) throw new IOException("Path is outside writable PersonalCloud storage: " + kernelPath);
        return remote;
    }

    private RemotePath remotePath(String kernelPath) {
        try {
            List<String> parts = segments(ReadOnlyVirtualFilesystem.normalize(kernelPath));
            if (parts.size() < 4 || !DEVICES.equals(parts.get(0)) || !FILESYSTEM.equals(parts.get(2))) return null;
            Map<String, Object> device = reference.requireDeviceRow(parts.get(1));
            if (!remoteFilesystemAvailable(device)) return null;
            RootInfo root = requireRoot(device, parts.get(3));
            String relative = parts.size() <= 4 ? "" : String.join("/", parts.subList(4, parts.size()));
            return new RemotePath(memberId(device), root.rootId(), relative);
        } catch (IOException | SecurityException unavailable) {
            return null;
        }
    }

    private List<RootInfo> rootEntries(Map<String, Object> device) throws IOException {
        List<Map<String, Object>> roots = client.listRemoteFilesystemRoots(memberId(device));
        Map<String, Long> counts = new java.util.HashMap<>();
        for (Map<String, Object> root : roots) {
            String name = text(root.get("name"));
            counts.merge(name.toLowerCase(Locale.ROOT), 1L, Long::sum);
        }
        List<RootInfo> result = new ArrayList<>();
        Set<String> used = new HashSet<>();
        for (Map<String, Object> root : roots) {
            String rootId = text(root.get("rootId"));
            if (rootId.isEmpty()) continue;
            String name = text(root.get("name"));
            if (name.isEmpty()) name = "Storage";
            String display = name;
            if (counts.getOrDefault(name.toLowerCase(Locale.ROOT), 0L) > 1L) {
                display += " [" + shortId(rootId) + "]";
            }
            String unique = display;
            int suffix = 2;
            while (!used.add(unique.toLowerCase(Locale.ROOT))) unique = display + " (" + suffix++ + ")";
            result.add(new RootInfo(unique, rootId));
        }
        result.sort(Comparator.comparing(root -> root.displayName().toLowerCase(Locale.ROOT)));
        return List.copyOf(result);
    }

    private RootInfo requireRoot(Map<String, Object> device, String displayName) throws IOException {
        for (RootInfo root : rootEntries(device)) if (root.displayName().equals(displayName)) return root;
        throw new NoSuchFileException(displayName);
    }

    /**
     * Eligible storage is exposed for active remote members. Reachability is not
     * required to browse the namespace: offline operations fail honestly at the
     * owner's endpoint instead of silently hiding the owner's storage plane.
     */
    private static boolean remoteFilesystemAvailable(Map<String, Object> device) {
        return !Boolean.TRUE.equals(device.get("local"))
                && Boolean.TRUE.equals(device.get("active"));
    }

    private static void requireRemoteFilesystem(Map<String, Object> device) throws IOException {
        if (!remoteFilesystemAvailable(device)) {
            throw new IOException("Eligible storage is available only for active remote devices.");
        }
    }

    private static String memberId(Map<String, Object> device) {
        return text(device.get("nodeId"));
    }

    private static boolean deviceOnline(Map<String, Object> device) {
        return Boolean.TRUE.equals(device.get("online"));
    }

    private static List<String> segments(String path) throws NoSuchFileException {
        String normalized = ReadOnlyVirtualFilesystem.normalize(path);
        if ("/".equals(normalized)) return List.of();
        List<String> result = new ArrayList<>();
        for (String segment : normalized.substring(1).split("/", -1)) {
            if (!segment.isEmpty()) result.add(segment);
        }
        return result;
    }

    private static String shortId(String value) {
        return value.length() <= 8 ? value : value.substring(0, 8);
    }

    private static String parentOf(String relative) {
        int separator = relative.lastIndexOf('/');
        return separator < 0 ? "" : relative.substring(0, separator);
    }

    private static String lastSegment(String relative) {
        int separator = relative.lastIndexOf('/');
        return separator < 0 ? relative : relative.substring(separator + 1);
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static long number(Object value) {
        return value instanceof Number number ? number.longValue() : 0L;
    }

    private record RootInfo(String displayName, String rootId) { }

    private record RemotePath(String memberId, String rootId, String relative) { }
}
