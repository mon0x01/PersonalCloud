package dev.personalcloud.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class GrantService {
    private final StateStore store;
    private final FileService files;
    private final PeerService peers;
    private final VersionService versions;
    private final long maxVersionBytes;

    public GrantService(StateStore store, FileService files, PeerService peers, VersionService versions, long maxVersionBytes) {
        this.store = store;
        this.files = files;
        this.peers = peers;
        this.versions = versions;
        this.maxVersionBytes = maxVersionBytes;
    }

    public Map<String, Object> create(String peerId, String relativePath, String permission) throws Exception {
        if (store.getRecord("trusted", peerId) == null) throw new IllegalArgumentException("That device has not paired with this node. Pairing must be initiated from the receiving device first.");
        String normalizedPath = files.validateAndGetRelativeSharePath(relativePath);
        boolean directory = files.isDirectory(normalizedPath);
        String level = permission == null ? "VIEW" : permission.toUpperCase();
        if (!level.equals("VIEW") && !level.equals("MODIFY")) throw new IllegalArgumentException("Permission must be VIEW or MODIFY.");
        for (Map<String, String> existing : store.records("grant")) {
            if (peerId.equals(existing.get("peerId")) && normalizedPath.equals(existing.get("relativePath"))) {
                store.removeRecord("grant", existing.get("_id"));
            }
        }
        String id = UUID.randomUUID().toString();
        Map<String, String> record = new LinkedHashMap<>();
        record.put("peerId", peerId);
        record.put("relativePath", normalizedPath);
        record.put("kind", directory ? "FOLDER" : "FILE");
        record.put("permission", level);
        record.put("createdAt", Instant.now().toString());
        store.putRecord("grant", id, record);
        return publicGrant(id, record);
    }

    public List<Map<String, Object>> listAll() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> grant : store.records("grant")) {
            Map<String, String> peer = store.getRecord("trusted", grant.get("peerId"));
            Map<String, Object> item = new LinkedHashMap<>(publicGrant(grant.get("_id"), grant));
            item.put("peerName", peer == null ? "Unknown device" : peer.getOrDefault("name", "Unknown device"));
            result.add(item);
        }
        return result;
    }

    public List<Map<String, Object>> listForPeer(String peerId) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        List<FileMetadata> allFiles = files.indexer().index();
        for (Map<String, String> grant : store.records("grant")) {
            if (!peerId.equals(grant.get("peerId"))) continue;
            String base = grant.get("relativePath");
            boolean folder = "FOLDER".equals(grant.get("kind"));
            if (!folder) {
                addSharedFile(result, grant, base, grant.get("_id"));
                continue;
            }
            String prefix = base.endsWith("/") ? base : base + "/";
            long totalBytes = 0;
            int fileCount = 0;
            for (FileMetadata file : allFiles) {
                if (file.getFilePath().startsWith(prefix)) { totalBytes += file.getFileSize(); fileCount++; }
            }
            Map<String, Object> folderItem = new LinkedHashMap<>();
            folderItem.put("shareId", grant.get("_id"));
            folderItem.put("name", base.substring(base.lastIndexOf('/') + 1));
            folderItem.put("path", base);
            folderItem.put("kind", "FOLDER");
            folderItem.put("size", totalBytes);
            folderItem.put("fileCount", fileCount);
            folderItem.put("permission", grant.get("permission"));
            result.add(folderItem);
            for (FileMetadata file : allFiles) {
                String path = file.getFilePath();
                if (path.startsWith(prefix)) addSharedFile(result, grant, path, folderShareId(grant.get("_id"), path));
            }
        }
        return result;
    }

    private void addSharedFile(List<Map<String, Object>> result, Map<String, String> grant, String path, String shareId) {
        try {
            Map<String, Object> metadata = files.metadata(path);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("shareId", shareId);
            item.put("name", metadata.get("name"));
            item.put("path", path);
            item.put("kind", "FILE");
            item.put("size", metadata.get("size"));
            item.put("modified", metadata.get("modified"));
            item.put("permission", grant.get("permission"));
            result.add(item);
        } catch (Exception ignored) { }
    }

    private static String folderShareId(String grantId, String path) {
        String value = grantId + "\n" + path;
        return "f_" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private record ResolvedShare(Map<String, String> grant, String path) { }

    private ResolvedShare resolveShare(String shareId, String peerId) throws Exception {
        Map<String, String> grant = store.getRecord("grant", shareId);
        if (grant != null) {
            if (!peerId.equals(grant.get("peerId"))) throw new IllegalArgumentException("Shared file not found.");
            if ("FOLDER".equals(grant.get("kind"))) throw new IllegalArgumentException("A folder grant requires a file-specific share identifier.");
            files.validateAndGetRelativeFile(grant.get("relativePath"));
            return new ResolvedShare(grant, grant.get("relativePath"));
        }
        if (shareId == null || !shareId.startsWith("f_")) throw new IllegalArgumentException("Shared file not found.");
        String decoded;
        try { decoded = new String(java.util.Base64.getUrlDecoder().decode(shareId.substring(2)), java.nio.charset.StandardCharsets.UTF_8); }
        catch (Exception error) { throw new IllegalArgumentException("Shared file not found."); }
        int separator = decoded.indexOf('\n');
        if (separator < 1) throw new IllegalArgumentException("Shared file not found.");
        String grantId = decoded.substring(0, separator);
        String path = decoded.substring(separator + 1);
        grant = store.getRecord("grant", grantId);
        if (grant == null || !peerId.equals(grant.get("peerId")) || !"FOLDER".equals(grant.get("kind"))) {
            throw new IllegalArgumentException("Shared file not found.");
        }
        String folder = grant.get("relativePath");
        String prefix = folder.endsWith("/") ? folder : folder + "/";
        if (!path.startsWith(prefix)) throw new SecurityException("Requested file is outside the shared folder.");
        files.validateAndGetRelativeFile(path);
        return new ResolvedShare(grant, path);
    }

    public String resolveSharePath(String shareId, String peerId) throws Exception {
        return resolveShare(shareId, peerId).path();
    }

    public String folderPathForPeer(String grantId, String peerId) throws Exception {
        Map<String, String> grant = store.getRecord("grant", grantId);
        if (grant == null || !peerId.equals(grant.get("peerId")) || !"FOLDER".equals(grant.get("kind"))) {
            throw new IllegalArgumentException("Shared folder not found.");
        }
        if (!files.isDirectory(grant.get("relativePath"))) throw new IllegalArgumentException("Shared folder no longer exists.");
        return grant.get("relativePath");
    }

    public List<String> folderFilesForPeer(String grantId, String peerId) throws Exception {
        String folder = folderPathForPeer(grantId, peerId);
        String prefix = folder.endsWith("/") ? folder : folder + "/";
        List<String> result = new ArrayList<>();
        for (FileMetadata file : files.indexer().index()) {
            if (file.getFilePath().startsWith(prefix)) result.add(file.getFilePath());
        }
        return result;
    }

    public Map<String, String> getGrant(String id) { return store.getRecord("grant", id); }

    public void revoke(String id) throws Exception { store.removeRecord("grant", id); }

    public String deleteSharedOriginal(String id, String peerId) throws Exception {
        ResolvedShare resolved = resolveShare(id, peerId);
        if (!"MODIFY".equals(resolved.grant().get("permission"))) throw new SecurityException("This share only allows viewing and downloading.");
        String path = resolved.path();
        // Preserve a local owner-controlled recovery point before a peer can delete the original.
        versions.snapshot(path, "REMOTE_MODIFY_DELETE", maxVersionBytes);
        files.delete(path);
        for (Map<String, String> other : store.records("grant")) {
            if (path.equals(other.get("relativePath"))) store.removeRecord("grant", other.get("_id"));
        }
        return path;
    }


    /** Keep explicit grants attached to a file/folder when the owner moves it locally. */
    public void rewritePaths(String source, String destination) throws Exception {
        String prefix = source.endsWith("/") ? source : source + "/";
        for (Map<String, String> grant : store.records("grant")) {
            String path = grant.get("relativePath");
            if (source.equals(path) || path.startsWith(prefix)) {
                String nextPath = destination + path.substring(source.length());
                Map<String, String> updated = new LinkedHashMap<>(grant);
                updated.remove("_id");
                updated.put("relativePath", nextPath);
                store.putRecord("grant", grant.get("_id"), updated);
            }
        }
    }

    public void removeGrantsForDeletedPath(String path) throws Exception {
        for (Map<String, String> grant : store.records("grant")) {
            if (path.equals(grant.get("relativePath"))) store.removeRecord("grant", grant.get("_id"));
        }
    }

    private Map<String, Object> publicGrant(String id, Map<String, String> grant) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("peerId", grant.get("peerId"));
        result.put("path", grant.get("relativePath"));
        result.put("kind", grant.getOrDefault("kind", "FILE"));
        result.put("permission", grant.get("permission"));
        result.put("createdAt", grant.get("createdAt"));
        return result;
    }
}
