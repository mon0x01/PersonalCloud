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

    public GrantService(StateStore store, FileService files, PeerService peers) {
        this.store = store;
        this.files = files;
        this.peers = peers;
    }

    public Map<String, Object> create(String peerId, String relativePath, String permission) throws Exception {
        if (store.getRecord("trusted", peerId) == null) throw new IllegalArgumentException("That device has not paired with this node. Pairing must be initiated from the receiving device first.");
        String normalizedPath = files.validateAndGetRelativeFile(relativePath);
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
        for (Map<String, String> grant : store.records("grant")) {
            if (!peerId.equals(grant.get("peerId"))) continue;
            try {
                Map<String, Object> metadata = files.metadata(grant.get("relativePath"));
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("shareId", grant.get("_id"));
                item.put("name", metadata.get("name"));
                item.put("size", metadata.get("size"));
                item.put("modified", metadata.get("modified"));
                item.put("permission", grant.get("permission"));
                result.add(item);
            } catch (Exception missing) {
                // A file may have been moved or deleted after it was shared.
            }
        }
        return result;
    }

    public Map<String, String> getGrant(String id) { return store.getRecord("grant", id); }

    public void revoke(String id) throws Exception { store.removeRecord("grant", id); }

    public String deleteSharedOriginal(String id, String peerId) throws Exception {
        Map<String, String> grant = store.getRecord("grant", id);
        if (grant == null || !peerId.equals(grant.get("peerId"))) throw new IllegalArgumentException("Shared file not found.");
        if (!"MODIFY".equals(grant.get("permission"))) throw new SecurityException("This share only allows viewing and downloading.");
        String path = grant.get("relativePath");
        files.delete(path);
        // Remove every grant for the deleted original, since the original no longer exists.
        for (Map<String, String> other : store.records("grant")) {
            if (path.equals(other.get("relativePath"))) store.removeRecord("grant", other.get("_id"));
        }
        return path;
    }

    private Map<String, Object> publicGrant(String id, Map<String, String> grant) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("peerId", grant.get("peerId"));
        result.put("path", grant.get("relativePath"));
        result.put("permission", grant.get("permission"));
        result.put("createdAt", grant.get("createdAt"));
        return result;
    }
}
