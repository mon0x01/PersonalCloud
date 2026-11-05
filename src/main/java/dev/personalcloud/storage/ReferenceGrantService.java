package dev.personalcloud.storage;

import dev.personalcloud.core.StateStore;
import dev.personalcloud.network.NetworkMembershipService;

import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Per-member authorization for remotely browsing or downloading referenced files. */
public final class ReferenceGrantService {
    private final StateStore store;
    private final ReferenceStorageService references;
    private final NetworkMembershipService membership;

    public ReferenceGrantService(StateStore store, ReferenceStorageService references, NetworkMembershipService membership) {
        this.store = store;
        this.references = references;
        this.membership = membership;
    }

    public synchronized Map<String, Object> create(String memberId, String referenceId, String relativePath, String permission) throws Exception {
        if (!membership.isActiveMember(memberId)) throw new IllegalArgumentException("The target device is not an active member of this network.");
        String path = normalizeRelative(relativePath == null ? "" : relativePath);
        Map<String, Object> metadata = references.inspect(referenceId, path);
        String kind = "DIRECTORY".equals(metadata.get("kind")) ? "FOLDER" : "FILE";
        String normalizedPermission = normalizePermission(permission);
        for (Map<String, String> existing : store.records("referenceGrant")) {
            if (memberId.equals(existing.get("memberId")) && referenceId.equals(existing.get("referenceId"))
                    && path.equals(existing.get("path"))) store.removeRecord("referenceGrant", existing.get("_id"));
        }
        String id = UUID.randomUUID().toString();
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("memberId", memberId);
        fields.put("referenceId", referenceId);
        fields.put("path", path);
        fields.put("kind", kind);
        fields.put("permission", normalizedPermission);
        fields.put("createdAt", Instant.now().toString());
        store.putRecord("referenceGrant", id, fields);
        return toPublic(id, fields);
    }

    public synchronized List<Map<String, Object>> listAll() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> grant : store.records("referenceGrant")) {
            Map<String, Object> row = new LinkedHashMap<>(toPublic(grant.get("_id"), grant));
            row.put("memberName", membership.memberDetails(grant.get("memberId")).getOrDefault("name", "Unknown device"));
            result.add(row);
        }
        result.sort(Comparator.comparing(row -> String.valueOf(row.get("createdAt"))));
        return List.copyOf(result);
    }

    public synchronized List<Map<String, Object>> listForMember(String memberId) throws Exception {
        requireActiveRequester(memberId);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> grant : store.records("referenceGrant")) {
            if (!memberId.equals(grant.get("memberId"))) continue;
            Map<String, Object> metadata = references.inspect(grant.get("referenceId"), grant.get("path"));
            Map<String, Object> row = new LinkedHashMap<>(toPublic(grant.get("_id"), grant));
            row.put("ownerNodeId", membership.status().get("nodeId"));
            row.put("rootName", metadata.get("storageName"));
            row.put("name", metadata.get("name"));
            row.put("size", metadata.get("size"));
            row.put("modified", metadata.get("modified"));
            result.add(row);
        }
        return List.copyOf(result);
    }

    public synchronized List<StorageEntry> browse(String memberId, String grantId, String relativeDirectory) throws Exception {
        Map<String, String> grant = requireGrant(memberId, grantId);
        if (!"FOLDER".equals(grant.get("kind"))) throw new IllegalArgumentException("This grant is for a single file, not a directory.");
        String base = grant.getOrDefault("path", "");
        String path = combine(base, relativeDirectory);
        List<StorageEntry> entries = references.listEntries(grant.get("referenceId"), path);
        if (base.isBlank()) return entries;
        List<StorageEntry> relativeEntries = new ArrayList<>(entries.size());
        for (StorageEntry entry : entries) {
            String relative = stripGrantBase(base, entry.relativePath());
            relativeEntries.add(new StorageEntry(entry.storageId(), entry.storageName(), relative,
                    entry.name(), entry.kind(), entry.sizeBytes(), entry.modifiedAt()));
        }
        return List.copyOf(relativeEntries);
    }

    public synchronized Map<String, Object> stat(String memberId, String grantId, String relativePath) throws Exception {
        Map<String, String> grant = requireGrant(memberId, grantId);
        String path = resolveGrantPath(grant, relativePath);
        return references.inspect(grant.get("referenceId"), path);
    }

    public synchronized InputStream openFile(String memberId, String grantId, String relativePath) throws Exception {
        Map<String, String> grant = requireGrant(memberId, grantId);
        String path = resolveGrantPath(grant, relativePath);
        Map<String, Object> metadata = references.inspect(grant.get("referenceId"), path);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The requested path is not a file.");
        return references.openFile(grant.get("referenceId"), path);
    }

    public synchronized String sha256(String memberId, String grantId, String relativePath) throws Exception {
        Map<String, String> grant = requireGrant(memberId, grantId);
        String path = resolveGrantPath(grant, relativePath);
        Map<String, Object> metadata = references.inspect(grant.get("referenceId"), path);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The requested path is not a file.");
        return references.sha256(grant.get("referenceId"), path);
    }

    public synchronized Map<String, Object> delete(String memberId, String grantId, String relativePath,
                                                   ReferenceVersionService versions, long maxSnapshotBytes) throws Exception {
        Map<String, String> grant = requireGrant(memberId, grantId);
        if (!"DOWNLOAD+DELETE".equals(grant.get("permission"))) throw new SecurityException("This file was shared as DOWNLOAD only; deletion is not authorized.");
        String path = resolveGrantPath(grant, relativePath);
        Map<String,Object> deleted = versions.snapshotAndDelete(grant.get("referenceId"), path, maxSnapshotBytes);
        if ("FILE".equals(grant.get("kind"))) store.removeRecord("referenceGrant", grantId);
        return deleted;
    }

    public synchronized void revoke(String grantId) throws Exception {
        if (store.getRecord("referenceGrant", grantId) == null) throw new IllegalArgumentException("Referenced-file grant not found.");
        store.removeRecord("referenceGrant", grantId);
    }

    public synchronized List<Map<String, Object>> search(String memberId, String query, int limit) throws Exception {
        requireActiveRequester(memberId);
        int bounded = Math.max(1, Math.min(limit, 100));
        List<StorageEntry> found = references.search(query, Math.min(200, bounded * 3));
        List<Map<String, Object>> result = new ArrayList<>();
        List<Map<String, String>> grants = store.records("referenceGrant").stream()
                .filter(row -> memberId.equals(row.get("memberId"))).toList();
        for (StorageEntry entry : found) {
            Map<String, String> grant = grants.stream()
                    .filter(row -> entry.storageId().equals(row.get("referenceId")))
                    .filter(row -> allowsPath(row, entry.relativePath(), entry.kind()))
                    .max(Comparator.comparingInt((Map<String, String> row) -> row.getOrDefault("path", "").length())
                            .thenComparingInt(row -> "FILE".equals(row.get("kind")) ? 1 : 0)
                            .thenComparingInt(row -> "DOWNLOAD".equals(row.get("permission")) ? 1 : 0))
                    .orElse(null);
            if (grant != null) {
                Map<String, Object> item = new LinkedHashMap<>(entry.toMap());
                String grantPath = grant.getOrDefault("path", "");
                String grantRelativePath = "FILE".equals(grant.get("kind")) ? "" :
                        (grantPath.isBlank() ? entry.relativePath() : stripGrantBase(grantPath, entry.relativePath()));
                item.put("path", grantRelativePath);
                item.put("grantId", grant.get("_id"));
                item.put("permission", grant.get("permission"));
                item.put("ownerNodeId", membership.status().get("nodeId"));
                result.add(item);
            }
            if (result.size() >= bounded) break;
        }
        return List.copyOf(result);
    }

    private Map<String, String> requireGrant(String memberId, String grantId) throws Exception {
        requireActiveRequester(memberId);
        Map<String, String> grant = store.getRecord("referenceGrant", grantId);
        if (grant == null || !memberId.equals(grant.get("memberId"))) throw new SecurityException("Referenced file is not shared with this device.");
        return grant;
    }
    private void requireActiveRequester(String memberId) {
        if (!membership.isActiveMember(memberId)) throw new SecurityException("This device is not an active member of the PersonalCloud network.");
    }

    private static boolean allowsPath(Map<String, String> grant, String relativePath, StorageEntry.Kind kind) {
        if ("FILE".equals(grant.get("kind"))) return relativePath.equals(grant.get("path"));
        String base = grant.getOrDefault("path", "");
        if (base.isBlank()) return true;
        return relativePath.equals(base) || relativePath.startsWith(base + "/");
    }

    private static String resolveGrantPath(Map<String, String> grant, String relativePath) {
        if ("FILE".equals(grant.get("kind"))) {
            if (relativePath != null && !relativePath.isBlank()) throw new IllegalArgumentException("A single-file grant does not accept a child path.");
            return grant.get("path");
        }
        return combine(grant.getOrDefault("path", ""), relativePath);
    }

    private static String stripGrantBase(String base, String path) {
        if (base == null || base.isBlank()) return path;
        if (path.equals(base)) return "";
        String prefix = base + "/";
        if (!path.startsWith(prefix)) throw new SecurityException("Referenced path escaped its granted folder.");
        return path.substring(prefix.length());
    }

    private static String combine(String base, String child) {
        String normalizedChild = normalizeRelative(child == null ? "" : child);
        if (normalizedChild.isBlank()) return base == null ? "" : base;
        String normalizedBase = base == null ? "" : base;
        return normalizedBase.isBlank() ? normalizedChild : normalizedBase + "/" + normalizedChild;
    }

    private static String normalizeRelative(String path) {
        if (path == null || path.isBlank()) return "";
        String portable = path.replace('\\', '/');
        if (portable.startsWith("/") || portable.matches("^[A-Za-z]:.*") || portable.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Only relative paths are accepted.");
        }
        for (String segment : portable.split("/", -1)) {
            if (segment.isBlank() || segment.equals(".") || segment.equals("..")) throw new IllegalArgumentException("Path contains an unsafe segment.");
        }
        return portable;
    }

    private static String normalizePermission(String permission) {
        String value = permission == null ? "" : permission.trim().toUpperCase(java.util.Locale.ROOT).replace(' ', '_');
        return switch (value) {
            case "DOWNLOAD" -> "DOWNLOAD";
            case "DOWNLOAD_DELETE", "DOWNLOAD+DELETE", "DOWNLOAD_AND_DELETE" -> "DOWNLOAD+DELETE";
            default -> throw new IllegalArgumentException("Permission must be DOWNLOAD or DOWNLOAD+DELETE.");
        };
    }

    private static Map<String, Object> toPublic(String id, Map<String, String> fields) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("grantId", id);
        result.put("memberId", fields.getOrDefault("memberId", ""));
        result.put("referenceId", fields.getOrDefault("referenceId", ""));
        result.put("path", fields.getOrDefault("path", ""));
        result.put("kind", fields.getOrDefault("kind", ""));
        result.put("permission", fields.getOrDefault("permission", ""));
        result.put("createdAt", fields.getOrDefault("createdAt", ""));
        return result;
    }
}
