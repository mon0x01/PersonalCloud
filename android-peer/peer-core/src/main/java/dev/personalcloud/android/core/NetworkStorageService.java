package dev.personalcloud.android.core;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileStore;
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
import java.util.Map;
import java.util.UUID;

/**
 * Android node storage exposed to authenticated PersonalCloud network members.
 * Existing phone files are referenced in place; managed files have a separate,
 * app-owned destination root. All persistent metadata uses the encrypted state domain.
 */
public final class NetworkStorageService {
    public static final long MAX_MANAGED_FILE_BYTES = 20L * 1024 * 1024 * 1024;
    public static final int MAX_RANGE_BYTES = 8 * 1024 * 1024;
    private static final long MAX_RECOVERY_SNAPSHOT_BYTES = 10L * 1024 * 1024 * 1024;
    private static final int MAX_SNAPSHOTS_PER_PATH = 20;
    private static final int MAX_TOTAL_SNAPSHOTS = 200;
    private static final long MAX_TOTAL_SNAPSHOT_BYTES = 10L * 1024 * 1024 * 1024;
    private static final String DOMAIN = "network-storage";
    private static final String STORAGE_ID = "android-node-storage";
    private static final String STORAGE_NAME = "Android storage";

    private final String nodeId;
    private final String managedStorageId;
    private final ManagedStorageBackend managedBackend;
    private final Path referenceRoot;
    private final Path realReferenceRoot;
    private final Path managedRoot;
    private final Path versionsRoot;
    private final StateStore store;
    private final Map<String, Object> state;

    public NetworkStorageService(String nodeId, Path nodeStorageRoot, StateStore store) throws Exception {
        this(nodeId, nodeStorageRoot, null, "app-private", store);
    }

    /**
     * Creates the network storage service with an explicitly selected managed-file volume.
     * Reference files and recovery snapshots remain in the existing app-private locations.
     */
    public NetworkStorageService(String nodeId, Path nodeStorageRoot, Path selectedManagedRoot,
                                 String selectedStorageId, StateStore store) throws Exception {
        this(nodeId, nodeStorageRoot, selectedManagedRoot, selectedStorageId, store, null);
    }

    public NetworkStorageService(String nodeId, Path nodeStorageRoot, Path selectedManagedRoot,
                                 String selectedStorageId, StateStore store,
                                 ManagedStorageBackend managedBackend) throws Exception {
        if (nodeId == null || nodeId.isBlank()) throw new IllegalArgumentException("Android node ID is required.");
        if (selectedStorageId == null || !selectedStorageId.matches("[A-Za-z0-9:_-]{1,128}")) {
            throw new IllegalArgumentException("A stable managed-storage volume identity is required.");
        }
        this.nodeId = nodeId;
        this.managedBackend = managedBackend;
        if (managedBackend != null && !selectedStorageId.equals(managedBackend.storageId())) {
            throw new IllegalArgumentException("Managed backend identity does not match the selected storage identity.");
        }
        this.referenceRoot = nodeStorageRoot.toAbsolutePath().normalize();
        Files.createDirectories(referenceRoot);
        this.realReferenceRoot = referenceRoot.toRealPath();
        Path base = referenceRoot.getParent();
        if (base == null) throw new IllegalArgumentException("Android storage root has no parent directory.");
        this.managedRoot = (selectedManagedRoot == null
                ? base.resolve("distributed-storage")
                : selectedManagedRoot).toAbsolutePath().normalize();
        if (this.managedRoot.equals(referenceRoot)
                || this.managedRoot.startsWith(referenceRoot)
                || referenceRoot.startsWith(this.managedRoot)) {
            throw new IllegalArgumentException("Managed placement storage must be separate from the reference root.");
        }
        this.versionsRoot = base.resolve("versions").toAbsolutePath().normalize();
        this.managedStorageId = selectedStorageId;
        this.store = store;
        this.state = store.loadDomain(DOMAIN);
        ensureMap("referenceGrants");
        ensureMap("managedFiles");
        ensureMap("snapshots");

        String persistedStorageId = state.get("managedStorageId") == null
                ? "app-private" : String.valueOf(state.get("managedStorageId"));
        if (!persistedStorageId.equals(selectedStorageId)
                && !object(state.get("managedFiles")).isEmpty()) {
            throw new IllegalStateException(
                    "Managed files are registered on storage volume '" + persistedStorageId
                            + "'. Refusing to switch to '" + selectedStorageId
                            + "' because that would hide existing files. Delete or migrate those files first.");
        }
        if (managedBackend == null) {
            if (Files.isSymbolicLink(this.managedRoot)) {
                throw new SecurityException("Managed placement root cannot be a symbolic link.");
            }
            Files.createDirectories(this.managedRoot);
            if (!Files.isDirectory(this.managedRoot, LinkOption.NOFOLLOW_LINKS)
                    || !Files.isWritable(this.managedRoot)) {
                throw new IllegalStateException("Selected managed-storage volume is not writable.");
            }
        }
        state.put("managedStorageId", selectedStorageId);
        persist();
        if (managedBackend != null) {
            java.util.Set<String> activeKeys = new java.util.HashSet<>();
            for (Object value : object(state.get("managedFiles")).values()) {
                Map<String,Object> record = object(value);
                String key = string(record.get("storageKey"));
                if (!key.isBlank()) activeKeys.add(key);
            }
            managedBackend.reconcile(activeKeys);
        }
    }

    public synchronized Map<String, Object> grantReference(String memberId, String relativePath, String permission) throws Exception {
        validateMember(memberId);
        String relative = normalizeReference(relativePath == null ? "" : relativePath);
        Path target = resolveReference(relative, true);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Only regular files and directories can be referenced.");
        }
        String kind = Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS) ? "FOLDER" : "FILE";
        String access = normalizePermission(permission);
        for (Map.Entry<String, Object> entry : new ArrayList<>(object(state.get("referenceGrants")).entrySet())) {
            Map<String, Object> old = object(entry.getValue());
            if (memberId.equals(string(old.get("memberId"))) && relative.equals(string(old.get("path")))) {
                object(state.get("referenceGrants")).remove(entry.getKey());
            }
        }
        String id = UUID.randomUUID().toString();
        Map<String, Object> grant = new LinkedHashMap<>();
        grant.put("memberId", memberId);
        grant.put("path", relative);
        grant.put("kind", kind);
        grant.put("permission", access);
        grant.put("createdAt", Instant.now().toString());
        object(state.get("referenceGrants")).put(id, grant);
        persist();
        return publicGrant(id, grant, target);
    }

    public synchronized void revokeReference(String grantId) throws Exception {
        if (object(state.get("referenceGrants")).remove(grantId) == null) {
            throw new IllegalArgumentException("Android network reference grant was not found.");
        }
        persist();
    }

    /** True only when this grant belongs to the authenticated member. */
    public synchronized boolean hasReferenceGrant(String memberId, String grantId) {
        Map<String, Object> grant = object(object(state.get("referenceGrants")).get(grantId));
        return !grant.isEmpty() && memberId != null && memberId.equals(string(grant.get("memberId")));
    }

    public synchronized List<Map<String, Object>> listReferencesForMember(String memberId) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, Object> entry : object(state.get("referenceGrants")).entrySet()) {
            Map<String, Object> grant = object(entry.getValue());
            if (!memberId.equals(string(grant.get("memberId")))) continue;
            try {
                Path path = resolveReference(string(grant.get("path")), true);
                result.add(publicGrant(entry.getKey(), grant, path));
            } catch (IllegalArgumentException missing) {
                result.add(missingPublicGrant(entry.getKey(), grant));
            }
        }
        result.sort(Comparator.comparing(row -> string(row.get("createdAt"))));
        return List.copyOf(result);
    }

    public synchronized List<Map<String, Object>> browseReference(String memberId, String grantId,
                                                                   String relativeDirectory) throws Exception {
        Map<String, Object> grant = requireReferenceGrant(memberId, grantId);
        if (!"FOLDER".equals(string(grant.get("kind")))) throw new IllegalArgumentException("This grant is for a single file, not a directory.");
        String path = combine(string(grant.get("path")), relativeDirectory);
        Path directory = resolveReference(path, true);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("The requested path is not a directory.");
        List<Map<String, Object>> result = new ArrayList<>();
        try (var entries = Files.list(directory)) {
            for (Path child : entries.toList()) {
                if (Files.isSymbolicLink(child)) continue;
                boolean isDirectory = Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS);
                if (!isDirectory && !Files.isRegularFile(child, LinkOption.NOFOLLOW_LINKS)) continue;
                String childName = child.getFileName().toString();
                String baseRelative = normalizeReference(relativeDirectory == null ? "" : relativeDirectory);
                String relative = baseRelative.isEmpty() ? childName : baseRelative + "/" + childName;
                result.add(referenceEntry(child, relative, isDirectory));
            }
        }
        result.sort(Comparator.comparing(row -> string(row.get("name")).toLowerCase(java.util.Locale.ROOT)));
        if (result.size() > 10_000) throw new IllegalStateException("Android reference directory contains too many entries.");
        return List.copyOf(result);
    }

    public synchronized Map<String, Object> statReference(String memberId, String grantId,
                                                            String relativePath) throws Exception {
        Map<String, Object> grant = requireReferenceGrant(memberId, grantId);
        String path = resolveGrantPath(grant, relativePath);
        Path target = resolveReference(path, true);
        boolean directory = Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS);
        if (!directory && !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Referenced item is not a regular file or directory.");
        String grantRelativePath = normalizeReference(relativePath == null ? "" : relativePath);
        Map<String, Object> result = referenceEntry(target, grantRelativePath, directory);
        if (!directory) result.put("sha256", sha256(target));
        return result;
    }

    public synchronized Path openReference(String memberId, String grantId, String relativePath) throws Exception {
        Map<String, Object> grant = requireReferenceGrant(memberId, grantId);
        String path = resolveGrantPath(grant, relativePath);
        Path target = resolveReference(path, true);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(target)) {
            throw new IllegalArgumentException("The requested referenced item is not a readable regular file.");
        }
        return target;
    }

    public synchronized Map<String, Object> deleteReference(String memberId, String grantId,
                                                              String relativePath) throws Exception {
        Map<String, Object> grant = requireReferenceGrant(memberId, grantId);
        if (!"DOWNLOAD+DELETE".equals(string(grant.get("permission")))) {
            throw new SecurityException("This reference was shared as DOWNLOAD only; deletion is not authorized.");
        }
        String path = resolveGrantPath(grant, relativePath);
        Path target = resolveReference(path, true);
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Only individual files can be deleted through a reference grant.");
        BasicFileAttributes before = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        long size = before.size();
        if (size > MAX_RECOVERY_SNAPSHOT_BYTES) throw new IllegalArgumentException("This Android file exceeds the recovery snapshot limit; deletion is blocked.");
        Files.createDirectories(versionsRoot);
        FileStore fileStore = Files.getFileStore(versionsRoot);
        if (size > fileStore.getUsableSpace()) throw new IllegalStateException("Android storage does not have enough free space for a recovery snapshot; deletion was cancelled.");
        String snapshotId = UUID.randomUUID().toString();
        Path snapshot = versionsRoot.resolve(snapshotId + ".blob");
        Path temporary = versionsRoot.resolve(snapshotId + ".blob.tmp");
        String hash;
        try {
            Files.copy(target, temporary);
            hash = sha256(temporary);
            BasicFileAttributes afterCopy = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!sameFileVersion(before, afterCopy) || !hash.equals(sha256(target))) {
                throw new IllegalStateException("Referenced file changed while its recovery snapshot was created; deletion was cancelled.");
            }
            Files.move(temporary, snapshot);
        } catch (Exception failure) {
            Files.deleteIfExists(temporary);
            Files.deleteIfExists(snapshot);
            throw failure;
        }
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("path", path); record.put("snapshotPath", snapshot.getFileName().toString());
        record.put("size", size); record.put("sha256", hash); record.put("createdAt", Instant.now().toString());
        object(state.get("snapshots")).put(snapshotId, record);
        try { persist(); }
        catch (Exception failure) { Files.deleteIfExists(snapshot); object(state.get("snapshots")).remove(snapshotId); throw failure; }
        BasicFileAttributes beforeDelete = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!sameFileVersion(before, beforeDelete) || !hash.equals(sha256(target))) {
            throw new IllegalStateException("Referenced file changed after its recovery snapshot was stored; deletion was cancelled and the snapshot was retained.");
        }
        Files.delete(target);
        if ("FILE".equals(string(grant.get("kind")))) object(state.get("referenceGrants")).remove(grantId);
        persist();
        pruneSnapshots();
        return Map.of("deleted", true, "path", path, "snapshotId", snapshotId, "size", size, "sha256", hash);
    }

    /** Recovery points remain owner-local; network members can never enumerate deleted paths. */
    public synchronized List<Map<String, Object>> listRecoverySnapshots(String localNodeId) throws Exception {
        requireLocalNode(localNodeId);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, Object> entry : object(state.get("snapshots")).entrySet()) {
            Map<String, Object> record = object(entry.getValue());
            long size = record.get("size") instanceof Number number ? number.longValue() : -1L;
            String hash = string(record.get("sha256"));
            Path blob = snapshotBlob(entry.getKey());
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("snapshotId", entry.getKey());
            row.put("path", string(record.get("path")));
            row.put("size", size);
            row.put("sha256", hash);
            row.put("createdAt", string(record.get("createdAt")));
            row.put("available", size >= 0 && hash.matches("[a-f0-9]{64}")
                    && Files.isRegularFile(blob, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isSymbolicLink(blob) && Files.size(blob) == size);
            result.add(row);
        }
        result.sort(Comparator.comparing(row -> string(row.get("createdAt"))));
        return List.copyOf(result);
    }

    /** Restores a verified snapshot to its original path. Existing files are never overwritten. */
    public synchronized Map<String, Object> restoreRecoverySnapshot(String localNodeId,
                                                                    String snapshotId) throws Exception {
        requireLocalNode(localNodeId);
        if (snapshotId == null || !snapshotId.matches("[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("Invalid Android recovery snapshot ID.");
        }
        Map<String, Object> record = object(object(state.get("snapshots")).get(snapshotId));
        if (record.isEmpty()) throw new IllegalArgumentException("Android recovery snapshot was not found.");
        String relativePath = normalizeReference(string(record.get("path")));
        long expectedSize = record.get("size") instanceof Number number ? number.longValue() : -1L;
        String expectedHash = string(record.get("sha256"));
        if (expectedSize < 0 || expectedSize > MAX_RECOVERY_SNAPSHOT_BYTES
                || !expectedHash.matches("[a-f0-9]{64}")) {
            throw new SecurityException("Android recovery snapshot metadata is invalid.");
        }
        Path blob = snapshotBlob(snapshotId);
        if (!Files.isRegularFile(blob, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(blob)
                || Files.size(blob) != expectedSize || !expectedHash.equals(sha256(blob))) {
            throw new SecurityException("Android recovery snapshot failed size or SHA-256 verification.");
        }
        Path target = resolveReference(relativePath, false);
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("The original reference directory no longer exists; restore was cancelled.");
        }
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The original path already exists; PersonalCloud never overwrites files during recovery.");
        }
        FileStore fileStore = Files.getFileStore(parent);
        if (expectedSize > fileStore.getUsableSpace()) throw new IllegalStateException("Android storage does not have enough free space to restore this snapshot.");
        Path temporary = Files.createTempFile(parent, ".personalcloud-restore-", ".part");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            try (InputStream input = Files.newInputStream(blob, LinkOption.NOFOLLOW_LINKS);
                 OutputStream output = Files.newOutputStream(temporary, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > expectedSize) throw new SecurityException("Recovery snapshot exceeded its recorded size.");
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
            }
            String actualHash = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedSize || !expectedHash.equals(actualHash)) {
                throw new SecurityException("Restored bytes failed size or SHA-256 verification.");
            }
            // Atomic create-if-absent publication; fail closed if hard links are unsupported.
            Files.createLink(target, temporary);
            Files.delete(temporary);
        } finally {
            Files.deleteIfExists(temporary);
        }
        return Map.of("snapshotId", snapshotId, "path", relativePath, "size", expectedSize,
                "sha256", expectedHash, "restored", true);
    }

    public synchronized List<Map<String, Object>> searchReferences(String memberId, String query, int limit) throws Exception {
        String needle = query == null ? "" : query.trim().toLowerCase(java.util.Locale.ROOT);
        int bounded = Math.max(1, Math.min(limit, 100));
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map.Entry<String, Object> entry : object(state.get("referenceGrants")).entrySet()) {
            Map<String, Object> grant = object(entry.getValue());
            if (!memberId.equals(string(grant.get("memberId")))) continue;
            Path base = resolveReference(string(grant.get("path")), true);
            if ("FILE".equals(string(grant.get("kind")))) {
                addSearchResult(results, entry.getKey(), grant, base, "", needle, bounded);
            } else {
                try (var paths = Files.walk(base)) {
                    var iterator = paths.filter(path -> !path.equals(base) && !Files.isSymbolicLink(path)
                            && (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)))
                            .iterator();
                    while (iterator.hasNext() && results.size() < bounded) {
                        Path item = iterator.next();
                        String relative = base.relativize(item.toAbsolutePath().normalize()).toString().replace('\\', '/');
                        addSearchResult(results, entry.getKey(), grant, item, relative, needle, bounded);
                    }
                }
            }
            if (results.size() >= bounded) break;
        }
        results.sort(Comparator.comparing(row -> string(row.get("name")).toLowerCase(java.util.Locale.ROOT)));
        return List.copyOf(results.subList(0, Math.min(results.size(), bounded)));
    }

    private void addSearchResult(List<Map<String, Object>> results, String grantId, Map<String, Object> grant,
                                 Path item, String relative, String needle, int limit) throws Exception {
        if (results.size() >= limit) return;
        String name = item.getFileName() == null ? STORAGE_NAME : item.getFileName().toString();
        if (!name.toLowerCase(java.util.Locale.ROOT).contains(needle)
                && !relative.toLowerCase(java.util.Locale.ROOT).contains(needle)) return;
        boolean directory = Files.isDirectory(item, LinkOption.NOFOLLOW_LINKS);
        Map<String, Object> row = referenceEntry(item, relative, directory);
        row.put("grantId", grantId); row.put("permission", grant.get("permission")); row.put("ownerNodeId", nodeId);
        results.add(row);
    }

    public synchronized Map<String, Object> receiveManagedFile(String uploaderNodeId, String relativePath,
                                                                 InputStream input, long requestLength,
                                                                 long declaredSize, String expectedSha256) throws Exception {
        return receiveManagedFileInternal(null, uploaderNodeId, relativePath, input, requestLength, declaredSize, expectedSha256);
    }

    /** Idempotent commit boundary for a durable resumable-transfer session. */
    public synchronized Map<String,Object> receiveManagedTransfer(String transferId, String uploaderNodeId,
                                                                    String relativePath, InputStream input,
                                                                    long declaredSize, String expectedSha256) throws Exception {
        if (transferId == null || !transferId.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("A valid transfer ID is required.");
        return receiveManagedFileInternal(transferId, uploaderNodeId, relativePath, input,
                declaredSize, declaredSize, expectedSha256);
    }

    private Map<String,Object> receiveManagedFileInternal(String transferId, String uploaderNodeId, String relativePath,
                                                           InputStream input, long requestLength,
                                                           long declaredSize, String expectedSha256) throws Exception {
        if (uploaderNodeId == null || uploaderNodeId.isBlank()) throw new SecurityException("Uploader identity is required.");
        String relative = normalizeManagedPath(relativePath);
        if (declaredSize < 0 || declaredSize > MAX_MANAGED_FILE_BYTES || requestLength != declaredSize) {
            throw new IllegalArgumentException("Managed upload length is invalid or exceeds the Android node limit.");
        }
        String expected = expectedSha256 == null ? "" : expectedSha256.toLowerCase(java.util.Locale.ROOT);
        if (!expected.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Managed upload must include a valid SHA-256 digest.");
        if (transferId != null) {
            for (Map.Entry<String,Object> entry : object(state.get("managedFiles")).entrySet()) {
                Map<String,Object> existing = object(entry.getValue());
                if (!transferId.equals(string(existing.get("transferId")))) continue;
                if (!uploaderNodeId.equals(string(existing.get("uploaderNodeId")))
                        || !relative.equals(string(existing.get("relativePath")))
                        || !(existing.get("size") instanceof Number existingSize) || declaredSize != existingSize.longValue()
                        || !expected.equals(string(existing.get("sha256")))) {
                    throw new SecurityException("Transfer ID was already committed with different metadata.");
                }
                if (managedBackend != null) {
                    if (!managedStorageId.equals(string(existing.get("storageId")))) throw new IllegalStateException("Committed transfer is pinned to another storage volume.");
                    return managedPublicBackend(entry.getKey(), existing, managedBackend.stat(string(existing.get("storageKey"))));
                }
                return managedPublic(entry.getKey(), existing, resolveManaged(relative, true));
            }
        }
        if (managedBackend != null) {
            return receiveManagedFileWithBackend(transferId, uploaderNodeId, relative, input, declaredSize, expected);
        }
        Path target = resolveManaged(relative, false);
        Path parent = target.getParent();
        createSafeDirectories(parent);
        FileStore fileStore = Files.getFileStore(parent);
        if (declaredSize > fileStore.getUsableSpace()) throw new IllegalStateException("Android managed storage does not have enough free space.");
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Managed destination already exists; PersonalCloud never overwrites files.");
        Path temporary = Files.createTempFile(parent, ".personalcloud-incoming-", ".part");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try {
            try (OutputStream output = Files.newOutputStream(temporary, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[128 * 1024];
                while (copied < declaredSize) {
                    int read = input.read(buffer, 0, (int) Math.min(buffer.length, declaredSize - copied));
                    if (read < 0) throw new java.io.EOFException("Managed upload ended before its declared length.");
                    if (read == 0) continue;
                    copied = Math.addExact(copied, read);
                    digest.update(buffer, 0, read); output.write(buffer, 0, read);
                }
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            if (!expected.equals(actual)) throw new SecurityException("Incoming managed file failed SHA-256 verification.");
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Managed destination appeared during upload; no file was overwritten.");
            // Same-filesystem move without REPLACE_EXISTING: supports removable
            // filesystems without hard links and does not overwrite an existing target.
            Files.move(temporary, target);
            String id = UUID.randomUUID().toString();
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("uploaderNodeId", uploaderNodeId); record.put("relativePath", relative);
            if (transferId != null) record.put("transferId", transferId);
            record.put("storageId", managedStorageId);
            record.put("size", copied); record.put("sha256", actual); record.put("createdAt", Instant.now().toString());
            object(state.get("managedFiles")).put(id, record);
            try { persist(); }
            catch (Exception failure) { object(state.get("managedFiles")).remove(id); Files.deleteIfExists(target); throw failure; }
            return managedPublic(id, record, target);
        } finally { Files.deleteIfExists(temporary); }
    }

    private Map<String,Object> receiveManagedFileWithBackend(String transferId, String uploaderNodeId, String relative,
                                                               InputStream input, long declaredSize,
                                                               String expectedSha256) throws Exception {
        for (Object value : object(state.get("managedFiles")).values()) {
            Map<String,Object> existing = object(value);
            if (relative.equals(string(existing.get("relativePath")))) {
                throw new IllegalArgumentException("Managed destination already exists; PersonalCloud never overwrites files.");
            }
        }
        String id = UUID.randomUUID().toString();
        ManagedStorageBackend.UploadSession upload = managedBackend.beginUpload(id, relative, declaredSize);
        String storageKey = null;
        boolean persisted = false;
        try (upload) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            OutputStream output = upload.outputStream();
            byte[] buffer = new byte[128 * 1024];
            while (copied < declaredSize) {
                int read = input.read(buffer, 0, (int)Math.min(buffer.length, declaredSize - copied));
                if (read < 0) throw new java.io.EOFException("Managed upload ended before its declared length.");
                if (read == 0) continue;
                copied = Math.addExact(copied, read);
                digest.update(buffer, 0, read);
                output.write(buffer, 0, read);
            }
            output.flush();
            String actual = HexFormat.of().formatHex(digest.digest());
            if (copied != declaredSize || !expectedSha256.equals(actual)) {
                throw new SecurityException("Incoming managed file failed SHA-256 or length verification.");
            }
            storageKey = upload.commit();
            Map<String,Object> physical = managedBackend.stat(storageKey);
            Object physicalSize = physical.get("size");
            if (!(physicalSize instanceof Number) || ((Number) physicalSize).longValue() != declaredSize) {
                throw new SecurityException("SAF provider stored a different file size than the verified upload.");
            }
            String readBack = sha256ManagedContent(managedBackend.open(storageKey), declaredSize);
            if (!expectedSha256.equals(readBack)) {
                throw new SecurityException("SAF provider read-back failed SHA-256 verification.");
            }
            Map<String,Object> record = new LinkedHashMap<>();
            record.put("uploaderNodeId", uploaderNodeId);
            record.put("relativePath", relative);
            if (transferId != null) record.put("transferId", transferId);
            record.put("size", copied);
            record.put("sha256", actual);
            record.put("createdAt", Instant.now().toString());
            record.put("storageId", managedStorageId);
            record.put("storageKind", "SAF");
            record.put("storageKey", storageKey);
            object(state.get("managedFiles")).put(id, record);
            try {
                persist();
                persisted = true;
            } catch (Exception failure) {
                object(state.get("managedFiles")).remove(id);
                throw failure;
            }
            return managedPublicBackend(id, record, physical);
        } catch (Exception failure) {
            if (!persisted && storageKey != null) {
                try { managedBackend.delete(storageKey); }
                catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            }
            throw failure;
        }
    }

    private static String sha256ManagedContent(ExternalReferenceStore.NetworkReferenceContent content,
                                               long expectedSize) throws Exception {
        if (content.size() != expectedSize) throw new SecurityException("Managed SAF content size changed after publication.");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long copied = 0;
        try (InputStream input = content.openRange(0, expectedSize)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                copied = Math.addExact(copied, read);
                if (copied > expectedSize) throw new SecurityException("SAF provider returned too many bytes.");
                digest.update(buffer, 0, read);
            }
        }
        if (copied != expectedSize) throw new SecurityException("SAF provider returned a truncated managed file.");
        return HexFormat.of().formatHex(digest.digest());
    }

    private Map<String,Object> managedPublicBackend(String id, Map<String,Object> record,
                                                     Map<String,Object> physical) {
        Object recordedSize = record.get("size");
        Object physicalSize = physical.get("size");
        if (!(recordedSize instanceof Number) || !(physicalSize instanceof Number)
                || ((Number) recordedSize).longValue() != ((Number) physicalSize).longValue()) {
            throw new IllegalStateException("Managed SAF document size changed or is no longer available; refusing to advertise stale metadata.");
        }
        String path = string(record.get("relativePath"));
        int slash = path.lastIndexOf('/');
        String name = slash >= 0 ? path.substring(slash + 1) : path;
        Map<String,Object> row = new LinkedHashMap<>();
        row.put("fileId", id);
        row.put("ownerNodeId", nodeId);
        row.put("uploaderNodeId", record.get("uploaderNodeId"));
        row.put("path", path);
        row.put("name", name);
        row.put("size", record.get("size"));
        row.put("sha256", record.get("sha256"));
        row.put("createdAt", record.get("createdAt"));
        row.put("modified", physical.getOrDefault("modified", ""));
        row.put("kind", "FILE");
        row.put("availability", "AVAILABLE");
        row.put("storageKind", "SAF");
        row.put("storageId", record.get("storageId"));
        return row;
    }

    public synchronized List<Map<String, Object>> listManagedFilesForMember(String memberId) throws Exception {
        requireAuthenticatedMember(memberId);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, Object> entry : object(state.get("managedFiles")).entrySet()) {
            Map<String, Object> record = object(entry.getValue());
            if (managedBackend != null) {
                String key = string(record.get("storageKey"));
                if (key.isBlank() || !managedStorageId.equals(string(record.get("storageId"))))
                    throw new IllegalStateException("Managed file is pinned to a different or missing storage identity.");
                result.add(managedPublicBackend(entry.getKey(), record, managedBackend.stat(key)));
            } else {
                Path file = resolveManaged(string(record.get("relativePath")), true);
                result.add(managedPublic(entry.getKey(), record, file));
            }
        }
        result.sort(Comparator.comparing(row -> string(row.get("createdAt"))));
        return List.copyOf(result);
    }

    public synchronized Map<String, Object> statManagedFile(String memberId, String fileId) throws Exception {
        Map<String, Object> record = requireManagedRecord(memberId, fileId);
        if (managedBackend != null) {
            if (!managedStorageId.equals(string(record.get("storageId"))))
                throw new IllegalStateException("Managed file is pinned to a different storage identity.");
            return managedPublicBackend(fileId, record, managedBackend.stat(string(record.get("storageKey"))));
        }
        Path file = resolveManaged(string(record.get("relativePath")), true);
        return managedPublic(fileId, record, file);
    }

    public synchronized Path openManagedFile(String memberId, String fileId) throws Exception {
        Map<String, Object> record = requireManagedRecord(memberId, fileId);
        Path file = resolveManaged(string(record.get("relativePath")), true);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(file)) throw new IllegalStateException("Managed file is unavailable.");
        return file;
    }

    public synchronized ExternalReferenceStore.NetworkReferenceContent openManagedContent(
            String memberId, String fileId) throws Exception {
        Map<String,Object> record = requireManagedRecord(memberId, fileId);
        if (managedBackend != null) {
            if (!managedStorageId.equals(string(record.get("storageId"))))
                throw new IllegalStateException("Managed file is pinned to a different storage identity.");
            return managedBackend.open(string(record.get("storageKey")));
        }
        Path file = openManagedFile(memberId, fileId);
        long expectedSize = Files.size(file);
        return new ExternalReferenceStore.NetworkReferenceContent() {
            @Override public long size() { return expectedSize; }
            @Override public InputStream openRange(long offset, long length) throws Exception {
                if (offset < 0 || length < 0 || offset > expectedSize || length > expectedSize - offset)
                    throw new IllegalArgumentException("Managed file range is outside the file bounds.");
                InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS);
                long remaining = offset;
                byte[] discard = new byte[65536];
                try {
                    while (remaining > 0) {
                        long skipped = input.skip(remaining);
                        if (skipped > 0) { remaining -= skipped; continue; }
                        int read = input.read(discard, 0, (int)Math.min(discard.length, remaining));
                        if (read < 0) throw new java.io.EOFException("Managed file ended before requested offset.");
                        remaining -= read;
                    }
                    return new java.io.FilterInputStream(input) {
                        private long left = length;
                        @Override public int read() throws java.io.IOException {
                            if (left <= 0) return -1;
                            int value = super.read();
                            if (value < 0) throw new java.io.EOFException("Managed file truncated during range read.");
                            left--;
                            return value;
                        }
                        @Override public int read(byte[] bytes, int off, int len) throws java.io.IOException {
                            if (left <= 0) return -1;
                            int count = super.read(bytes, off, (int)Math.min((long)len, left));
                            if (count < 0) throw new java.io.EOFException("Managed file truncated during range read.");
                            left -= count;
                            return count;
                        }
                    };
                } catch (Exception failure) {
                    input.close();
                    throw failure;
                }
            }
        };
    }

    public synchronized Map<String, Object> deleteManagedFile(String memberId, String fileId) throws Exception {
        Map<String, Object> record = requireManagedRecord(memberId, fileId);
        if (managedBackend != null) {
            String key = string(record.get("storageKey"));
            if (!managedStorageId.equals(string(record.get("storageId"))) || key.isBlank())
                throw new IllegalStateException("Managed file is pinned to a different or missing storage identity.");
            object(state.get("managedFiles")).remove(fileId);
            try { persist(); }
            catch (Exception failure) { object(state.get("managedFiles")).put(fileId, record); throw failure; }
            try { managedBackend.delete(key); }
            catch (Exception failure) {
                object(state.get("managedFiles")).put(fileId, record);
                try { persist(); } catch (Exception rollback) { failure.addSuppressed(rollback); }
                throw failure;
            }
            return Map.of("ok", true, "fileId", fileId, "deleted", true);
        }
        Path file = resolveManaged(string(record.get("relativePath")), true);
        Files.delete(file);
        object(state.get("managedFiles")).remove(fileId);
        persist();
        return Map.of("ok", true, "fileId", fileId, "deleted", true);
    }

    public Path managedRoot() { return managedRoot; }

    private Map<String, Object> requireReferenceGrant(String memberId, String grantId) {
        Map<String, Object> grant = object(object(state.get("referenceGrants")).get(grantId));
        if (grant.isEmpty() || !memberId.equals(string(grant.get("memberId")))) {
            throw new SecurityException("Referenced file is not shared with this network member.");
        }
        return grant;
    }

    private Map<String, Object> requireManagedRecord(String memberId, String fileId) {
        requireAuthenticatedMember(memberId);
        Map<String, Object> record = object(object(state.get("managedFiles")).get(fileId));
        if (record.isEmpty()) throw new IllegalArgumentException("Managed file not found on this device.");
        return record;
    }

    private static void requireAuthenticatedMember(String memberId) {
        // PeerNode authenticates the signed active-member request before invoking this service.
        if (memberId == null || memberId.isBlank()) throw new SecurityException("An authenticated PersonalCloud network member is required.");
    }

    private Map<String, Object> publicGrant(String id, Map<String, Object> grant, Path path) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        boolean directory = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS);
        row.put("grantId", id); row.put("memberId", grant.get("memberId"));
        row.put("referenceId", STORAGE_ID); row.put("path", grant.get("path"));
        row.put("kind", directory ? "FOLDER" : "FILE"); row.put("permission", grant.get("permission"));
        row.put("createdAt", grant.get("createdAt")); row.put("ownerNodeId", nodeId);
        row.put("rootName", STORAGE_NAME); row.put("name", path.getFileName() == null ? STORAGE_NAME : path.getFileName().toString());
        row.put("size", directory ? 0L : Files.size(path));
        row.put("modified", Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toInstant().toString());
        return row;
    }

    private Map<String, Object> missingPublicGrant(String id, Map<String, Object> grant) {
        String path = string(grant.get("path"));
        String name = path.isEmpty() ? STORAGE_NAME : path.substring(path.lastIndexOf('/') + 1);
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("grantId", id); row.put("memberId", grant.get("memberId"));
        row.put("referenceId", STORAGE_ID); row.put("path", path); row.put("kind", grant.get("kind"));
        row.put("permission", grant.get("permission")); row.put("createdAt", grant.get("createdAt"));
        row.put("ownerNodeId", nodeId); row.put("rootName", STORAGE_NAME); row.put("name", name);
        row.put("size", 0L); row.put("modified", ""); row.put("availability", "MISSING");
        return row;
    }

    private Map<String, Object> referenceEntry(Path path, String relative, boolean directory) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("storageId", STORAGE_ID); row.put("storageName", STORAGE_NAME); row.put("storageKind", "REFERENCE");
        row.put("path", relative); row.put("name", path.getFileName() == null ? STORAGE_NAME : path.getFileName().toString());
        row.put("kind", directory ? "DIRECTORY" : "FILE"); row.put("size", directory ? 0L : Files.size(path));
        row.put("modified", Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toInstant().toString());
        return row;
    }

    private Map<String, Object> managedPublic(String id, Map<String, Object> record, Path file) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("fileId", id); row.put("ownerNodeId", nodeId); row.put("uploaderNodeId", record.get("uploaderNodeId"));
        row.put("path", record.get("relativePath")); row.put("name", file.getFileName().toString());
        row.put("size", record.get("size")); row.put("sha256", record.get("sha256"));
        row.put("createdAt", record.get("createdAt")); row.put("modified", Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS).toInstant().toString());
        row.put("kind", "FILE"); row.put("availability", "AVAILABLE");
        return row;
    }

    private Path resolveReference(String relative, boolean mustExist) throws Exception {
        String safe = normalizeReference(relative);
        Path target = safe.isEmpty() ? referenceRoot : referenceRoot.resolve(safe).normalize();
        if (!target.startsWith(referenceRoot)) throw new SecurityException("Referenced path escapes Android node storage.");
        rejectSymlinks(referenceRoot, target);
        if (mustExist && !Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Referenced item is unavailable.");
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) && !target.toRealPath().startsWith(realReferenceRoot)) throw new SecurityException("Referenced path escapes Android storage.");
        return target;
    }

    private Path resolveManaged(String relative, boolean mustExist) throws Exception {
        String safe = normalizeManagedPath(relative);
        Path target = managedRoot.resolve(safe).normalize();
        if (!target.startsWith(managedRoot) || target.equals(managedRoot)) throw new SecurityException("Managed path escapes Android distributed storage.");
        rejectSymlinks(managedRoot, target);
        if (mustExist && !Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Managed file is unavailable.");
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) && !target.toRealPath().startsWith(managedRoot.toRealPath())) throw new SecurityException("Managed path escapes Android distributed storage.");
        return target;
    }

    private static void rejectSymlinks(Path root, Path target) {
        Path current = root;
        if (Files.isSymbolicLink(root)) throw new SecurityException("Storage root cannot be a symbolic link.");
        for (Path part : root.relativize(target)) {
            current = current.resolve(part);
            if (Files.isSymbolicLink(current)) throw new SecurityException("Symbolic links are not allowed in PersonalCloud storage paths.");
        }
    }

    private void createSafeDirectories(Path directory) throws Exception {
        Path current = managedRoot;
        for (Path part : managedRoot.relativize(directory)) {
            current = current.resolve(part);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(current) || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) throw new SecurityException("Managed destination contains an unsafe directory component.");
            } else Files.createDirectory(current);
            if (!current.toRealPath().startsWith(managedRoot.toRealPath())) throw new SecurityException("Managed destination escapes Android storage.");
        }
    }

    private static String resolveGrantPath(Map<String, Object> grant, String relativePath) {
        if ("FILE".equals(string(grant.get("kind")))) {
            if (relativePath != null && !relativePath.isBlank()) throw new IllegalArgumentException("A single-file grant does not accept a child path.");
            return string(grant.get("path"));
        }
        return combine(string(grant.get("path")), relativePath);
    }

    private static String combine(String base, String child) {
        String relative = normalizeReference(child == null ? "" : child);
        if (relative.isEmpty()) return base;
        return base.isEmpty() ? relative : base + "/" + relative;
    }

    private static String normalizeReference(String value) {
        if (value == null || value.isBlank() || ".".equals(value)) return "";
        String path = value.replace('\\', '/');
        if (path.startsWith("/") || path.matches("^[A-Za-z]:.*") || path.indexOf('\0') >= 0 || path.length() > 2048) throw new IllegalArgumentException("Reference path must be relative.");
        for (String segment : path.split("/", -1)) if (segment.isBlank() || segment.equals(".") || segment.equals("..") || segment.length() > 255) throw new IllegalArgumentException("Reference path contains an unsafe segment.");
        return path;
    }

    private static String normalizeManagedPath(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("A managed destination path is required.");
        String path = value.replace('\\', '/');
        if (path.startsWith("/") || path.matches("^[A-Za-z]:.*") || path.indexOf('\0') >= 0 || path.length() > 1024) throw new IllegalArgumentException("Managed destination must be a relative path of at most 1024 characters.");
        for (String segment : path.split("/", -1)) if (segment.isBlank() || segment.equals(".") || segment.equals("..") || segment.length() > 255) throw new IllegalArgumentException("Managed destination contains an unsafe path segment.");
        return path;
    }

    private static String normalizePermission(String permission) {
        String value = permission == null ? "" : permission.trim().toUpperCase(java.util.Locale.ROOT).replace(' ', '_');
        return switch (value) {
            case "DOWNLOAD" -> "DOWNLOAD";
            case "DOWNLOAD_DELETE", "DOWNLOAD+DELETE", "DOWNLOAD_AND_DELETE" -> "DOWNLOAD+DELETE";
            default -> throw new IllegalArgumentException("Permission must be DOWNLOAD or DOWNLOAD+DELETE.");
        };
    }

    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[128 * 1024]; int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private Path snapshotBlob(String snapshotId) {
        if (snapshotId == null || !snapshotId.matches("[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("Invalid Android recovery snapshot ID.");
        }
        Path blob = versionsRoot.resolve(snapshotId + ".blob").normalize();
        if (!blob.startsWith(versionsRoot) || blob.equals(versionsRoot)) {
            throw new SecurityException("Recovery snapshot path escapes the owner storage directory.");
        }
        return blob;
    }

    private void pruneSnapshots() throws Exception {
        List<Map.Entry<String, Object>> entries = new ArrayList<>(object(state.get("snapshots")).entrySet());
        entries.sort((left, right) -> string(object(right.getValue()).get("createdAt"))
                .compareTo(string(object(left.getValue()).get("createdAt"))));
        Map<String, Integer> keptByPath = new LinkedHashMap<>();
        List<String> evicted = new ArrayList<>();
        int keptCount = 0;
        long keptBytes = 0;
        for (Map.Entry<String, Object> entry : entries) {
            Map<String, Object> record = object(entry.getValue());
            String path = string(record.get("path"));
            long size = record.get("size") instanceof Number number ? number.longValue() : -1L;
            int pathCount = keptByPath.getOrDefault(path, 0);
            boolean valid = size >= 0 && size <= MAX_TOTAL_SNAPSHOT_BYTES
                    && string(record.get("sha256")).matches("[a-f0-9]{64}")
                    && Files.isRegularFile(snapshotBlob(entry.getKey()), LinkOption.NOFOLLOW_LINKS)
                    && !Files.isSymbolicLink(snapshotBlob(entry.getKey()));
            if (!valid || pathCount >= MAX_SNAPSHOTS_PER_PATH || keptCount >= MAX_TOTAL_SNAPSHOTS
                    || keptBytes > MAX_TOTAL_SNAPSHOT_BYTES - Math.max(0, size)) {
                evicted.add(entry.getKey());
            } else {
                keptByPath.put(path, pathCount + 1);
                keptCount++;
                keptBytes += size;
            }
        }
        if (evicted.isEmpty()) return;
        Map<String, Object> snapshots = object(state.get("snapshots"));
        Map<String, Object> removed = new LinkedHashMap<>();
        for (String id : evicted) {
            Object record = snapshots.remove(id);
            if (record != null) removed.put(id, record);
        }
        try {
            persist();
        } catch (Exception failure) {
            snapshots.putAll(removed);
            throw failure;
        }
        for (String id : evicted) Files.deleteIfExists(snapshotBlob(id));
    }

    private static boolean sameFileVersion(BasicFileAttributes left, BasicFileAttributes right) {
        if (!left.isRegularFile() || !right.isRegularFile()) return false;
        if (left.size() != right.size() || !left.lastModifiedTime().equals(right.lastModifiedTime())) return false;
        Object leftKey = left.fileKey();
        Object rightKey = right.fileKey();
        return leftKey == null || rightKey == null || leftKey.equals(rightKey);
    }

    private void requireLocalNode(String suppliedNodeId) {
        if (!nodeId.equals(suppliedNodeId)) {
            throw new SecurityException("Recovery snapshots are available only to the storage-owning device.");
        }
    }

    private void validateMember(String memberId) {
        if (memberId == null || memberId.isBlank() || memberId.equals(nodeId)) throw new IllegalArgumentException("A different network member must be selected.");
    }
    private void ensureMap(String name) { if (!(state.get(name) instanceof Map<?, ?>)) state.put(name, new LinkedHashMap<String, Object>()); }
    private void persist() throws Exception { store.saveDomain(DOMAIN, state); }
    @SuppressWarnings("unchecked") private static Map<String, Object> object(Object value) { return value instanceof Map<?, ?> map ? (Map<String, Object>) map : new LinkedHashMap<>(); }
    private static String string(Object value) { return value instanceof String text ? text : ""; }
}
