package dev.personalcloud.android;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;

import dev.personalcloud.android.core.ExternalReferenceStore;
import dev.personalcloud.android.core.StateStore;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * In-place Android Storage Access Framework references. Source documents remain in the
 * user's chosen provider; PersonalCloud persists only the tree URI, document IDs and grants.
 */
public final class AndroidSafReferenceStore implements ExternalReferenceStore {
    private static final String DOMAIN = "saf-references";
    private static final String DIRECTORY_MIME = "vnd.android.document/directory";
    private static final long MAX_SNAPSHOT_BYTES = 10L * 1024 * 1024 * 1024;
    private static final long MAX_TOTAL_SNAPSHOT_BYTES = 10L * 1024 * 1024 * 1024;
    private static final int MAX_SNAPSHOTS_PER_PATH = 20;
    private static final int MAX_TOTAL_SNAPSHOTS = 200;
    private static final int MAX_TREE_DEPTH = 32;
    private static final int MAX_SEARCH_VISITS = 10000;

    private final Context appContext;
    private final ContentResolver resolver;
    private final StateStore stateStore;
    private final Path versionsRoot;
    private final Map<String,Object> state;

    public AndroidSafReferenceStore(Context context, StateStore stateStore, Path appFilesDirectory) throws Exception {
        this.appContext = context.getApplicationContext();
        this.resolver = this.appContext.getContentResolver();
        this.stateStore = stateStore;
        this.versionsRoot = appFilesDirectory.resolve("saf-reference-versions").toAbsolutePath().normalize();
        Files.createDirectories(versionsRoot);
        Map<String,Object> loaded = stateStore.loadDomain(DOMAIN);
        this.state = loaded == null ? new LinkedHashMap<>() : loaded;
        ensureMap("grants");
        ensureMap("snapshots");
        persist();
    }

    @Override public synchronized Map<String,Object> grantReference(String memberId, String selector, String permission) throws Exception {
        validateMember(memberId);
        String access = normalizePermission(permission);
        Uri selected = Uri.parse(selector == null ? "" : selector);
        boolean treeSelection = DocumentsContract.isTreeUri(selected);
        boolean documentSelection = DocumentsContract.isDocumentUri(contextForResolver(), selected);
        if (!treeSelection && !documentSelection) {
            throw new IllegalArgumentException("Select an Android file or folder through the system Storage Access Framework picker.");
        }
        if (!hasPersistedReadPermission(selected)) {
            throw new SecurityException("Android has not persisted read permission for this selection. Select it again and allow access.");
        }
        String rootId = treeSelection ? DocumentsContract.getTreeDocumentId(selected) : DocumentsContract.getDocumentId(selected);
        Uri rootDocumentUri = treeSelection
                ? DocumentsContract.buildDocumentUriUsingTree(selected, rootId) : selected;
        DocInfo root = query(rootDocumentUri);
        if (treeSelection && !root.directory()) throw new IllegalArgumentException("The selected Android tree root is not a folder.");
        if (!treeSelection && root.directory()) throw new IllegalArgumentException("Select folders with the system folder picker, not the single-file picker.");
        if ("DOWNLOAD+DELETE".equals(access)) {
            if (!treeSelection) throw new SecurityException("Single-file Android references are read-only in this release; use DOWNLOAD.");
            if (!hasPersistedWritePermission(selected)) {
                throw new SecurityException("Android did not grant persistent write access to this folder; use DOWNLOAD or reselect with write access.");
            }
        }
        String grantId = UUID.randomUUID().toString();
        Map<String,Object> row = new LinkedHashMap<>();
        row.put("memberId", memberId);
        row.put("permissionUri", selected.toString());
        if (treeSelection) row.put("treeUri", selected.toString());
        row.put("rootDocumentUri", rootDocumentUri.toString());
        row.put("rootDocumentId", rootId);
        row.put("rootKind", root.directory() ? "FOLDER" : "FILE");
        row.put("name", root.name); row.put("size", root.size); row.put("modified", root.modified);
        row.put("mimeType", root.mimeType); row.put("permission", access); row.put("createdAt", Instant.now().toString());
        object(state.get("grants")).put(grantId, row);
        try {
            persist();
        } catch (Exception failure) {
            object(state.get("grants")).remove(grantId);
            throw failure;
        }
        return publicGrant(grantId, row, true);
    }

    @Override public synchronized void revokeReference(String grantId) throws Exception {
        Object removedValue = object(state.get("grants")).remove(grantId);
        Map<String,Object> removed = removedValue instanceof Map<?,?> ? object(removedValue) : Map.of();
        if (removed.isEmpty()) throw new IllegalArgumentException("Android SAF reference grant was not found.");
        try {
            persist();
        } catch (Exception failure) {
            object(state.get("grants")).put(grantId, removed);
            throw failure;
        }
        // A deletion snapshot is useful only while its original SAF source can still be
        // addressed. Do not release a persisted URI grant while recovery depends on it.
        String permissionUri = text(removed.get("permissionUri"), text(removed.get("treeUri")));
        releaseUriPermissionIfUnused(permissionUri);
    }

    @Override public synchronized boolean hasGrant(String memberId, String grantId) {
        Map<String,Object> grant = object(object(state.get("grants")).get(grantId));
        return !grant.isEmpty() && memberId != null && memberId.equals(text(grant.get("memberId")));
    }

    @Override public synchronized boolean hasGrantForOwner(String grantId) {
        return !object(object(state.get("grants")).get(grantId)).isEmpty();
    }

    @Override public synchronized List<Map<String,Object>> listReferencesForMember(String memberId) throws Exception {
        validateMember(memberId);
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map.Entry<String,Object> entry : object(state.get("grants")).entrySet()) {
            Map<String,Object> grant = object(entry.getValue());
            if (!memberId.equals(text(grant.get("memberId")))) continue;
            boolean available = true;
            try { query(rootUri(grant)); } catch (Exception unavailable) { available = false; }
            result.add(publicGrant(entry.getKey(), grant, available));
        }
        result.sort(Comparator.comparing(row -> text(row.get("createdAt"))));
        return List.copyOf(result);
    }

    @Override public synchronized List<Map<String,Object>> browseReference(String memberId, String grantId, String relativeDirectory) throws Exception {
        Map<String,Object> grant = requireGrant(memberId, grantId);
        DocInfo directory = resolve(grant, relativeDirectory);
        if (!directory.directory()) throw new IllegalArgumentException("The requested Android document is not a folder.");
        List<Map<String,Object>> result = new ArrayList<>();
        for (DocInfo child : children(Uri.parse(text(grant.get("treeUri"))), directory.documentId)) {
            String base = normalizeRelative(relativeDirectory);
            String childPath = base.isEmpty() ? child.name : base + "/" + child.name;
            result.add(entry(child, childPath));
            if (result.size() > 10000) throw new IllegalStateException("Android document folder exceeds 10,000 entries.");
        }
        result.sort(Comparator.comparing(row -> text(row.get("name")).toLowerCase(java.util.Locale.ROOT)));
        return List.copyOf(result);
    }

    @Override public synchronized Map<String,Object> statReference(String memberId, String grantId, String relativePath) throws Exception {
        Map<String,Object> grant = requireGrant(memberId, grantId);
        DocInfo info = resolve(grant, relativePath);
        Map<String,Object> row = entry(info, normalizeRelative(relativePath));
        row.put("grantId", grantId); row.put("permission", grant.get("permission"));
        return row;
    }

    @Override public synchronized NetworkReferenceContent openReference(String memberId, String grantId, String relativePath) throws Exception {
        Map<String,Object> grant = requireGrant(memberId, grantId);
        DocInfo info = resolve(grant, relativePath);
        if (info.directory()) throw new IllegalArgumentException("The requested Android document is a folder, not a file.");
        if (info.size < 0) throw new IllegalStateException("The Android document provider does not report a stable file size; random-access sharing is unavailable for this item.");
        Uri document = info.uri;
        long expectedSize = info.size;
        long expectedModified = info.modified;
        String expectedDocumentId = info.documentId;
        return new NetworkReferenceContent() {
            @Override public long size() { return expectedSize; }
            @Override public InputStream openRange(long offset, long length) throws Exception {
                if (offset < 0 || length < 0 || offset > expectedSize || length > expectedSize - offset) {
                    throw new IllegalArgumentException("Requested Android document byte range is outside the file.");
                }
                DocInfo current = query(document);
                if (!expectedDocumentId.equals(current.documentId) || current.size != expectedSize
                        || (expectedModified > 0 && current.modified != expectedModified)) {
                    throw new IllegalStateException("Android source document changed after this read was opened.");
                }
                ParcelFileDescriptor descriptor = resolver.openFileDescriptor(document, "r");
                if (descriptor == null) throw new IllegalStateException("Android document provider returned no readable file descriptor.");
                InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
                try {
                    skipFully(input, offset);
                    return new BoundedInputStream(input, length);
                } catch (Exception failure) {
                    input.close();
                    throw failure;
                }
            }
        };
    }

    @Override public synchronized Map<String,Object> deleteReference(String memberId, String grantId, String relativePath) throws Exception {
        Map<String,Object> grant = requireGrant(memberId, grantId);
        if (!"DOWNLOAD+DELETE".equals(text(grant.get("permission")))) throw new SecurityException("This Android folder was shared as DOWNLOAD only; deletion is not authorized.");
        DocInfo before = resolve(grant, relativePath);
        if (before.directory()) throw new IllegalArgumentException("Only individual Android files can be deleted through a reference grant.");
        if (before.size < 0 || before.size > MAX_SNAPSHOT_BYTES) throw new IllegalArgumentException("This Android document exceeds the recovery snapshot limit or has unknown size; deletion is blocked.");
        if ((before.flags & DocumentsContract.Document.FLAG_SUPPORTS_DELETE) == 0) throw new SecurityException("The selected Android document provider does not support deletion for this file.");

        String snapshotId = UUID.randomUUID().toString();
        Path temporary = versionsRoot.resolve(snapshotId + ".tmp");
        Path blob = versionsRoot.resolve(snapshotId + ".blob");
        String digest;
        try {
            try (InputStream input = resolver.openInputStream(before.uri);
                 OutputStream output = Files.newOutputStream(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                if (input == null) throw new IllegalStateException("Android document provider could not open the source file.");
                digest = copyAndHash(input, output, before.size);
            }
            DocInfo afterCopy = resolve(grant, relativePath);
            if (!sameVersion(before, afterCopy) || !digest.equals(hashDocument(afterCopy.uri, afterCopy.size))) {
                throw new IllegalStateException("Android source changed while the recovery snapshot was created; deletion was cancelled.");
            }
            Files.move(temporary, blob);
            Map<String,Object> record = new LinkedHashMap<>();
            record.put("treeUri", grant.get("treeUri")); record.put("parentDocumentId", parentDocumentId(grant, relativePath));
            record.put("name", before.name); record.put("mimeType", before.mimeType); record.put("path", normalizeRelative(relativePath));
            record.put("size", before.size); record.put("sha256", digest); record.put("createdAt", Instant.now().toString());
            object(state.get("snapshots")).put(snapshotId, record);
            try {
                persist();
            } catch (Exception persistenceFailure) {
                object(state.get("snapshots")).remove(snapshotId);
                throw persistenceFailure;
            }
            DocInfo beforeDelete = resolve(grant, relativePath);
            if (!sameVersion(before, beforeDelete) || !digest.equals(hashDocument(beforeDelete.uri, beforeDelete.size))) {
                throw new IllegalStateException("Android source changed after its recovery snapshot was stored; deletion was cancelled and the snapshot was retained.");
            }
            if (!DocumentsContract.deleteDocument(resolver, before.uri)) throw new IllegalStateException("The Android document provider refused deletion; the original file was retained.");
            pruneSnapshots();
            return Map.of("deleted", true, "path", normalizeRelative(relativePath), "snapshotId", snapshotId,
                    "size", before.size, "sha256", digest);
        } catch (Exception failure) {
            Files.deleteIfExists(temporary);
            if (!object(state.get("snapshots")).containsKey(snapshotId)) Files.deleteIfExists(blob);
            throw failure;
        }
    }

    @Override public synchronized List<Map<String,Object>> searchReferences(String memberId, String query, int limit) throws Exception {
        String needle = query == null ? "" : query.trim().toLowerCase(java.util.Locale.ROOT);
        int maximum = Math.max(1, Math.min(limit, 100));
        validateMember(memberId);
        List<Map<String,Object>> results = new ArrayList<>();
        int totalVisited = 0;
        for (Map.Entry<String,Object> entry : object(state.get("grants")).entrySet()) {
            Map<String,Object> grant = object(entry.getValue());
            if (!memberId.equals(text(grant.get("memberId")))) continue;
            if (!"FOLDER".equals(text(grant.get("rootKind"), "FOLDER"))) {
                DocInfo root = query(rootUri(grant));
                if (root.name.toLowerCase(java.util.Locale.ROOT).contains(needle)) {
                    Map<String,Object> row = entry(root, "");
                    row.put("grantId", entry.getKey()); row.put("permission", grant.get("permission"));
                    results.add(row);
                }
                if (results.size() >= maximum) break;
                continue;
            }
            Uri tree = Uri.parse(text(grant.get("treeUri")));
            ArrayDeque<WalkItem> queue = new ArrayDeque<>();
            queue.add(new WalkItem(text(grant.get("rootDocumentId")), "", 0));
            while (!queue.isEmpty() && results.size() < maximum && totalVisited < MAX_SEARCH_VISITS) {
                WalkItem current = queue.removeFirst();
                if (current.depth > MAX_TREE_DEPTH) continue;
                for (DocInfo child : children(tree, current.documentId)) {
                    if (++totalVisited > MAX_SEARCH_VISITS) break;
                    String path = current.path.isEmpty() ? child.name : current.path + "/" + child.name;
                    if (child.name.toLowerCase(java.util.Locale.ROOT).contains(needle)
                            || path.toLowerCase(java.util.Locale.ROOT).contains(needle)) {
                        Map<String,Object> row = entry(child, path);
                        row.put("grantId", entry.getKey()); row.put("permission", grant.get("permission"));
                        results.add(row);
                        if (results.size() >= maximum) break;
                    }
                    if (child.directory() && current.depth < MAX_TREE_DEPTH) queue.addLast(new WalkItem(child.documentId, path, current.depth + 1));
                }
            }
            if (results.size() >= maximum || totalVisited >= MAX_SEARCH_VISITS) break;
        }
        results.sort(Comparator.comparing(row -> text(row.get("name")).toLowerCase(java.util.Locale.ROOT)));
        return List.copyOf(results.subList(0, Math.min(results.size(), maximum)));
    }

    /** Owner-only view used by the local Android DocumentsProvider. */
    public synchronized List<Map<String,Object>> listOwnerReferences() throws Exception {
        List<Map<String,Object>> rows = new ArrayList<>();
        for (Map.Entry<String,Object> entry : object(state.get("grants")).entrySet()) {
            Map<String,Object> grant = object(entry.getValue());
            boolean available = true;
            try { query(rootUri(grant)); } catch (Exception missing) { available = false; }
            Map<String,Object> row = publicGrant(entry.getKey(), grant, available);
            row.put("memberId", grant.get("memberId"));
            rows.add(row);
        }
        rows.sort(Comparator.comparing(row -> text(row.get("name")).toLowerCase(java.util.Locale.ROOT)));
        return List.copyOf(rows);
    }

    public synchronized List<Map<String,Object>> browseOwnerReference(String grantId, String relativeDirectory) throws Exception {
        Map<String,Object> grant = requireOwnerGrant(grantId);
        return browseReference(text(grant.get("memberId")), grantId, relativeDirectory);
    }

    public synchronized Map<String,Object> statOwnerReference(String grantId, String relativePath) throws Exception {
        Map<String,Object> grant = requireOwnerGrant(grantId);
        return statReference(text(grant.get("memberId")), grantId, relativePath);
    }

    public synchronized NetworkReferenceContent openOwnerReference(String grantId, String relativePath) throws Exception {
        Map<String,Object> grant = requireOwnerGrant(grantId);
        return openReference(text(grant.get("memberId")), grantId, relativePath);
    }

    public synchronized List<Map<String,Object>> searchOwnerReferences(String query, int limit) throws Exception {
        List<Map<String,Object>> rows = new ArrayList<>();
        int maximum = Math.max(1, Math.min(limit, 100));
        java.util.Set<String> members = new java.util.LinkedHashSet<>();
        for (Object value : object(state.get("grants")).values()) {
            String memberId = text(object(value).get("memberId"));
            if (!memberId.isBlank()) members.add(memberId);
        }
        for (String memberId : members) {
            List<Map<String,Object>> found = searchReferences(memberId, query, maximum - rows.size());
            rows.addAll(found);
            if (rows.size() >= maximum) break;
        }
        return List.copyOf(rows.subList(0, Math.min(rows.size(), maximum)));
    }

    /** Owner-only recovery metadata. It is deliberately not exposed through the network API. */
    public synchronized List<Map<String,Object>> listRecoverySnapshots() throws Exception {
        List<Map<String,Object>> rows = new ArrayList<>();
        for (Map.Entry<String,Object> entry : object(state.get("snapshots")).entrySet()) {
            Map<String,Object> record = object(entry.getValue());
            Path blob = snapshotBlob(entry.getKey());
            rows.add(Map.of("snapshotId", entry.getKey(), "path", text(record.get("path")),
                    "size", number(record.get("size")), "sha256", text(record.get("sha256")),
                    "createdAt", text(record.get("createdAt")), "available", validSnapshot(blob, record)));
        }
        return List.copyOf(rows);
    }

    /** Restores an owner-local SAF deletion snapshot without overwriting a document. */
    public synchronized Map<String,Object> restoreRecoverySnapshot(String snapshotId) throws Exception {
        Map<String,Object> record = object(object(state.get("snapshots")).get(snapshotId));
        if (record.isEmpty()) throw new IllegalArgumentException("Android SAF recovery snapshot was not found.");
        Path blob = snapshotBlob(snapshotId);
        if (!validSnapshot(blob, record)) throw new SecurityException("Android SAF recovery snapshot failed SHA-256 verification.");
        Uri tree = Uri.parse(text(record.get("treeUri")));
        Uri parent = DocumentsContract.buildDocumentUriUsingTree(tree, text(record.get("parentDocumentId")));
        for (DocInfo child : children(tree, text(record.get("parentDocumentId")))) {
            if (child.name.equals(text(record.get("name")))) throw new IllegalArgumentException("The original Android document name already exists; restore will not overwrite it.");
        }
        Uri created = DocumentsContract.createDocument(resolver, parent, text(record.get("mimeType")), text(record.get("name")));
        if (created == null) throw new IllegalStateException("Android document provider refused to create the recovery target.");
        try {
            try (InputStream input = Files.newInputStream(blob); OutputStream output = resolver.openOutputStream(created, "w")) {
                if (output == null) throw new IllegalStateException("Android document provider returned no output stream for recovery.");
                byte[] buffer = new byte[128 * 1024]; int read;
                while ((read = input.read(buffer)) != -1) output.write(buffer, 0, read);
            }
            DocInfo restored = query(created);
            if (restored.size != number(record.get("size")) || !text(record.get("sha256")).equals(hashDocument(created, restored.size))) {
                throw new SecurityException("Restored Android document failed size or SHA-256 verification.");
            }
        } catch (Exception failure) {
            try { DocumentsContract.deleteDocument(resolver, created); } catch (Exception ignored) { }
            throw failure;
        }
        return Map.of("snapshotId", snapshotId, "path", text(record.get("path")), "restored", true,
                "size", number(record.get("size")), "sha256", text(record.get("sha256")));
    }

    private Map<String,Object> requireGrant(String memberId, String grantId) {
        Map<String,Object> grant = object(object(state.get("grants")).get(grantId));
        if (memberId == null || memberId.isBlank() || grant.isEmpty()
                || !memberId.equals(text(grant.get("memberId")))) {
            throw new SecurityException("Android SAF reference grant was not found for this network member.");
        }
        return grant;
    }

    private Map<String,Object> requireOwnerGrant(String grantId) {
        Map<String,Object> grant = object(object(state.get("grants")).get(grantId));
        if (grant.isEmpty()) throw new SecurityException("Android SAF reference grant was not found.");
        return grant;
    }

    private Uri rootUri(Map<String,Object> grant) {
        String value = text(grant.get("rootDocumentUri"));
        if (!value.isBlank()) return Uri.parse(value);
        // Compatibility with references created by the earlier scoped V2 build.
        return DocumentsContract.buildDocumentUriUsingTree(Uri.parse(text(grant.get("treeUri"))),
                text(grant.get("rootDocumentId")));
    }

    private DocInfo resolve(Map<String,Object> grant, String relativePath) throws Exception {
        String normalized = normalizeRelative(relativePath);
        DocInfo current = query(rootUri(grant));
        if (normalized.isEmpty()) return current;
        if (!"FOLDER".equals(text(grant.get("rootKind"), "FOLDER"))) {
            throw new IllegalArgumentException("A single-file Android reference has no child paths.");
        }
        Uri tree = Uri.parse(text(grant.get("treeUri")));
        String currentId = text(grant.get("rootDocumentId"));
        for (String segment : normalized.split("/")) {
            if (!current.directory()) throw new IllegalArgumentException("A path component is not an Android folder.");
            DocInfo match = null;
            for (DocInfo child : children(tree, currentId)) {
                if (segment.equals(child.name)) {
                    if (match != null) throw new IllegalStateException("Android provider returned ambiguous duplicate document names; use a narrower folder reference.");
                    match = child;
                }
            }
            if (match == null) throw new IllegalArgumentException("Android referenced document does not exist: " + segment);
            current = match;
            currentId = match.documentId;
        }
        return current;
    }

    private List<DocInfo> children(Uri tree, String parentDocumentId) throws Exception {
        Uri childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentDocumentId);
        String[] projection = { DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED, DocumentsContract.Document.COLUMN_FLAGS };
        List<DocInfo> result = new ArrayList<>();
        try (Cursor cursor = resolver.query(childrenUri, projection, null, null, null)) {
            if (cursor == null) throw new IllegalStateException("Android document provider did not return a child listing.");
            while (cursor.moveToNext()) result.add(infoFromCursor(tree, cursor));
        }
        return result;
    }

    private DocInfo query(Uri documentUri) throws Exception {
        String[] projection = { DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED, DocumentsContract.Document.COLUMN_FLAGS };
        try (Cursor cursor = resolver.query(documentUri, projection, null, null, null)) {
            if (cursor == null || !cursor.moveToFirst()) throw new IllegalArgumentException("Android source document is no longer available.");
            return infoFromCursor(documentUri, cursor, documentUri);
        }
    }

    private DocInfo infoFromCursor(Uri tree, Cursor cursor) {
        Uri document = DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)));
        return infoFromCursor(tree, cursor, document);
    }

    private DocInfo infoFromCursor(Uri tree, Cursor cursor, Uri document) {
        int sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE);
        int modifiedColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED);
        int flagsColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_FLAGS);
        return new DocInfo(document,
                cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)),
                cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)),
                cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)),
                sizeColumn < 0 || cursor.isNull(sizeColumn) ? -1L : cursor.getLong(sizeColumn),
                modifiedColumn < 0 || cursor.isNull(modifiedColumn) ? 0L : cursor.getLong(modifiedColumn),
                flagsColumn < 0 || cursor.isNull(flagsColumn) ? 0 : cursor.getInt(flagsColumn));
    }

    private Map<String,Object> entry(DocInfo info, String relativePath) {
        Map<String,Object> row = new LinkedHashMap<>(); row.put("name", info.name); row.put("path", relativePath);
        row.put("kind", info.directory() ? "FOLDER" : "FILE"); row.put("size", info.size);
        row.put("modified", info.modified); row.put("mimeType", info.mimeType); row.put("readOnly", true);
        return row;
    }

    private Map<String,Object> publicGrant(String grantId, Map<String,Object> grant, boolean available) {
        Map<String,Object> row = new LinkedHashMap<>(); row.put("grantId", grantId); row.put("name", text(grant.get("name")));
        row.put("kind", text(grant.get("rootKind"), "FOLDER")); row.put("path", ""); row.put("permission", text(grant.get("permission")));
        row.put("size", number(grant.get("size"))); row.put("modified", number(grant.get("modified")));
        row.put("mimeType", text(grant.get("mimeType"), "application/octet-stream"));
        row.put("createdAt", text(grant.get("createdAt"))); row.put("ownerNodeId", "local");
        row.put("available", available); row.put("availability", available ? "ONLINE" : "UNAVAILABLE"); return row;
    }

    private Context contextForResolver() { return appContext; }
    private boolean hasPersistedReadPermission(Uri selected) {
        for (android.content.UriPermission permission : resolver.getPersistedUriPermissions())
            if (permission.getUri().equals(selected) && permission.isReadPermission()) return true;
        return false;
    }
    private boolean hasPersistedWritePermission(Uri selected) {
        for (android.content.UriPermission permission : resolver.getPersistedUriPermissions())
            if (permission.getUri().equals(selected) && permission.isWritePermission()) return true;
        return false;
    }

    private String parentDocumentId(Map<String,Object> grant, String relativePath) throws Exception {
        String normalized = normalizeRelative(relativePath);
        int slash = normalized.lastIndexOf('/'); String parentPath = slash < 0 ? "" : normalized.substring(0, slash);
        return resolve(grant, parentPath).documentId;
    }
    private String hashDocument(Uri uri, long expectedSize) throws Exception {
        try (InputStream input = resolver.openInputStream(uri)) {
            if (input == null) throw new IllegalStateException("Android document could not be read for integrity verification.");
            return copyAndHash(input, new DiscardOutputStream(), expectedSize);
        }
    }
    private static String copyAndHash(InputStream input, OutputStream output, long expectedSize) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); long copied = 0; byte[] buffer = new byte[128 * 1024];
        int read;
        while ((read = input.read(buffer)) != -1) {
            copied = Math.addExact(copied, read); if (expectedSize >= 0 && copied > expectedSize) throw new SecurityException("Android document grew during snapshot verification.");
            digest.update(buffer, 0, read); output.write(buffer, 0, read);
        }
        if (expectedSize >= 0 && copied != expectedSize) throw new SecurityException("Android document changed size during snapshot verification.");
        return hex(digest.digest());
    }
    private boolean sameVersion(DocInfo a, DocInfo b) { return a.documentId.equals(b.documentId) && a.size == b.size && a.modified == b.modified; }
    private Path snapshotBlob(String id) { if (id == null || !id.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Invalid snapshot ID."); return versionsRoot.resolve(id + ".blob"); }
    private boolean validSnapshot(Path blob, Map<String,Object> record) throws Exception {
        long size = number(record.get("size")); String hash = text(record.get("sha256"));
        return size >= 0 && hash.matches("[a-f0-9]{64}") && Files.isRegularFile(blob, LinkOption.NOFOLLOW_LINKS)
                && !Files.isSymbolicLink(blob) && Files.size(blob) == size && hash.equals(shaFile(blob));
    }
    private void pruneSnapshots() throws Exception {
        Map<String,Object> snapshots = object(state.get("snapshots"));
        List<Map.Entry<String,Object>> records = new ArrayList<>(snapshots.entrySet());
        records.sort((a,b) -> text(object(b.getValue()).get("createdAt"))
                .compareTo(text(object(a.getValue()).get("createdAt"))));

        Map<String,Integer> perSourcePath = new LinkedHashMap<>();
        List<Map.Entry<String,Object>> removed = new ArrayList<>();
        long retainedBytes = 0;
        int retainedCount = 0;
        for (Map.Entry<String,Object> entry : records) {
            Map<String,Object> record = object(entry.getValue());
            String sourcePath = text(record.get("treeUri")) + "\u0000" + text(record.get("path"));
            long size = number(record.get("size"));
            int pathCount = perSourcePath.getOrDefault(sourcePath, 0);
            boolean exceedsByteBudget = size < 0 || size > MAX_TOTAL_SNAPSHOT_BYTES - retainedBytes;
            if (pathCount >= MAX_SNAPSHOTS_PER_PATH || retainedCount >= MAX_TOTAL_SNAPSHOTS || exceedsByteBudget) {
                removed.add(entry);
                snapshots.remove(entry.getKey());
            } else {
                perSourcePath.put(sourcePath, pathCount + 1);
                retainedCount++;
                retainedBytes += size;
            }
        }

        if (removed.isEmpty()) return;
        try {
            persist();
        } catch (Exception failure) {
            for (Map.Entry<String,Object> entry : removed) snapshots.put(entry.getKey(), entry.getValue());
            throw failure;
        }

        java.util.Set<String> trees = new java.util.LinkedHashSet<>();
        for (Map.Entry<String,Object> entry : removed) {
            Map<String,Object> record = object(entry.getValue());
            trees.add(text(record.get("treeUri")));
            Files.deleteIfExists(snapshotBlob(entry.getKey()));
        }
        for (String tree : trees) releaseUriPermissionIfUnused(tree);
    }

    private void releaseUriPermissionIfUnused(String uriValue) {
        releaseUriPermissionIfUnused(uriValue, -1);
    }

    private void releaseUriPermissionIfUnused(String uriValue, int requestedReleaseFlags) {
        if (uriValue == null || uriValue.isBlank()) return;
        boolean referencedByGrant = object(state.get("grants")).values().stream().anyMatch(value -> {
            Map<String,Object> grant = object(value);
            String retainedUri = text(grant.get("permissionUri"), text(grant.get("treeUri")));
            return uriValue.equals(retainedUri);
        });
        boolean retainedForRecovery = object(state.get("snapshots")).values().stream()
                .anyMatch(value -> uriValue.equals(text(object(value).get("treeUri"))));
        if (referencedByGrant || retainedForRecovery) return;

        Uri selected = Uri.parse(uriValue);
        int flags = 0;
        for (android.content.UriPermission permission : resolver.getPersistedUriPermissions()) {
            if (!permission.getUri().equals(selected)) continue;
            if (permission.isReadPermission()) flags |= android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION;
            if (permission.isWritePermission()) flags |= android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
        }
        if (requestedReleaseFlags >= 0) flags &= requestedReleaseFlags;
        if (flags != 0) {
            try { resolver.releasePersistableUriPermission(selected, flags); }
            catch (SecurityException ignored) { /* The user may have revoked it in system settings. */ }
        }
    }

    /**
     * Roll back a picker permission if the UI acquired it but failed to persist a grant.
     * Existing grants and deletion snapshots keep the permission alive.
     */
    public synchronized void releasePersistedPermissionIfUnused(String uriValue, int flags) {
        releaseUriPermissionIfUnused(uriValue, flags);
    }

    private static String hex(byte[] bytes) {
        final char[] digits = "0123456789abcdef".toCharArray();
        char[] output = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            output[i * 2] = digits[value >>> 4];
            output[i * 2 + 1] = digits[value & 0x0f];
        }
        return new String(output);
    }
    private String shaFile(Path file) throws Exception { try(InputStream input=Files.newInputStream(file)){return copyAndHash(input,new DiscardOutputStream(),Files.size(file));} }
    private void validateMember(String id) { if(id==null||id.isBlank())throw new IllegalArgumentException("Network member ID is required."); }
    private String normalizePermission(String permission) { String p=permission==null?"":permission.trim().toUpperCase(java.util.Locale.ROOT); if(!p.equals("DOWNLOAD")&&!p.equals("DOWNLOAD+DELETE"))throw new IllegalArgumentException("Permission must be DOWNLOAD or DOWNLOAD+DELETE.");return p; }
    private static String normalizeRelative(String value) {
        if(value==null||value.isBlank())return ""; String normalized=value.replace('\\','/');
        if(normalized.startsWith("/")||normalized.matches("^[A-Za-z]:.*"))throw new IllegalArgumentException("Absolute Android document paths are not allowed.");
        String[] parts=normalized.split("/",-1);List<String> clean=new ArrayList<>();
        for(String part:parts){if(part.isEmpty()||part.equals("."))continue;if(part.equals("..")||part.indexOf('\0')>=0)throw new IllegalArgumentException("Android document path traversal is not allowed.");clean.add(part);}
        return String.join("/",clean);
    }
    private static void skipFully(InputStream input,long offset)throws Exception { long remaining=offset;while(remaining>0){long skipped=input.skip(remaining);if(skipped>0){remaining-=skipped;continue;}if(input.read()<0)throw new java.io.EOFException("Android document ended before requested byte offset.");remaining--;}}
    private synchronized void persist()throws Exception { stateStore.saveDomain(DOMAIN,state); }
    private void ensureMap(String key){if(!(state.get(key) instanceof Map))state.put(key,new LinkedHashMap<String,Object>());}
    @SuppressWarnings("unchecked") private static Map<String,Object> object(Object value){return value instanceof Map?(Map<String,Object>)value:new LinkedHashMap<>();}
    private static String text(Object value){return value==null?"":String.valueOf(value);}
    private static String text(Object value, String fallback){String result=text(value);return result.isBlank()?fallback:result;}
    private static long number(Object value){return value instanceof Number n?n.longValue():-1L;}

    private static final class DocInfo {
        final Uri uri; final String documentId,name,mimeType; final long size,modified; final int flags;
        DocInfo(Uri uri,String id,String name,String mime,long size,long modified,int flags){this.uri=uri;this.documentId=id;this.name=name==null?"":name;this.mimeType=mime==null?"application/octet-stream":mime;this.size=size;this.modified=modified;this.flags=flags;}
        boolean directory(){return DIRECTORY_MIME.equals(mimeType);}
    }
    private static final class WalkItem {
        final String documentId, path; final int depth;
        WalkItem(String documentId, String path, int depth) { this.documentId=documentId; this.path=path; this.depth=depth; }
    }
    private static final class DiscardOutputStream extends OutputStream {
        @Override public void write(int value) { }
        @Override public void write(byte[] bytes, int offset, int length) { }
    }
    private static final class BoundedInputStream extends java.io.FilterInputStream {
        private long remaining;
        BoundedInputStream(InputStream input,long length){super(input);remaining=length;}
        @Override public int read() throws java.io.IOException { if(remaining<=0)return -1;int value=super.read();if(value<0)throw new java.io.EOFException("Android document ended during a bounded range read.");remaining--;return value; }
        @Override public int read(byte[] bytes,int offset,int length)throws java.io.IOException { if(remaining<=0)return -1;int read=super.read(bytes,offset,(int)Math.min(length,remaining));if(read<0)throw new java.io.EOFException("Android document ended during a bounded range read.");remaining-=read;return read; }
        @Override public void close()throws java.io.IOException{super.close();}
    }
}
