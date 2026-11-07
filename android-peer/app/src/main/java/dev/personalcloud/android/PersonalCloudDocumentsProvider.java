package dev.personalcloud.android;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.ParcelFileDescriptor;
import android.os.ProxyFileDescriptorCallback;
import android.os.storage.StorageManager;
import android.provider.DocumentsContract;
import android.provider.DocumentsProvider;
import android.webkit.MimeTypeMap;
import android.system.ErrnoException;
import android.system.OsConstants;

import dev.personalcloud.android.core.ExternalReferenceStore;
import dev.personalcloud.android.core.Json;
import dev.personalcloud.android.core.NetworkMembershipClient;
import dev.personalcloud.android.core.NetworkPeerConnector;
import dev.personalcloud.android.core.PeerConnector;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Android Storage Access Framework surface for the signed PersonalCloud network.
 * Remote files use seekable proxy descriptors and authenticated, digest-verified byte ranges.
 * Metadata is cached for offline visibility; cached entries are always labelled unavailable.
 * Mutations are limited to owner-authorized reference deletion and network-managed file deletion.
 */
public final class PersonalCloudDocumentsProvider extends DocumentsProvider {
    public static final String AUTHORITY_SUFFIX = ".documents";
    private static final String ROOT_ID = "personalcloud";
    private static final String DOC_ROOT = "root";
    private static final String DOC_LOCAL = "local";
    private static final String DOC_LOCAL_REFERENCES = "localrefs";
    private static final int RANGE_CHUNK = 4 * 1024 * 1024;
    /** Writable proxy staging cap; larger eligible-storage files remain readable but are not edited in place. */
    private static final long MAX_STAGED_BYTES = 512L * 1024 * 1024;
    private static final int FILE_WRITE_FLAGS = DocumentsContract.Document.FLAG_SUPPORTS_WRITE
            | DocumentsContract.Document.FLAG_SUPPORTS_DELETE
            | DocumentsContract.Document.FLAG_SUPPORTS_RENAME
            | DocumentsContract.Document.FLAG_SUPPORTS_MOVE;
    private static final int DIRECTORY_WRITE_FLAGS = DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
            | DocumentsContract.Document.FLAG_SUPPORTS_DELETE
            | DocumentsContract.Document.FLAG_SUPPORTS_RENAME
            | DocumentsContract.Document.FLAG_SUPPORTS_MOVE;
    private static final String MEMBER_CACHE = "documents.network.members";

    private static final String[] ROOT_COLUMNS = {
            DocumentsContract.Root.COLUMN_ROOT_ID,
            DocumentsContract.Root.COLUMN_DOCUMENT_ID,
            DocumentsContract.Root.COLUMN_TITLE,
            DocumentsContract.Root.COLUMN_SUMMARY,
            DocumentsContract.Root.COLUMN_ICON,
            DocumentsContract.Root.COLUMN_FLAGS,
            DocumentsContract.Root.COLUMN_MIME_TYPES,
            DocumentsContract.Root.COLUMN_AVAILABLE_BYTES
    };
    private static final String[] DOC_COLUMNS = {
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            DocumentsContract.Document.COLUMN_SUMMARY
    };

    private HandlerThread proxyThread;
    private Handler proxyHandler;
    private AndroidStateStore stateStore;
    private AndroidSafReferenceStore externalReferences;

    @Override public boolean onCreate() {
        try {
            stateStore = new AndroidStateStore(appContext());
            externalReferences = AndroidStorageRuntime.references(appContext());
            proxyThread = new HandlerThread("personalcloud-document-io");
            proxyThread.start();
            proxyHandler = new Handler(proxyThread.getLooper());
            return true;
        } catch (Exception failure) {
            android.util.Log.e("PersonalCloud", "Could not initialize Android document storage", failure);
            if (proxyThread != null) proxyThread.quitSafely();
            return false;
        }
    }

    @Override public Cursor queryRoots(String[] projection) {
        MatrixCursor cursor = new MatrixCursor(columns(projection, ROOT_COLUMNS));
        Map<String,Object> row = new LinkedHashMap<>();
        row.put(DocumentsContract.Root.COLUMN_ROOT_ID, ROOT_ID);
        row.put(DocumentsContract.Root.COLUMN_DOCUMENT_ID, DOC_ROOT);
        row.put(DocumentsContract.Root.COLUMN_TITLE, "PersonalCloud");
        row.put(DocumentsContract.Root.COLUMN_SUMMARY, "Private devices, on-demand files and writable eligible storage");
        row.put(DocumentsContract.Root.COLUMN_ICON, android.R.drawable.ic_menu_save);
        row.put(DocumentsContract.Root.COLUMN_FLAGS, DocumentsContract.Root.FLAG_SUPPORTS_SEARCH
                | DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD);
        row.put(DocumentsContract.Root.COLUMN_MIME_TYPES, "*/*");
        row.put(DocumentsContract.Root.COLUMN_AVAILABLE_BYTES, null);
        addRow(cursor, row);
        cursor.setNotificationUri(appContext().getContentResolver(), DocumentsContract.buildRootsUri(authority()));
        return cursor;
    }

    @Override public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
        try {
            MatrixCursor cursor = new MatrixCursor(columns(projection, DOC_COLUMNS));
            addRow(cursor, document(documentId));
            return cursor;
        } catch (Exception error) {
            throw fileNotFound("PersonalCloud document is unavailable: " + safe(error), error);
        }
    }

    @Override public Cursor queryChildDocuments(String parentDocumentId, String[] projection, String sortOrder)
            throws FileNotFoundException {
        try {
            MatrixCursor cursor = new MatrixCursor(columns(projection, DOC_COLUMNS));
            for (Map<String,Object> row : children(parentDocumentId)) addRow(cursor, row);
            return cursor;
        } catch (Exception error) {
            throw fileNotFound("Could not list PersonalCloud documents: " + safe(error), error);
        }
    }

    @Override public Cursor queryChildDocuments(String parentDocumentId, String[] projection, Bundle queryArgs)
            throws FileNotFoundException {
        return queryChildDocuments(parentDocumentId, projection, (String) null);
    }

    @Override public Cursor querySearchDocuments(String rootId, String query, String[] projection)
            throws FileNotFoundException {
        String needle = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        MatrixCursor cursor = new MatrixCursor(columns(projection, DOC_COLUMNS));
        if (needle.isEmpty()) return cursor;
        try {
            for (Map<String,Object> row : searchLocal(needle)) addRow(cursor, row);
            try {
                for (Map<String,Object> item : externalReferences.searchOwnerReferences(needle, 100)) {
                    String grantId = text(item.get("grantId"));
                    String path = text(item.get("path"));
                    String kind = text(item.get("kind"));
                    if ("FOLDER".equalsIgnoreCase(kind)) {
                        addRow(cursor, directoryRow(DocumentId.localReferenceDir(grantId, path),
                                text(item.get("name")), "Referenced in place on this device", false));
                    } else if ("FILE".equalsIgnoreCase(kind)) {
                        String name = text(item.get("name"), lastSegment(path));
                        addRow(cursor, fileRow(DocumentId.localReferenceFile(grantId, path), name,
                                text(item.get("mimeType"), mime(name)), number(item.get("size"), 0L),
                                parseTimeMillis(item.get("modified")), "Referenced in place on this device"));
                    }
                }
            } catch (Exception localReferenceUnavailable) {
                android.util.Log.w("PersonalCloud", "One or more local Android references are unavailable", localReferenceUnavailable);
            }
            for (Map<String,Object> member : peers()) {
                String peerId = text(member.get("nodeId"));
                try {
                    List<Map<String,Object>> found = NetworkPeerConnector.searchReferences(endpoint(peerId), needle, 100,
                            requireMembership(), trustedCa());
                    cacheRows(searchCacheKey(peerId), found);
                    for (Map<String,Object> item : found) {
                        if (!"FILE".equalsIgnoreCase(text(item.get("kind")))) continue;
                        addRow(cursor, remoteReferenceFileRow(peerId, item, false));
                    }
                } catch (Exception unavailable) {
                    for (Map<String,Object> item : cachedRows(searchCacheKey(peerId))) {
                        if (text(item.get("name")).toLowerCase(Locale.ROOT).contains(needle)
                                && "FILE".equalsIgnoreCase(text(item.get("kind")))) {
                            addRow(cursor, remoteReferenceFileRow(peerId, item, true));
                        }
                    }
                }
                for (Map<String,Object> item : managedFiles(peerId)) {
                    if (text(item.get("name")).toLowerCase(Locale.ROOT).contains(needle)) {
                        addRow(cursor, remoteManagedFileRow(peerId, item, Boolean.TRUE.equals(item.get("stale"))));
                    }
                }
            }
            return cursor;
        } catch (Exception error) {
            throw fileNotFound("PersonalCloud search failed: " + safe(error), error);
        }
    }

    @Override public boolean isChildDocument(String parentDocumentId, String documentId) {
        if (parentDocumentId == null || documentId == null || parentDocumentId.equals(documentId)) return false;
        if (DOC_ROOT.equals(parentDocumentId)) {
            return DOC_LOCAL.equals(documentId) || DOC_LOCAL_REFERENCES.equals(documentId)
                    || safeParseType(documentId, "peer");
        }
        if (DOC_LOCAL_REFERENCES.equals(parentDocumentId)) {
            try {
                DocumentId child = DocumentId.parse(documentId);
                return (child.type.equals("localrefdir") || child.type.equals("localreffile")) && child.path.isEmpty();
            } catch (Exception ignored) { return false; }
        }
        try {
            DocumentId parent = DocumentId.parse(parentDocumentId);
            DocumentId child = DocumentId.parse(documentId);
            if (parent.type.equals("peer")) return child.peerId.equals(parent.peerId)
                    && (child.type.equals("refs") || child.type.equals("managed") || child.type.equals("fss"));
            if (parent.type.equals("fss")) return child.peerId.equals(parent.peerId) && child.type.equals("fsroot");
            if ((parent.type.equals("fsroot") || parent.type.equals("fsdir"))
                    && (child.type.equals("fsdir") || child.type.equals("fsfile"))) {
                return child.peerId.equals(parent.peerId) && child.grantId.equals(parent.grantId)
                        && isPathWithin(parent.path, child.path);
            }
            if (parent.type.equals("refs")) return child.peerId.equals(parent.peerId)
                    && (child.type.equals("refdir") || child.type.equals("reffile"));
            if (parent.type.equals("managed")) return child.peerId.equals(parent.peerId) && child.type.equals("managedfile");
            if (parent.type.equals("refdir") && child.peerId.equals(parent.peerId)
                    && child.grantId.equals(parent.grantId)
                    && (child.type.equals("refdir") || child.type.equals("reffile"))) {
                return isPathWithin(parent.path, child.path);
            }
            if (parent.type.equals("local") && (child.type.equals("localdir") || child.type.equals("localfile"))) return true;
            if (parent.type.equals("localdir") && (child.type.equals("localdir") || child.type.equals("localfile"))) {
                return isPathWithin(parent.path, child.path);
            }
            if (parent.type.equals("localrefdir") && child.grantId.equals(parent.grantId)
                    && (child.type.equals("localrefdir") || child.type.equals("localreffile"))) {
                return isPathWithin(parent.path, child.path);
            }
        } catch (Exception ignored) { }
        return false;
    }

    @Override public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        if (signal != null && signal.isCanceled()) throw fileNotFound("Document open was cancelled.", null);
        try {
            DocumentId id = DocumentId.parse(documentId);
            if (id.type.equals("fsfile")) return openFilesystemDocument(id, mode, signal);
            if (!"r".equals(mode)) {
                throw new UnsupportedOperationException("Only eligible-storage documents are writable in this release.");
            }
            if (id.type.equals("localfile")) {
                Path file = localPath(id.path);
                return ParcelFileDescriptor.open(file.toFile(), ParcelFileDescriptor.MODE_READ_ONLY);
            }
            if (id.type.equals("localreffile")) {
                Map<String,Object> metadata = externalReferences.statOwnerReference(id.grantId, id.path);
                long size = number(metadata.get("size"), -1L);
                if (size < 0) throw new FileNotFoundException("The Android source provider does not report a stable file size.");
                ExternalReferenceStore.NetworkReferenceContent content = externalReferences.openOwnerReference(id.grantId, id.path);
                StorageManager storage = appContext().getSystemService(StorageManager.class);
                if (storage == null) throw new IllegalStateException("Android proxy file descriptors are unavailable on this device.");
                return storage.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY,
                        new LocalReferenceFileCallback(content, size, signal), proxyHandler);
            }
            if (!id.type.equals("reffile") && !id.type.equals("managedfile")) {
                throw new FileNotFoundException("Only file documents can be opened.");
            }
            NetworkMembershipClient membership = requireMembership();
            String endpoint = endpoint(id.peerId);
            String ca = trustedCa();
            Map<String,Object> metadata = id.type.equals("reffile")
                    ? referenceMetadata(id.peerId, id.grantId, id.path)
                    : managedMetadata(id.peerId, id.fileId);
            if (Boolean.TRUE.equals(metadata.get("stale"))) {
                throw new IllegalStateException("This device is offline. Cached metadata is visible, but its files are unavailable.");
            }
            long size = number(metadata.get("size"), -1L);
            if (size < 0) throw new FileNotFoundException("The remote peer did not provide a valid file size.");
            StorageManager storage = appContext().getSystemService(StorageManager.class);
            if (storage == null) throw new IllegalStateException("Android proxy file descriptors are unavailable on this device.");
            return storage.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY,
                    new NetworkFileCallback(id, endpoint, membership, ca, size, signal), proxyHandler);
        } catch (FileNotFoundException error) {
            throw error;
        } catch (Exception error) {
            throw fileNotFound("Could not open PersonalCloud document: " + safe(error), error);
        }
    }

    @Override public void deleteDocument(String documentId) throws FileNotFoundException {
        try {
            DocumentId id = DocumentId.parse(documentId);
            NetworkMembershipClient membership = requireMembership();
            String peerEndpoint = endpoint(id.peerId);
            String ca = trustedCa();
            if (id.type.equals("reffile")) {
                Map<String,Object> metadata = referenceMetadata(id.peerId, id.grantId, id.path);
                if (Boolean.TRUE.equals(metadata.get("stale"))) {
                    throw new IllegalStateException("The owner device is offline; deletion cannot be performed from cached metadata.");
                }
                if (!"DOWNLOAD+DELETE".equals(text(metadata.get("permission")))) {
                    throw new SecurityException("The owner granted DOWNLOAD only; this file cannot be deleted.");
                }
                NetworkPeerConnector.deleteReference(peerEndpoint, id.grantId, id.path, membership, ca);
                invalidateReferenceCaches(id.peerId, id.grantId, id.path);
            } else if (id.type.equals("managedfile")) {
                Map<String,Object> metadata = managedMetadata(id.peerId, id.fileId);
                if (Boolean.TRUE.equals(metadata.get("stale"))) {
                    throw new IllegalStateException("The storage device is offline; deletion cannot be performed from cached metadata.");
                }
                NetworkPeerConnector.deleteManagedFile(peerEndpoint, id.fileId, membership, ca);
                invalidateManagedCaches(id.peerId, id.fileId);
            } else if (id.type.equals("fsfile") || id.type.equals("fsdir")) {
                NetworkPeerConnector.deleteFilesystemEntry(peerEndpoint, id.grantId, id.path,
                        id.type.equals("fsdir"), "", membership, ca);
            } else {
                throw new SecurityException("Only remote files can be deleted through this PersonalCloud document provider.");
            }
            appContext().getContentResolver().notifyChange(
                    DocumentsContract.buildDocumentUri(authority(), documentId), null);
            appContext().getContentResolver().notifyChange(DocumentsContract.buildRootsUri(authority()), null);
        } catch (FileNotFoundException error) {
            throw error;
        } catch (Exception error) {
            throw fileNotFound("Could not delete PersonalCloud document: " + safe(error), error);
        }
    }

    @Override public String createDocument(String parentDocumentId, String mimeType, String displayName)
            throws FileNotFoundException {
        try {
            DocumentId parent = DocumentId.parse(parentDocumentId);
            if (!parent.type.equals("fsroot") && !parent.type.equals("fsdir")) {
                throw new SecurityException("New documents can only be created inside writable eligible storage.");
            }
            String name = writableName(displayName);
            String childPath = parent.path.isEmpty() ? name : parent.path + "/" + name;
            NetworkMembershipClient membership = requireMembership();
            String peerEndpoint = endpoint(parent.peerId);
            String ca = trustedCa();
            String documentId;
            if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mimeType)) {
                NetworkPeerConnector.createFilesystemDirectory(peerEndpoint, parent.grantId, childPath, membership, ca);
                documentId = DocumentId.filesystemDir(parent.peerId, parent.grantId, childPath);
            } else {
                Path staging = Files.createTempFile("personalcloud-create-", ".part");
                try {
                    NetworkPeerConnector.uploadFilesystemFile(peerEndpoint, parent.grantId, childPath, staging,
                            false, "", membership, ca, MAX_STAGED_BYTES);
                } finally { Files.deleteIfExists(staging); }
                documentId = DocumentId.filesystemFile(parent.peerId, parent.grantId, childPath);
            }
            notifyParent(parentDocumentId);
            return documentId;
        } catch (FileNotFoundException error) {
            throw error;
        } catch (Exception error) {
            throw fileNotFound("Could not create PersonalCloud document: " + safe(error), error);
        }
    }

    @Override public String renameDocument(String documentId, String displayName) throws FileNotFoundException {
        try {
            DocumentId id = DocumentId.parse(documentId);
            if (!id.type.equals("fsfile") && !id.type.equals("fsdir")) {
                throw new SecurityException("Only eligible-storage documents can be renamed.");
            }
            String name = writableName(displayName);
            String parent = parentPath(id.path);
            String destination = parent.isEmpty() ? name : parent + "/" + name;
            if (destination.equals(id.path)) return documentId;
            NetworkPeerConnector.moveFilesystemEntry(endpoint(id.peerId), id.grantId, id.path, destination,
                    false, "", requireMembership(), trustedCa());
            notifyParent(DocumentId.filesystemDir(id.peerId, id.grantId, parent));
            return id.type.equals("fsfile")
                    ? DocumentId.filesystemFile(id.peerId, id.grantId, destination)
                    : DocumentId.filesystemDir(id.peerId, id.grantId, destination);
        } catch (FileNotFoundException error) {
            throw error;
        } catch (Exception error) {
            throw fileNotFound("Could not rename PersonalCloud document: " + safe(error), error);
        }
    }

    @Override public String moveDocument(String sourceDocumentId, String sourceParentDocumentId,
                                         String targetParentDocumentId) throws FileNotFoundException {
        try {
            DocumentId source = DocumentId.parse(sourceDocumentId);
            DocumentId target = DocumentId.parse(targetParentDocumentId);
            if (!source.type.equals("fsfile") && !source.type.equals("fsdir")) {
                throw new SecurityException("Only eligible-storage documents can be moved.");
            }
            if (!target.type.equals("fsroot") && !target.type.equals("fsdir")) {
                throw new SecurityException("The destination is not a writable eligible-storage directory.");
            }
            if (!source.peerId.equals(target.peerId) || !source.grantId.equals(target.grantId)) {
                throw new SecurityException("PersonalCloud cannot move entries across devices or eligible roots.");
            }
            String name = lastSegment(source.path);
            if (name.isEmpty()) throw new SecurityException("The eligible root itself cannot be moved.");
            String destination = target.path.isEmpty() ? name : target.path + "/" + name;
            if (destination.equals(source.path)) return sourceDocumentId;
            NetworkPeerConnector.moveFilesystemEntry(endpoint(source.peerId), source.grantId, source.path,
                    destination, false, "", requireMembership(), trustedCa());
            notifyParent(sourceParentDocumentId);
            notifyParent(targetParentDocumentId);
            return source.type.equals("fsfile")
                    ? DocumentId.filesystemFile(source.peerId, source.grantId, destination)
                    : DocumentId.filesystemDir(source.peerId, source.grantId, destination);
        } catch (FileNotFoundException error) {
            throw error;
        } catch (Exception error) {
            throw fileNotFound("Could not move PersonalCloud document: " + safe(error), error);
        }
    }

    private void notifyParent(String parentDocumentId) {
        if (parentDocumentId == null) return;
        appContext().getContentResolver().notifyChange(
                DocumentsContract.buildDocumentUri(authority(), parentDocumentId), null);
        appContext().getContentResolver().notifyChange(DocumentsContract.buildRootsUri(authority()), null);
    }

    private static String writableName(String displayName) {
        String name = displayName == null ? "" : displayName;
        if (name.isBlank() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0
                || name.indexOf('\\') >= 0 || name.indexOf('\0') >= 0) {
            throw new SecurityException("The document name is not a safe single path segment.");
        }
        return name;
    }

    private static String parentPath(String path) {
        if (path == null || path.isEmpty()) return "";
        int separator = path.lastIndexOf('/');
        return separator < 0 ? "" : path.substring(0, separator);
    }

    @Override public void shutdown() {
        if (proxyThread != null) proxyThread.quitSafely();
        super.shutdown();
    }

    private List<Map<String,Object>> children(String parentDocumentId) throws Exception {
        if (DOC_LOCAL_REFERENCES.equals(parentDocumentId)) return localReferenceRoots();
        if (DOC_ROOT.equals(parentDocumentId)) {
            List<Map<String,Object>> result = new ArrayList<>();
            result.add(directoryRow(DOC_LOCAL, "This device", "Phone-owned PersonalCloud storage", false));
            result.add(directoryRow(DOC_LOCAL_REFERENCES, "Referenced items", "Existing Android files and folders · no copy", false));
            for (Map<String,Object> member : peers()) {
                String id = text(member.get("nodeId"));
                boolean offline = Boolean.FALSE.equals(member.get("online"));
                result.add(directoryRow(DocumentId.peer(id), text(member.get("nodeName"), "PersonalCloud device"),
                        offline ? "Offline · cached device" : "Private network member", offline));
            }
            return result;
        }
        DocumentId parent = DocumentId.parse(parentDocumentId);
        return switch (parent.type) {
            case "local" -> localChildren("");
            case "localdir" -> localChildren(parent.path);
            case "localrefdir" -> localReferenceChildren(parent.grantId, parent.path);
            case "peer" -> List.of(
                    directoryRow(DocumentId.refs(parent.peerId), "References", "Existing files shared by this device", false),
                    directoryRow(DocumentId.managed(parent.peerId), "Distributed-Storage", "Whole files stored on this device", false),
                    directoryRow(DocumentId.filesystem(parent.peerId), "Filesystem",
                            "Owner's actual files and folders · writable", false));
            case "refs" -> referenceRoots(parent.peerId);
            case "managed" -> managedRows(parent.peerId);
            case "refdir" -> referenceChildren(parent.peerId, parent.grantId, parent.path);
            case "fss" -> filesystemRoots(parent.peerId);
            case "fsroot" -> filesystemChildren(parent.peerId, parent.grantId, "");
            case "fsdir" -> filesystemChildren(parent.peerId, parent.grantId, parent.path);
            default -> Collections.emptyList();
        };
    }

    private List<Map<String,Object>> localChildren(String relative) throws Exception {
        Path directory = localPath(relative);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) return Collections.emptyList();
        List<Map<String,Object>> result = new ArrayList<>();
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                if (Files.isSymbolicLink(entry)) continue;
                String child = relative.isEmpty() ? entry.getFileName().toString() : relative + "/" + entry.getFileName();
                if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                    result.add(directoryRow(DocumentId.localDir(child), entry.getFileName().toString(), "On this device", false));
                } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
                    result.add(fileRow(DocumentId.localFile(child), entry.getFileName().toString(), mime(entry),
                            Files.size(entry), Files.getLastModifiedTime(entry, LinkOption.NOFOLLOW_LINKS).toMillis(), "On this device"));
                }
            }
        }
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> referenceRoots(String peerId) throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map<String,Object> grant : referenceGrants(peerId)) {
            String grantId = text(grant.get("grantId"));
            String kind = text(grant.get("kind"));
            boolean stale = Boolean.TRUE.equals(grant.get("stale")) || "MISSING".equalsIgnoreCase(text(grant.get("availability")));
            String path = "";
            if ("FOLDER".equalsIgnoreCase(kind)) {
                result.add(directoryRow(DocumentId.referenceDir(peerId, grantId, path),
                        text(grant.get("name"), text(grant.get("rootName"), "Reference")),
                        stale ? "Offline · cached metadata · unavailable" : "Referenced folder · zero-copy", stale));
            } else if ("FILE".equalsIgnoreCase(kind)) {
                Map<String,Object> row = new LinkedHashMap<>(grant);
                row.put("permission", grant.get("permission"));
                cacheReferenceMetadata(peerId, grantId, path, row);
                result.add(remoteReferenceFileRow(peerId, row, stale));
            }
        }
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> referenceChildren(String peerId, String grantId, String relativePath) throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        Map<String,Object> grant = findGrant(referenceGrants(peerId), grantId);
        boolean rootStale = Boolean.TRUE.equals(grant.get("stale"));
        List<Map<String,Object>> entries = browseReference(peerId, grantId, relativePath);
        for (Map<String,Object> entry : entries) {
            String path = text(entry.get("path"));
            String kind = text(entry.get("kind"));
            entry.put("grantId", grantId);
            entry.put("permission", grant.get("permission"));
            boolean stale = rootStale || Boolean.TRUE.equals(entry.get("stale"));
            if ("DIRECTORY".equalsIgnoreCase(kind) || "FOLDER".equalsIgnoreCase(kind)) {
                result.add(directoryRow(DocumentId.referenceDir(peerId, grantId, path), text(entry.get("name")),
                        stale ? "Offline · cached metadata · unavailable" : "Remote folder", stale));
            } else if ("FILE".equalsIgnoreCase(kind)) {
                cacheReferenceMetadata(peerId, grantId, path, entry);
                result.add(remoteReferenceFileRow(peerId, entry, stale));
            }
        }
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> localReferenceRoots() throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map<String,Object> grant : externalReferences.listOwnerReferences()) {
            String grantId = text(grant.get("grantId"));
            boolean available = Boolean.TRUE.equals(grant.get("available"));
            String name = text(grant.get("name"), "Referenced location");
            String summary = available ? "Referenced in place on this device · zero-copy"
                    : "Source unavailable · Android permission or provider is unavailable";
            if ("FILE".equalsIgnoreCase(text(grant.get("kind")))) {
                result.add(fileRow(DocumentId.localReferenceFile(grantId, ""), name,
                        text(grant.get("mimeType"), mime(name)), number(grant.get("size"), 0L),
                        parseTimeMillis(grant.get("modified")), summary));
            } else {
                result.add(directoryRow(DocumentId.localReferenceDir(grantId, ""), name, summary, !available));
            }
        }
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> localReferenceChildren(String grantId, String relativeDirectory) throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map<String,Object> entry : externalReferences.browseOwnerReference(grantId, relativeDirectory)) {
            String path = text(entry.get("path"));
            String name = text(entry.get("name"), lastSegment(path));
            String kind = text(entry.get("kind"));
            if ("FOLDER".equalsIgnoreCase(kind)) {
                result.add(directoryRow(DocumentId.localReferenceDir(grantId, path), name,
                        "Referenced in place on this device · zero-copy", false));
            } else if ("FILE".equalsIgnoreCase(kind)) {
                result.add(fileRow(DocumentId.localReferenceFile(grantId, path), name,
                        text(entry.get("mimeType"), mime(name)), number(entry.get("size"), 0L),
                        parseTimeMillis(entry.get("modified")), "Referenced in place on this device · zero-copy"));
            }
        }
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> managedRows(String peerId) throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map<String,Object> file : managedFiles(peerId)) result.add(remoteManagedFileRow(peerId, file, Boolean.TRUE.equals(file.get("stale"))));
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> filesystemRoots(String peerId) throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map<String,Object> root : NetworkPeerConnector.listFilesystemRoots(endpoint(peerId),
                requireMembership(), trustedCa())) {
            String rootId = text(root.get("rootId"));
            if (rootId.isBlank()) continue;
            String name = text(root.get("name"), "Storage");
            result.add(directoryRow(DocumentId.filesystemRoot(peerId, rootId), name,
                    "Owner's eligible storage · writable", false, DIRECTORY_WRITE_FLAGS));
        }
        sortRows(result);
        return result;
    }

    private List<Map<String,Object>> filesystemChildren(String peerId, String rootId, String relativePath)
            throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        for (Map<String,Object> entry : NetworkPeerConnector.browseFilesystem(endpoint(peerId), rootId,
                relativePath, requireMembership(), trustedCa())) {
            String name = text(entry.get("name"));
            if (name.isEmpty()) continue;
            String path = text(entry.get("path"), relativePath.isEmpty() ? name : relativePath + "/" + name);
            if ("DIRECTORY".equalsIgnoreCase(text(entry.get("kind")))) {
                result.add(directoryRow(DocumentId.filesystemDir(peerId, rootId, path), name,
                        "Owner's eligible storage · writable", false, DIRECTORY_WRITE_FLAGS));
            } else {
                result.add(fileRow(DocumentId.filesystemFile(peerId, rootId, path), name,
                        text(entry.get("mimeType"), mime(name)), number(entry.get("size"), 0L),
                        parseTimeMillis(entry.get("modified")), "Owner's eligible storage · writable",
                        FILE_WRITE_FLAGS));
            }
        }
        sortRows(result);
        return result;
    }

    private String filesystemRootName(String peerId, String rootId) throws Exception {
        for (Map<String,Object> root : NetworkPeerConnector.listFilesystemRoots(endpoint(peerId),
                requireMembership(), trustedCa())) {
            if (rootId.equals(text(root.get("rootId")))) return text(root.get("name"), "Storage");
        }
        throw new FileNotFoundException("The eligible storage root is no longer available.");
    }

    private ParcelFileDescriptor openFilesystemDocument(DocumentId id, String mode, CancellationSignal signal)
            throws Exception {
        boolean read = mode != null && mode.indexOf('r') >= 0;
        boolean write = mode != null && mode.indexOf('w') >= 0;
        if (!read && !write) throw new FileNotFoundException("Unsupported document mode: " + mode);
        NetworkMembershipClient membership = requireMembership();
        String peerEndpoint = endpoint(id.peerId);
        String ca = trustedCa();
        Map<String,Object> metadata = NetworkPeerConnector.statFilesystem(peerEndpoint, id.grantId, id.path,
                membership, ca);
        if ("DIRECTORY".equalsIgnoreCase(text(metadata.get("kind")))) {
            throw new FileNotFoundException("Only file documents can be opened.");
        }
        long size = number(metadata.get("size"), -1L);
        if (size < 0) throw new FileNotFoundException("The owner did not report a valid file size.");
        StorageManager storage = appContext().getSystemService(StorageManager.class);
        if (storage == null) throw new IllegalStateException("Android proxy file descriptors are unavailable on this device.");
        if (!write) {
            return storage.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY,
                    new FilesystemReadCallback(peerEndpoint, id.grantId, id.path, membership, ca, size, signal),
                    proxyHandler);
        }
        if (size > MAX_STAGED_BYTES) {
            throw new FileNotFoundException("This file is too large to edit through this device ("
                    + size + " bytes; limit " + MAX_STAGED_BYTES + ").");
        }
        Path staging = Files.createTempFile("personalcloud-fs-", ".part");
        boolean truncate = mode.indexOf('t') >= 0;
        try {
            if (!truncate) downloadFilesystemFile(peerEndpoint, id.grantId, id.path, staging, membership, ca, size);
            int descriptorMode = read ? ParcelFileDescriptor.MODE_READ_WRITE : ParcelFileDescriptor.MODE_WRITE_ONLY;
            return storage.openProxyFileDescriptor(descriptorMode,
                    new FilesystemWriteCallback(peerEndpoint, id.grantId, id.path, staging, membership, ca, signal, truncate),
                    proxyHandler);
        } catch (Exception failure) {
            Files.deleteIfExists(staging);
            throw failure;
        }
    }

    private static void downloadFilesystemFile(String peerEndpoint, String rootId, String relativePath,
                                               Path staging, NetworkMembershipClient membership, String ca,
                                               long expectedSize) throws Exception {
        try (java.io.OutputStream output = Files.newOutputStream(staging,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING, java.nio.file.StandardOpenOption.WRITE)) {
            long offset = 0;
            while (offset < expectedSize) {
                int chunk = (int) Math.min((long) RANGE_CHUNK, expectedSize - offset);
                PeerConnector.RangeResult result = NetworkPeerConnector.readFilesystemRange(peerEndpoint, rootId,
                        relativePath, offset, chunk, membership, ca);
                if (result.totalSize != expectedSize) {
                    throw new java.io.IOException("Remote file size changed while it was being staged.");
                }
                if (result.bytes.length != chunk) {
                    throw new java.io.IOException("Remote file ended before its declared size.");
                }
                output.write(result.bytes);
                offset += chunk;
            }
        }
        if (Files.size(staging) != expectedSize) throw new java.io.IOException("Staged file size does not match the owner metadata.");
    }

    private Map<String,Object> document(String documentId) throws Exception {
        if (DOC_ROOT.equals(documentId)) return directoryRow(DOC_ROOT, "PersonalCloud", "Private device network", false);
        if (DOC_LOCAL.equals(documentId)) return directoryRow(DOC_LOCAL, "This device", "Phone-owned storage", false);
        if (DOC_LOCAL_REFERENCES.equals(documentId)) return directoryRow(DOC_LOCAL_REFERENCES,
                "Referenced items", "Existing Android files and folders · no copy", false);
        DocumentId id = DocumentId.parse(documentId);
        if (id.type.equals("localdir")) {
            Path path = localPath(id.path);
            return directoryRow(documentId, path.getFileName() == null ? "This device" : path.getFileName().toString(), "On this device", false);
        }
        if (id.type.equals("localfile")) {
            Path path = localPath(id.path);
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new FileNotFoundException("Local file not found.");
            return fileRow(documentId, path.getFileName().toString(), mime(path), Files.size(path),
                    Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toMillis(), "On this device");
        }
        if (id.type.equals("localrefdir") || id.type.equals("localreffile")) {
            Map<String,Object> metadata = externalReferences.statOwnerReference(id.grantId, id.path);
            String name = text(metadata.get("name"), lastSegment(id.path));
            if ("FOLDER".equalsIgnoreCase(text(metadata.get("kind")))) {
                return directoryRow(documentId, name, "Referenced in place on this device · zero-copy", false);
            }
            return fileRow(documentId, name, text(metadata.get("mimeType"), mime(name)),
                    number(metadata.get("size"), 0L), parseTimeMillis(metadata.get("modified")),
                    "Referenced in place on this device · zero-copy");
        }
        if (id.type.equals("peer")) {
            Map<String,Object> member = findMember(id.peerId);
            boolean stale = Boolean.FALSE.equals(member.get("online"));
            return directoryRow(documentId, text(member.get("nodeName"), "PersonalCloud device"),
                    stale ? "Offline · cached metadata" : "Private network member", stale);
        }
        if (id.type.equals("refs")) return directoryRow(documentId, "References", "Existing files shared by this device", false);
        if (id.type.equals("managed")) return directoryRow(documentId, "Distributed-Storage", "Whole files stored on this device", false);
        if (id.type.equals("refdir")) {
            Map<String,Object> metadata = referenceMetadata(id.peerId, id.grantId, id.path);
            return directoryRow(documentId, text(metadata.get("name"), lastSegment(id.path)),
                    Boolean.TRUE.equals(metadata.get("stale")) ? "Offline · cached metadata · unavailable" : "Remote folder",
                    Boolean.TRUE.equals(metadata.get("stale")));
        }
        if (id.type.equals("reffile")) {
            Map<String,Object> metadata = referenceMetadata(id.peerId, id.grantId, id.path);
            return remoteReferenceFileRow(id.peerId, metadata, Boolean.TRUE.equals(metadata.get("stale")));
        }
        if (id.type.equals("managedfile")) {
            Map<String,Object> metadata = managedMetadata(id.peerId, id.fileId);
            return remoteManagedFileRow(id.peerId, metadata, Boolean.TRUE.equals(metadata.get("stale")));
        }
        if (id.type.equals("fss")) {
            return directoryRow(documentId, "Filesystem", "Owner's actual files and folders · writable", false);
        }
        if (id.type.equals("fsroot")) {
            return directoryRow(documentId, filesystemRootName(id.peerId, id.grantId),
                    "Owner's eligible storage · writable", false, DIRECTORY_WRITE_FLAGS);
        }
        if (id.type.equals("fsdir")) {
            Map<String,Object> metadata = NetworkPeerConnector.statFilesystem(endpoint(id.peerId), id.grantId,
                    id.path, requireMembership(), trustedCa());
            if (!"DIRECTORY".equalsIgnoreCase(text(metadata.get("kind")))) {
                throw new FileNotFoundException("The remote path is not a directory.");
            }
            return directoryRow(documentId, text(metadata.get("name"), lastSegment(id.path)),
                    "Owner's eligible storage · writable", false, DIRECTORY_WRITE_FLAGS);
        }
        if (id.type.equals("fsfile")) {
            Map<String,Object> metadata = NetworkPeerConnector.statFilesystem(endpoint(id.peerId), id.grantId,
                    id.path, requireMembership(), trustedCa());
            if ("DIRECTORY".equalsIgnoreCase(text(metadata.get("kind")))) {
                throw new FileNotFoundException("The remote path is not a file.");
            }
            String name = text(metadata.get("name"), lastSegment(id.path));
            return fileRow(documentId, name, text(metadata.get("mimeType"), mime(name)),
                    number(metadata.get("size"), 0L), parseTimeMillis(metadata.get("modified")),
                    "Owner's eligible storage · writable", FILE_WRITE_FLAGS);
        }
        throw new FileNotFoundException("Unknown PersonalCloud document identifier.");
    }

    private List<Map<String,Object>> peers() throws Exception {
        NetworkMembershipClient membership = membership();
        if (membership != null && Boolean.TRUE.equals(membership.status().get("joined"))) {
            List<Map<String,Object>> remote = new ArrayList<>();
            String self = text(membership.status().get("nodeId"));
            for (Map<String,Object> member : membership.members()) {
                if (self.equals(member.get("nodeId")) || !"ACTIVE".equals(text(member.get("status")))) continue;
                remote.add(new LinkedHashMap<>(member));
            }
            cacheRows(MEMBER_CACHE, remote);
            return remote;
        }
        return cachedRows(MEMBER_CACHE);
    }

    private List<Map<String,Object>> referenceGrants(String peerId) throws Exception {
        String key = refsCacheKey(peerId);
        try {
            NetworkMembershipClient membership = requireMembership();
            List<Map<String,Object>> rows = NetworkPeerConnector.listReferences(endpoint(peerId), membership, trustedCa());
            cacheRows(key, rows);
            return rows;
        } catch (Exception unavailable) { return cachedRows(key); }
    }

    private List<Map<String,Object>> browseReference(String peerId, String grantId, String path) throws Exception {
        String key = browseCacheKey(peerId, grantId, path);
        try {
            List<Map<String,Object>> rows = NetworkPeerConnector.browseReference(endpoint(peerId), grantId, path,
                    requireMembership(), trustedCa());
            cacheRows(key, rows);
            return rows;
        } catch (Exception unavailable) { return cachedRows(key); }
    }

    private List<Map<String,Object>> managedFiles(String peerId) throws Exception {
        String key = managedCacheKey(peerId);
        try {
            List<Map<String,Object>> rows = NetworkPeerConnector.listManagedFiles(endpoint(peerId), requireMembership(), trustedCa());
            cacheRows(key, rows);
            for (Map<String,Object> row : rows) {
                String fileId = text(row.get("fileId"));
                if (!fileId.isBlank()) cacheMap(managedMetadataCacheKey(peerId, fileId), row);
            }
            return rows;
        } catch (Exception unavailable) { return cachedRows(key); }
    }

    private Map<String,Object> referenceMetadata(String peerId, String grantId, String path) throws Exception {
        String key = refMetadataCacheKey(peerId, grantId, path);
        try {
            Map<String,Object> row = NetworkPeerConnector.statReference(endpoint(peerId), grantId, path,
                    requireMembership(), trustedCa());
            row.put("grantId", grantId);
            row.put("permission", permissionFor(peerId, grantId));
            cacheMap(key, row);
            return row;
        } catch (Exception unavailable) {
            Map<String,Object> row = cachedMap(key);
            if (row.isEmpty()) throw unavailable;
            row.put("stale", true);
            return row;
        }
    }

    private Map<String,Object> managedMetadata(String peerId, String fileId) throws Exception {
        String key = managedMetadataCacheKey(peerId, fileId);
        try {
            Map<String,Object> row = NetworkPeerConnector.statManagedFile(endpoint(peerId), fileId,
                    requireMembership(), trustedCa());
            cacheMap(key, row);
            return row;
        } catch (Exception unavailable) {
            Map<String,Object> row = cachedMap(key);
            if (row.isEmpty()) throw unavailable;
            row.put("stale", true);
            return row;
        }
    }

    private void cacheReferenceMetadata(String peerId, String grantId, String path, Map<String,Object> row) {
        try {
            Map<String,Object> copy = new LinkedHashMap<>(row);
            copy.put("grantId", grantId);
            cacheMap(refMetadataCacheKey(peerId, grantId, path), copy);
        } catch (Exception ignored) { }
    }

    private String permissionFor(String peerId, String grantId) throws Exception {
        if (grantId == null || grantId.isBlank()) return "DOWNLOAD";
        for (Map<String,Object> grant : referenceGrants(peerId)) if (grantId.equals(grant.get("grantId"))) return text(grant.get("permission"));
        return "DOWNLOAD";
    }

    private List<Map<String,Object>> searchLocal(String needle) throws Exception {
        List<Map<String,Object>> result = new ArrayList<>();
        Path root = localRoot();
        if (!Files.isDirectory(root)) return result;
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            paths.filter(path -> !path.equals(root) && !Files.isSymbolicLink(path)
                    && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).contains(needle))
                    .limit(200).forEach(path -> {
                        try {
                            String relative = root.relativize(path).toString().replace('\\', '/');
                            result.add(fileRow(DocumentId.localFile(relative), path.getFileName().toString(), mime(path),
                                    Files.size(path), Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toMillis(), "On this device"));
                        } catch (Exception ignored) { }
                    });
        }
        return result;
    }

    private Map<String,Object> remoteReferenceFileRow(String peerId, Map<String,Object> reference, boolean stale) {
        String grantId = text(reference.get("grantId"));
        String path = text(reference.get("path"));
        String name = text(reference.get("name"), lastSegment(path));
        long modified = parseTimeMillis(reference.get("modified"));
        String permission = text(reference.get("permission"), "DOWNLOAD");
        String summary = stale ? "Offline · cached metadata · file unavailable"
                : ("DOWNLOAD+DELETE".equals(permission) ? "Remote file · delete permission granted" : "Remote file · fetched on demand");
        int flags = !stale && "DOWNLOAD+DELETE".equals(permission)
                ? DocumentsContract.Document.FLAG_SUPPORTS_DELETE : 0;
        return fileRow(DocumentId.referenceFile(peerId, grantId, path), name, mime(name),
                number(reference.get("size"), 0L), modified, summary, flags);
    }

    private Map<String,Object> remoteManagedFileRow(String peerId, Map<String,Object> file, boolean stale) {
        String fileId = text(file.get("fileId"));
        String name = text(file.get("name"), lastSegment(text(file.get("path"))));
        String summary = stale ? "Offline · cached metadata · file unavailable" : "Distributed file · fetched on demand";
        int flags = stale ? 0 : DocumentsContract.Document.FLAG_SUPPORTS_DELETE;
        return fileRow(DocumentId.managedFile(peerId, fileId), name, mime(name),
                number(file.get("size"), 0L), parseTimeMillis(file.get("modified")), summary, flags);
    }

    private NetworkMembershipClient membership() throws Exception {
        NetworkMembershipClient current = PeerRuntime.membership;
        if (current != null) return current;
        String nodeId = stateStore.getConfig("node_id");
        String nodeName = stateStore.getConfig("node_name");
        if (nodeId.isBlank() || nodeName.isBlank()) return null;
        NetworkMembershipClient restored = NetworkMembershipClient.restore(stateStore, nodeId, nodeName);
        if (restored != null) PeerRuntime.membership = restored;
        return restored;
    }

    private NetworkMembershipClient requireMembership() throws Exception {
        NetworkMembershipClient value = membership();
        if (value == null || !Boolean.TRUE.equals(value.status().get("joined"))) {
            throw new IllegalStateException("This Android device has not joined a private PersonalCloud network.");
        }
        return value;
    }

    private String endpoint(String peerId) throws Exception {
        return NetworkPeerConnector.activeEndpoint(requireMembership(), peerId);
    }

    private String trustedCa() throws Exception {
        String value = stateStore.getConfig("peer_ca");
        if (value.isBlank() || !Files.isRegularFile(java.nio.file.Paths.get(value))) {
            throw new IllegalStateException("Import the trusted PersonalCloud network CA certificate before opening remote files.");
        }
        return value;
    }

    private Map<String,Object> findMember(String peerId) throws Exception {
        for (Map<String,Object> member : peers()) if (peerId.equals(member.get("nodeId"))) return member;
        throw new FileNotFoundException("This device is no longer an active PersonalCloud network member.");
    }

    private Path localRoot() throws Exception {
        Path root = java.nio.file.Paths.get(appContext().getFilesDir().getAbsolutePath(), "node-storage").toAbsolutePath().normalize();
        Files.createDirectories(root);
        return root;
    }

    private Path localPath(String relative) throws Exception {
        Path root = localRoot();
        Path input = relative.isEmpty() ? root : java.nio.file.Paths.get(relative);
        if (input.isAbsolute()) throw new SecurityException("Absolute paths are not accepted.");
        Path target = root.resolve(input).normalize();
        if (!target.startsWith(root)) throw new SecurityException("Local document path escapes PersonalCloud storage.");
        Path current = root;
        if (!relative.isEmpty()) for (Path part : root.relativize(target)) {
            current = current.resolve(part);
            if (Files.isSymbolicLink(current)) throw new SecurityException("Symbolic links are not exposed through PersonalCloud Documents.");
        }
        return target;
    }

    private void invalidateReferenceCaches(String peerId, String grantId, String path) {
        String parent = "";
        int slash = path == null ? -1 : path.lastIndexOf('/');
        if (slash >= 0) parent = path.substring(0, slash);
        try { stateStore.putConfig(browseCacheKey(peerId, grantId, parent), "[]"); } catch (Exception ignored) { }
        try { stateStore.putConfig(refMetadataCacheKey(peerId, grantId, path), ""); } catch (Exception ignored) { }
        try { stateStore.putConfig(searchCacheKey(peerId), "[]"); } catch (Exception ignored) { }
    }

    private void invalidateManagedCaches(String peerId, String fileId) {
        try { stateStore.putConfig(managedCacheKey(peerId), "[]"); } catch (Exception ignored) { }
        try { stateStore.putConfig(managedMetadataCacheKey(peerId, fileId), ""); } catch (Exception ignored) { }
        try { stateStore.putConfig(searchCacheKey(peerId), "[]"); } catch (Exception ignored) { }
    }

    private void cacheRows(String key, List<Map<String,Object>> rows) {
        try { stateStore.putConfig(key, Json.stringify(rows)); } catch (Exception ignored) { }
    }

    private List<Map<String,Object>> cachedRows(String key) {
        try {
            String value = stateStore.getConfig(key);
            if (value.isBlank()) return Collections.emptyList();
            Object parsed = Json.parse(value);
            if (!(parsed instanceof List<?> list)) return Collections.emptyList();
            List<Map<String,Object>> result = new ArrayList<>();
            for (Object item : list) if (item instanceof Map<?,?> map) {
                Map<String,Object> row = new LinkedHashMap<>();
                for (Map.Entry<?,?> entry : map.entrySet()) row.put(String.valueOf(entry.getKey()), entry.getValue());
                row.put("stale", true);
                result.add(row);
            }
            return result;
        } catch (Exception ignored) { return Collections.emptyList(); }
    }

    private void cacheMap(String key, Map<String,Object> row) {
        try { stateStore.putConfig(key, Json.stringify(row)); } catch (Exception ignored) { }
    }

    private Map<String,Object> cachedMap(String key) {
        try {
            String value = stateStore.getConfig(key);
            if (value.isBlank()) return new LinkedHashMap<>();
            Map<String,Object> row = new LinkedHashMap<>(Json.object(value));
            row.put("stale", true);
            return row;
        } catch (Exception ignored) { return new LinkedHashMap<>(); }
    }

    private static Map<String,Object> findGrant(List<Map<String,Object>> grants, String grantId) throws FileNotFoundException {
        return grants.stream().filter(row -> grantId.equals(text(row.get("grantId")))).findFirst()
                .orElseThrow(() -> new FileNotFoundException("The reference grant was revoked or is no longer available."));
    }

    private static Map<String,Object> directoryRow(String id, String name, String summary, boolean stale) {
        return directoryRow(id, name, summary, stale, 0);
    }

    private static Map<String,Object> directoryRow(String id, String name, String summary, boolean stale, int flags) {
        Map<String,Object> row = new LinkedHashMap<>();
        row.put(DocumentsContract.Document.COLUMN_DOCUMENT_ID, id);
        row.put(DocumentsContract.Document.COLUMN_DISPLAY_NAME, name);
        row.put(DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.MIME_TYPE_DIR);
        row.put(DocumentsContract.Document.COLUMN_FLAGS, flags);
        row.put(DocumentsContract.Document.COLUMN_SIZE, null);
        row.put(DocumentsContract.Document.COLUMN_LAST_MODIFIED, null);
        row.put(DocumentsContract.Document.COLUMN_SUMMARY, summary);
        return row;
    }

    private static Map<String,Object> fileRow(String id, String name, String mime, long size, long modified, String summary) {
        return fileRow(id, name, mime, size, modified, summary, 0);
    }

    private static Map<String,Object> fileRow(String id, String name, String mime, long size, long modified,
                                               String summary, int flags) {
        Map<String,Object> row = new LinkedHashMap<>();
        row.put(DocumentsContract.Document.COLUMN_DOCUMENT_ID, id);
        row.put(DocumentsContract.Document.COLUMN_DISPLAY_NAME, name);
        row.put(DocumentsContract.Document.COLUMN_MIME_TYPE, mime);
        row.put(DocumentsContract.Document.COLUMN_FLAGS, flags);
        row.put(DocumentsContract.Document.COLUMN_SIZE, size);
        row.put(DocumentsContract.Document.COLUMN_LAST_MODIFIED, modified <= 0 ? null : modified);
        row.put(DocumentsContract.Document.COLUMN_SUMMARY, summary);
        return row;
    }

    private static String[] columns(String[] projection, String[] defaults) {
        return projection == null || projection.length == 0 ? defaults : projection;
    }

    private static void addRow(MatrixCursor cursor, Map<String,Object> row) {
        String[] columns = cursor.getColumnNames();
        Object[] values = new Object[columns.length];
        for (int i = 0; i < columns.length; i++) values[i] = row.get(columns[i]);
        cursor.addRow(values);
    }

    private android.content.Context appContext() {
        android.content.Context context = getContext();
        if (context == null) throw new IllegalStateException("PersonalCloud DocumentsProvider is not attached to a context.");
        return context;
    }

    private String authority() { return appContext().getPackageName() + AUTHORITY_SUFFIX; }
    private static String refsCacheKey(String peer) { return "documents.network.refs." + encode(peer); }
    private static String managedCacheKey(String peer) { return "documents.network.managed." + encode(peer); }
    private static String searchCacheKey(String peer) { return "documents.network.search." + encode(peer); }
    private static String browseCacheKey(String peer, String grant, String path) { return "documents.network.browse." + encode(peer) + "." + encode(grant) + "." + encode(path); }
    private static String refMetadataCacheKey(String peer, String grant, String path) { return "documents.network.refmeta." + encode(peer) + "." + encode(grant) + "." + encode(path); }
    private static String managedMetadataCacheKey(String peer, String file) { return "documents.network.managedmeta." + encode(peer) + "." + encode(file); }
    private static boolean isPathWithin(String parent, String child) { return child != null && parent != null && (parent.isEmpty() ? !child.isEmpty() : child.startsWith(parent + "/")); }
    private static void sortRows(List<Map<String,Object>> rows) {
        rows.sort(Comparator.comparing((Map<String,Object> row) -> DocumentsContract.Document.MIME_TYPE_DIR.equals(row.get(DocumentsContract.Document.COLUMN_MIME_TYPE)) ? 0 : 1)
                .thenComparing(row -> text(row.get(DocumentsContract.Document.COLUMN_DISPLAY_NAME)).toLowerCase(Locale.ROOT)));
    }
    private static boolean safeParseType(String id, String type) {
        try { return DocumentId.parse(id).type.equals(type); } catch (Exception ignored) { return false; }
    }
    private static long parseTimeMillis(Object value) {
        if (value instanceof Number n) return n.longValue();
        try { return java.time.Instant.parse(String.valueOf(value)).toEpochMilli(); }
        catch (Exception ignored) { return 0L; }
    }
    private static long number(Object value, long fallback) { return value instanceof Number n ? n.longValue() : fallback; }
    private static String lastSegment(String path) { if (path == null || path.isEmpty()) return ""; int i = path.lastIndexOf('/'); return i < 0 ? path : path.substring(i + 1); }
    private static String encode(String value) { return Base64.getUrlEncoder().withoutPadding().encodeToString((value == null ? "" : value).getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
    private static String decode(String value) { return new String(Base64.getUrlDecoder().decode(value), java.nio.charset.StandardCharsets.UTF_8); }
    private static String text(Object value) { return value == null ? "" : String.valueOf(value); }
    private static String text(Object value, String fallback) { String result = text(value); return result.isBlank() ? fallback : result; }
    private static String mime(Path path) { return mime(path.getFileName() == null ? "" : path.getFileName().toString()); }
    private static String mime(String name) {
        String extension = ""; int dot = name.lastIndexOf('.');
        if (dot >= 0 && dot + 1 < name.length()) extension = name.substring(dot + 1).toLowerCase(Locale.ROOT);
        String type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
        return type == null ? "application/octet-stream" : type;
    }
    private static String safe(Exception error) { return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage(); }
    private static FileNotFoundException fileNotFound(String message, Throwable cause) {
        FileNotFoundException error = new FileNotFoundException(message); if (cause != null) error.initCause(cause); return error;
    }

    private static final class DocumentId {
        final String type, peerId, grantId, fileId, path;
        DocumentId(String type, String peerId, String grantId, String fileId, String path) {
            this.type=type; this.peerId=peerId; this.grantId=grantId; this.fileId=fileId; this.path=path;
        }
        static String peer(String peer) { return "peer|" + encode(peer); }
        static String refs(String peer) { return "refs|" + encode(peer); }
        static String managed(String peer) { return "managed|" + encode(peer); }
        static String referenceDir(String peer, String grant, String path) { return "refdir|" + encode(peer) + "|" + encode(grant) + "|" + encode(path); }
        static String referenceFile(String peer, String grant, String path) { return "reffile|" + encode(peer) + "|" + encode(grant) + "|" + encode(path); }
        static String managedFile(String peer, String file) { return "managedfile|" + encode(peer) + "|" + encode(file); }
        static String filesystem(String peer) { return "fss|" + encode(peer); }
        static String filesystemRoot(String peer, String root) { return "fsroot|" + encode(peer) + "|" + encode(root); }
        static String filesystemDir(String peer, String root, String path) { return "fsdir|" + encode(peer) + "|" + encode(root) + "|" + encode(path); }
        static String filesystemFile(String peer, String root, String path) { return "fsfile|" + encode(peer) + "|" + encode(root) + "|" + encode(path); }
        static String localDir(String path) { return "localdir|" + encode(path); }
        static String localFile(String path) { return "localfile|" + encode(path); }
        static String localReferenceDir(String grant, String path) { return "localrefdir|" + encode(grant) + "|" + encode(path); }
        static String localReferenceFile(String grant, String path) { return "localreffile|" + encode(grant) + "|" + encode(path); }
        static DocumentId parse(String value) throws FileNotFoundException {
            String[] fields = value.split("\\|", -1);
            try {
                return switch (fields[0]) {
                    case "peer" -> new DocumentId("peer", decode(fields[1]), "", "", "");
                    case "refs" -> new DocumentId("refs", decode(fields[1]), "", "", "");
                    case "managed" -> new DocumentId("managed", decode(fields[1]), "", "", "");
                    case "refdir" -> new DocumentId("refdir", decode(fields[1]), decode(fields[2]), "", decode(fields[3]));
                    case "reffile" -> new DocumentId("reffile", decode(fields[1]), decode(fields[2]), "", decode(fields[3]));
                    case "managedfile" -> new DocumentId("managedfile", decode(fields[1]), "", decode(fields[2]), "");
                    case "fss" -> new DocumentId("fss", decode(fields[1]), "", "", "");
                    case "fsroot" -> new DocumentId("fsroot", decode(fields[1]), decode(fields[2]), "", "");
                    case "fsdir" -> new DocumentId("fsdir", decode(fields[1]), decode(fields[2]), "", decode(fields[3]));
                    case "fsfile" -> new DocumentId("fsfile", decode(fields[1]), decode(fields[2]), "", decode(fields[3]));
                    case "localdir" -> new DocumentId("localdir", "", "", "", decode(fields[1]));
                    case "localfile" -> new DocumentId("localfile", "", "", "", decode(fields[1]));
                    case "localrefdir" -> new DocumentId("localrefdir", "", decode(fields[1]), "", decode(fields[2]));
                    case "localreffile" -> new DocumentId("localreffile", "", decode(fields[1]), "", decode(fields[2]));
                    default -> throw new IllegalArgumentException("Unknown document ID type.");
                };
            } catch (Exception invalid) { throw fileNotFound("Invalid PersonalCloud document ID.", invalid); }
        }
    }

    private static final class LocalReferenceFileCallback extends ProxyFileDescriptorCallback {
        private final ExternalReferenceStore.NetworkReferenceContent content;
        private final long totalSize;
        private final CancellationSignal cancellation;

        LocalReferenceFileCallback(ExternalReferenceStore.NetworkReferenceContent content, long totalSize,
                                   CancellationSignal cancellation) {
            this.content = content;
            this.totalSize = totalSize;
            this.cancellation = cancellation;
        }

        @Override public long onGetSize() { return totalSize; }

        @Override public int onRead(long offset, int size, byte[] data) throws ErrnoException {
            if (offset < 0 || size < 0) throw new ErrnoException("read", OsConstants.EINVAL);
            if (size == 0 || offset >= totalSize) return 0;
            if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("read", OsConstants.ECANCELED);
            int requested = (int) Math.min((long) size, totalSize - offset);
            try (java.io.InputStream input = content.openRange(offset, requested)) {
                int copied = 0;
                while (copied < requested) {
                    if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("read", OsConstants.ECANCELED);
                    int read = input.read(data, copied, requested - copied);
                    if (read < 0) throw new java.io.EOFException("Android source document ended before the requested range.");
                    if (read == 0) continue;
                    copied += read;
                }
                if (input.read() != -1) throw new java.io.IOException("Android source document exceeded the requested range.");
                return copied;
            } catch (ErrnoException error) {
                throw error;
            } catch (Exception error) {
                ErrnoException failure = new ErrnoException("read", OsConstants.EIO);
                failure.initCause(error);
                throw failure;
            }
        }
        @Override public void onRelease() { /* Each read opens and closes its own range stream. */ }
    }

    private static final class NetworkFileCallback extends ProxyFileDescriptorCallback {
        private final DocumentId id;
        private final String endpoint, trustedCa;
        private final NetworkMembershipClient membership;
        private final long totalSize;
        private final CancellationSignal cancellation;
        NetworkFileCallback(DocumentId id, String endpoint, NetworkMembershipClient membership,
                            String trustedCa, long totalSize, CancellationSignal cancellation) {
            this.id=id; this.endpoint=endpoint; this.membership=membership; this.trustedCa=trustedCa;
            this.totalSize=totalSize; this.cancellation=cancellation;
        }
        @Override public long onGetSize() { return totalSize; }
        @Override public int onRead(long offset, int size, byte[] data) throws ErrnoException {
            if (offset < 0 || size < 0) throw new ErrnoException("read", OsConstants.EINVAL);
            if (size == 0 || offset >= totalSize) return 0;
            if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("read", OsConstants.ECANCELED);
            int requested = (int) Math.min((long) size, totalSize - offset);
            int copied = 0;
            try {
                while (copied < requested) {
                    if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("read", OsConstants.ECANCELED);
                    int chunk = Math.min(RANGE_CHUNK, requested - copied);
                    PeerConnector.RangeResult result = id.type.equals("reffile")
                            ? NetworkPeerConnector.readReferenceRange(endpoint, id.grantId, id.path,
                                    offset + copied, chunk, membership, trustedCa)
                            : NetworkPeerConnector.readManagedRange(endpoint, id.fileId,
                                    offset + copied, chunk, membership, trustedCa);
                    if (result.totalSize != totalSize) throw new java.io.IOException("Remote file size changed while it was open.");
                    if (result.bytes.length == 0) break;
                    System.arraycopy(result.bytes, 0, data, copied, result.bytes.length);
                    copied += result.bytes.length;
                    if (result.bytes.length < chunk) break;
                }
                return copied;
            } catch (ErrnoException error) { throw error; }
            catch (Exception error) {
                ErrnoException failure = new ErrnoException("read", OsConstants.EIO);
                failure.initCause(error); throw failure;
            }
        }
        @Override public void onRelease() { /* No descriptor-level network resource is retained. */ }
    }

    private static final class FilesystemReadCallback extends ProxyFileDescriptorCallback {
        private final String endpoint, rootId, path, trustedCa;
        private final NetworkMembershipClient membership;
        private final long totalSize;
        private final CancellationSignal cancellation;

        FilesystemReadCallback(String endpoint, String rootId, String path, NetworkMembershipClient membership,
                               String trustedCa, long totalSize, CancellationSignal cancellation) {
            this.endpoint = endpoint; this.rootId = rootId; this.path = path; this.membership = membership;
            this.trustedCa = trustedCa; this.totalSize = totalSize; this.cancellation = cancellation;
        }

        @Override public long onGetSize() { return totalSize; }

        @Override public int onRead(long offset, int size, byte[] data) throws ErrnoException {
            if (offset < 0 || size < 0) throw new ErrnoException("read", OsConstants.EINVAL);
            if (size == 0 || offset >= totalSize) return 0;
            if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("read", OsConstants.ECANCELED);
            int requested = (int) Math.min((long) size, totalSize - offset);
            int copied = 0;
            try {
                while (copied < requested) {
                    if (cancellation != null && cancellation.isCanceled()) {
                        throw new ErrnoException("read", OsConstants.ECANCELED);
                    }
                    int chunk = Math.min(RANGE_CHUNK, requested - copied);
                    PeerConnector.RangeResult result = NetworkPeerConnector.readFilesystemRange(endpoint, rootId, path,
                            offset + copied, chunk, membership, trustedCa);
                    if (result.totalSize != totalSize) {
                        throw new java.io.IOException("Remote file size changed while it was open.");
                    }
                    if (result.bytes.length == 0) break;
                    System.arraycopy(result.bytes, 0, data, copied, result.bytes.length);
                    copied += result.bytes.length;
                    if (result.bytes.length < chunk) break;
                }
                return copied;
            } catch (ErrnoException error) {
                throw error;
            } catch (Exception error) {
                ErrnoException failure = new ErrnoException("read", OsConstants.EIO);
                failure.initCause(error);
                throw failure;
            }
        }

        @Override public void onRelease() { /* Each read opens and closes its own range stream. */ }
    }

    /**
     * Staging-backed writable callback. Bytes are committed to the owner only on
     * fsync/release; an interrupted edit leaves the original remote file intact.
     */
    private static final class FilesystemWriteCallback extends ProxyFileDescriptorCallback {
        private final String endpoint, rootId, path, trustedCa;
        private final Path staging;
        private final NetworkMembershipClient membership;
        private final CancellationSignal cancellation;
        private boolean dirty;
        private boolean released;

        FilesystemWriteCallback(String endpoint, String rootId, String path, Path staging,
                                NetworkMembershipClient membership, String trustedCa,
                                CancellationSignal cancellation, boolean truncate) {
            this.endpoint = endpoint; this.rootId = rootId; this.path = path; this.staging = staging;
            this.membership = membership; this.trustedCa = trustedCa; this.cancellation = cancellation;
            // A truncating open must publish the empty staging even if no bytes are written.
            this.dirty = truncate;
        }

        @Override public synchronized long onGetSize() throws ErrnoException {
            try { return Files.size(staging); }
            catch (Exception error) { throw failure("getattr", error); }
        }

        @Override public synchronized int onRead(long offset, int size, byte[] data) throws ErrnoException {
            if (offset < 0 || size < 0) throw new ErrnoException("read", OsConstants.EINVAL);
            if (size == 0) return 0;
            if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("read", OsConstants.ECANCELED);
            try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(staging,
                    java.nio.file.StandardOpenOption.READ)) {
                long fileSize = channel.size();
                if (offset >= fileSize) return 0;
                int requested = (int) Math.min((long) size, fileSize - offset);
                java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(data, 0, requested);
                channel.position(offset);
                int total = 0;
                while (buffer.hasRemaining()) {
                    int read = channel.read(buffer);
                    if (read < 0) break;
                    total += read;
                }
                return total;
            } catch (Exception error) { throw failure("read", error); }
        }

        @Override public synchronized int onWrite(long offset, int size, byte[] data) throws ErrnoException {
            if (offset < 0 || size < 0) throw new ErrnoException("write", OsConstants.EINVAL);
            if (size == 0) return 0;
            if (cancellation != null && cancellation.isCanceled()) throw new ErrnoException("write", OsConstants.ECANCELED);
            try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(staging,
                    java.nio.file.StandardOpenOption.WRITE)) {
                channel.position(offset);
                java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(data, 0, size);
                while (buffer.hasRemaining()) channel.write(buffer);
                dirty = true;
                return size;
            } catch (Exception error) { throw failure("write", error); }
        }

        @Override public synchronized void onFsync() throws ErrnoException { publish("fsync"); }

        @Override public synchronized void onRelease() {
            try { publish("release"); }
            catch (ErrnoException ignored) { /* The original remote file remains intact. */ }
            finally {
                released = true;
                try { Files.deleteIfExists(staging); } catch (Exception ignored) { }
            }
        }

        private void publish(String operation) throws ErrnoException {
            if (!dirty || released) return;
            if (cancellation != null && cancellation.isCanceled()) {
                throw new ErrnoException(operation, OsConstants.ECANCELED);
            }
            try {
                NetworkPeerConnector.uploadFilesystemFile(endpoint, rootId, path, staging, true, "",
                        membership, trustedCa, MAX_STAGED_BYTES);
                dirty = false;
            } catch (Exception error) { throw failure(operation, error); }
        }

        private static ErrnoException failure(String operation, Throwable error) {
            ErrnoException failure = new ErrnoException(operation, OsConstants.EIO);
            failure.initCause(error);
            return failure;
        }
    }
}
