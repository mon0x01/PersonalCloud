package dev.personalcloud.android;

import android.content.ContentResolver;
import android.content.Context;
import android.content.UriPermission;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;

import dev.personalcloud.android.core.ExternalReferenceStore;
import dev.personalcloud.android.core.ManagedStorageBackend;
import dev.personalcloud.android.core.StateStore;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Managed-file byte backend over a user-authorized SAF tree.
 * Files are held in a dedicated PersonalCloud Managed directory and are indexed by the
 * encrypted NetworkStorageService domain. Logical paths remain metadata; physical objects
 * receive random opaque names so providers cannot overwrite a same-named user file.
 */
public final class AndroidSafManagedStorageBackend implements ManagedStorageBackend {
    public static final String TREE_URI_CONFIG_KEY = "managed_storage_tree_uri";
    private static final String DIRECTORY_NAME = "PersonalCloud Managed";
    private static final String FILE_PREFIX = ".personalcloud-managed-";
    private static final String MIME_BINARY = "application/octet-stream";

    private final Context appContext;
    private final ContentResolver resolver;
    private final Uri treeUri;
    private final Uri treeRootUri;
    private final Uri managedDirectoryUri;
    private final String storageId;

    public AndroidSafManagedStorageBackend(Context context, String selectedTreeUri,
                                           String selectedStorageId) throws Exception {
        this.appContext = context.getApplicationContext();
        this.resolver = appContext.getContentResolver();
        if (selectedTreeUri == null || selectedTreeUri.isBlank()) {
            throw new IllegalStateException("Selected SAF managed-storage folder is missing. Select it again; PersonalCloud will not fall back to internal storage.");
        }
        this.treeUri = Uri.parse(selectedTreeUri);
        if (!DocumentsContract.isTreeUri(treeUri)) {
            throw new SecurityException("Configured managed-storage URI is not an Android document tree.");
        }
        this.storageId = storageIdForTree(treeUri);
        if (!this.storageId.equals(selectedStorageId)) {
            throw new SecurityException("Selected SAF tree identity does not match the persisted managed-storage identity.");
        }
        requirePersistedReadWrite(treeUri, resolver);
        String rootId = DocumentsContract.getTreeDocumentId(treeUri);
        this.treeRootUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId);
        DocumentInfo root = query(treeRootUri);
        if (!root.directory()) throw new IllegalArgumentException("Selected SAF managed-storage root is not a directory.");
        if ((root.flags & DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE) == 0) {
            throw new IllegalStateException("Selected SAF provider does not advertise folder creation support.");
        }
        this.managedDirectoryUri = findOrCreateManagedDirectory();
        DocumentInfo managedDirectory = query(managedDirectoryUri);
        if (!managedDirectory.directory()
                || (managedDirectory.flags & DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE) == 0) {
            throw new IllegalStateException("SAF provider cannot create files in the PersonalCloud Managed folder.");
        }
    }

    @Override public String storageId() { return storageId; }

    /** Identity binds the permission-bearing tree URI, not a transient mount path. */
    public static String storageIdForTree(Uri tree) throws Exception {
        if (tree == null || !DocumentsContract.isTreeUri(tree)) throw new IllegalArgumentException("A SAF tree URI is required.");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(tree.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder("saf:");
        for (byte value : digest) hex.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return hex.toString();
    }

    /** Validate the selected tree using the temporary picker grant before taking persistable permission. */
    public static void validateSelection(Context context, Uri tree) throws Exception {
        if (tree == null || !DocumentsContract.isTreeUri(tree)) throw new IllegalArgumentException("Choose a folder using Android's system folder picker.");
        ContentResolver resolver = context.getApplicationContext().getContentResolver();
        String id = DocumentsContract.getTreeDocumentId(tree);
        Uri root = DocumentsContract.buildDocumentUriUsingTree(tree, id);
        DocumentInfo info = query(resolver, root);
        if (!info.directory()) throw new IllegalArgumentException("Selected SAF item is not a folder.");
        if ((info.flags & DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE) == 0) {
            throw new IllegalStateException("This document provider does not allow creating files in the selected folder.");
        }
    }

    private static void requirePersistedReadWrite(Uri uri, ContentResolver resolver) {
        for (UriPermission permission : resolver.getPersistedUriPermissions()) {
            if (permission.getUri().equals(uri) && permission.isReadPermission() && permission.isWritePermission()) return;
        }
        throw new SecurityException("Persistent read and write permission for the selected SAF folder is unavailable. Select the folder again and grant both permissions.");
    }

    private Uri findOrCreateManagedDirectory() throws Exception {
        List<DocumentInfo> matches = children(treeUri, DocumentsContract.getDocumentId(treeRootUri));
        DocumentInfo found = null;
        for (DocumentInfo child : matches) {
            if (!DIRECTORY_NAME.equals(child.name)) continue;
            if (!child.directory()) throw new IllegalStateException("A non-directory item already uses the PersonalCloud Managed folder name.");
            if (found != null) throw new IllegalStateException("The selected provider contains ambiguous duplicate PersonalCloud Managed folders.");
            found = child;
        }
        if (found != null) return found.uri;
        Uri created = DocumentsContract.createDocument(resolver, treeRootUri,
                DocumentsContract.Document.MIME_TYPE_DIR, DIRECTORY_NAME);
        if (created == null) throw new IllegalStateException("SAF provider refused to create the PersonalCloud Managed folder.");
        return created;
    }

    @Override public synchronized UploadSession beginUpload(String fileId, String relativePath,
                                                              long expectedSize) throws Exception {
        if (fileId == null || !fileId.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Invalid managed file identifier.");
        if (relativePath == null || relativePath.isBlank()) throw new IllegalArgumentException("Managed logical path is required.");
        if (expectedSize < 0) throw new IllegalArgumentException("Managed file size is invalid.");
        String physicalName = FILE_PREFIX + fileId + ".blob";
        for (DocumentInfo child : children(treeUri, DocumentsContract.getDocumentId(managedDirectoryUri))) {
            if (physicalName.equals(child.name)) throw new IllegalStateException("A physical SAF object with this unique identifier already exists; no file was overwritten.");
        }
        Uri created = DocumentsContract.createDocument(resolver, managedDirectoryUri, MIME_BINARY, physicalName);
        if (created == null) throw new IllegalStateException("SAF provider refused to create a managed upload document.");
        if (!isChildOfManagedDirectory(created)) {
            try { DocumentsContract.deleteDocument(resolver, created); } catch (Exception ignored) { }
            throw new SecurityException("SAF provider created the managed document outside the selected PersonalCloud folder.");
        }
        DocumentInfo createdInfo = query(created);
        if (createdInfo.directory()
                || (createdInfo.flags & DocumentsContract.Document.FLAG_SUPPORTS_WRITE) == 0) {
            try { DocumentsContract.deleteDocument(resolver, created); } catch (Exception ignored) { }
            throw new IllegalStateException("SAF provider created a document but does not advertise write support.");
        }
        OutputStream output;
        try {
            output = resolver.openOutputStream(created, "w");
            if (output == null) throw new IllegalStateException("SAF provider returned no writable stream for the managed document.");
        } catch (Exception failure) {
            try { DocumentsContract.deleteDocument(resolver, created); } catch (Exception ignored) { }
            throw failure;
        }
        return new SafUpload(created, output, expectedSize);
    }

    private final class SafUpload implements UploadSession {
        private Uri uri;
        private OutputStream output;
        private final long expectedSize;
        private boolean committed;
        private boolean aborted;

        SafUpload(Uri uri, OutputStream output, long expectedSize) {
            this.uri = uri;
            this.output = output;
            this.expectedSize = expectedSize;
        }

        @Override public synchronized OutputStream outputStream() {
            if (aborted || committed || output == null) throw new IllegalStateException("Managed SAF upload is no longer writable.");
            return output;
        }

        @Override public synchronized String commit() throws Exception {
            if (aborted || committed) throw new IllegalStateException("Managed SAF upload cannot be committed twice.");
            if (output != null) {
                output.flush();
                output.close();
                output = null;
            }
            DocumentInfo info = query(uri);
            if (info.directory() || info.size != expectedSize) {
                throw new SecurityException("SAF provider did not publish the declared managed-file length.");
            }
            if (!isChildOfManagedDirectory(uri)) throw new SecurityException("Managed document moved outside its selected storage folder.");
            committed = true;
            return DocumentsContract.getDocumentId(uri);
        }

        @Override public synchronized void abort() {
            if (committed || aborted) return;
            aborted = true;
            if (output != null) {
                try { output.close(); } catch (Exception ignored) { }
                output = null;
            }
            try { DocumentsContract.deleteDocument(resolver, uri); } catch (Exception ignored) { }
        }

        @Override public void close() { abort(); }
    }

    /**
     * Debug-only real-provider contract test. Creates one uniquely named temporary object,
     * verifies full and ranged read-back, verifies no-overwrite, and deletes only that object.
     */
    public synchronized Map<String,Object> runProviderSelfTest() throws Exception {
        byte[] expected = new byte[256 * 1024 + 37];
        for (int i = 0; i < expected.length; i++) {
            expected[i] = (byte)((i * 131 + 17) & 0xff);
        }
        String fileId = java.util.UUID.randomUUID().toString();
        String key = null;
        try {
            try (ManagedStorageBackend.UploadSession upload =
                         beginUpload(fileId, "diagnostics/provider-roundtrip.bin", expected.length)) {
                OutputStream output = upload.outputStream();
                output.write(expected);
                output.flush();
                key = upload.commit();
            }

            Map<String,Object> metadata = stat(key);
            Object storedSize = metadata.get("size");
            if (!(storedSize instanceof Number)
                    || ((Number) storedSize).longValue() != expected.length) {
                throw new SecurityException("SAF provider reported an incorrect self-test object size.");
            }

            ExternalReferenceStore.NetworkReferenceContent content = open(key);
            if (content.size() != expected.length) {
                throw new SecurityException("SAF provider returned an incorrect read size.");
            }
            byte[] full = readSelfTestRange(content, 0, expected.length);
            if (!java.util.Arrays.equals(expected, full)) {
                throw new SecurityException("SAF provider full read-back differs from uploaded bytes.");
            }

            int offset = 32761;
            int rangeLength = 8193;
            byte[] range = readSelfTestRange(content, offset, rangeLength);
            byte[] expectedRange = java.util.Arrays.copyOfRange(expected, offset, offset + rangeLength);
            if (!java.util.Arrays.equals(expectedRange, range)) {
                throw new SecurityException("SAF provider ranged read-back differs from uploaded bytes.");
            }

            boolean noOverwrite = false;
            try (ManagedStorageBackend.UploadSession duplicate =
                         beginUpload(fileId, "diagnostics/duplicate.bin", expected.length)) {
                duplicate.abort();
            } catch (IllegalStateException expectedDuplicate) {
                noOverwrite = true;
            }
            if (!noOverwrite) {
                throw new SecurityException("SAF provider backend did not reject a duplicate physical identifier.");
            }

            String deletedKey = key;
            delete(key);
            key = null;
            boolean deletionVerified = false;
            try {
                stat(deletedKey);
            } catch (Exception expectedMissing) {
                deletionVerified = true;
            }
            if (!deletionVerified) {
                throw new SecurityException("SAF provider still exposes the self-test document after deletion.");
            }

            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(expected);
            StringBuilder sha256Builder = new StringBuilder();
            for (byte value : digest) {
                sha256Builder.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            }
            String sha256 = sha256Builder.toString();
            return Map.of(
                    "result", "PASS",
                    "bytes", expected.length,
                    "sha256", sha256,
                    "fullReadBack", "PASS",
                    "rangeReadBack", "PASS",
                    "noOverwrite", "PASS",
                    "delete", "PASS"
            );
        } finally {
            if (key != null) {
                try { delete(key); } catch (Exception ignored) { }
            }
        }
    }

    private static byte[] readSelfTestRange(
            ExternalReferenceStore.NetworkReferenceContent content,
            long offset, long length) throws Exception {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        try (InputStream input = content.openRange(offset, length)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (output.size() + read > length) {
                    throw new SecurityException("SAF provider returned too many bytes in a self-test range.");
                }
                output.write(buffer, 0, read);
            }
        }
        if (output.size() != length) {
            throw new SecurityException("SAF provider returned a truncated self-test range.");
        }
        return output.toByteArray();
    }

    @Override public synchronized Map<String,Object> stat(String storageKey) throws Exception {
        Uri uri = requireManagedUri(storageKey);
        DocumentInfo info = query(uri);
        if (info.directory() || info.size < 0) throw new IllegalStateException("Managed SAF document does not expose a stable file size.");
        return Map.of("name", info.name, "size", info.size,
                "modified", info.modified <= 0 ? "" : java.time.Instant.ofEpochMilli(info.modified).toString(),
                "mimeType", info.mimeType, "flags", info.flags);
    }

    @Override public synchronized ExternalReferenceStore.NetworkReferenceContent open(String storageKey) throws Exception {
        Uri uri = requireManagedUri(storageKey);
        DocumentInfo info = query(uri);
        if (info.directory() || info.size < 0) throw new IllegalStateException("Managed SAF document is unavailable or has no stable size.");
        long expectedSize = info.size;
        return new ExternalReferenceStore.NetworkReferenceContent() {
            @Override public long size() { return expectedSize; }
            @Override public InputStream openRange(long offset, long length) throws Exception {
                if (offset < 0 || length < 0 || offset > expectedSize || length > expectedSize - offset)
                    throw new IllegalArgumentException("Managed SAF byte range is outside file bounds.");
                ParcelFileDescriptor descriptor = null;
                try {
                    descriptor = resolver.openFileDescriptor(uri, "r");
                    if (descriptor != null) {
                        ParcelFileDescriptor.AutoCloseInputStream stream =
                                new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
                        descriptor = null;
                        try {
                            stream.getChannel().position(offset);
                            return bounded(stream, length);
                        } catch (Exception notSeekable) {
                            try { stream.close(); } catch (Exception ignored) { }
                        }
                    }
                } finally {
                    if (descriptor != null) try { descriptor.close(); } catch (Exception ignored) { }
                }
                InputStream stream = resolver.openInputStream(uri);
                if (stream == null) throw new IllegalStateException("SAF provider returned no input stream.");
                try {
                    skipExactly(stream, offset);
                    return bounded(stream, length);
                } catch (Exception failure) {
                    stream.close();
                    throw failure;
                }
            }
        };
    }

    @Override public synchronized void delete(String storageKey) throws Exception {
        Uri uri = requireManagedUri(storageKey);
        if (!DocumentsContract.deleteDocument(resolver, uri)) {
            throw new IllegalStateException("SAF provider refused to delete the managed document.");
        }
    }

    @Override public synchronized void reconcile(Collection<String> referencedStorageKeys) throws Exception {
        // Validate every catalogue reference, but never delete an unindexed provider object.
        // A reinstall, state-key loss, interrupted persistence, or a damaged local index must
        // not turn into silent data loss on shared SD/USB storage. Orphaned objects remain in
        // the reserved PersonalCloud Managed directory for a future explicit recovery tool.
        Set<String> active = new HashSet<>(referencedStorageKeys);
        for (String key : active) {
            Uri uri = requireManagedUri(key);
            DocumentInfo info = query(uri);
            if (info.directory() || info.size < 0) {
                throw new IllegalStateException("An indexed PersonalCloud SAF object is unavailable or does not expose a stable size.");
            }
        }
    }

    private Uri requireManagedUri(String key) throws Exception {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("Managed SAF storage key is missing.");
        // Persist provider document IDs, not transient content URI strings. Rebuild the
        // tree-scoped URI from the selected permission-bearing tree after every restart.
        Uri uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, key);
        if (!"content".equals(uri.getScheme()) || !treeUri.getAuthority().equals(uri.getAuthority())) {
            throw new SecurityException("Managed SAF key belongs to a different document provider.");
        }
        if (!isChildOfManagedDirectory(uri)) throw new SecurityException("Managed SAF document is outside the selected PersonalCloud folder.");
        return uri;
    }

    private boolean isChildOfManagedDirectory(Uri document) throws Exception {
        String wantedId = DocumentsContract.getDocumentId(document);
        String parentId = DocumentsContract.getDocumentId(managedDirectoryUri);
        for (DocumentInfo child : children(treeUri, parentId)) {
            if (wantedId.equals(DocumentsContract.getDocumentId(child.uri))) return true;
        }
        return false;
    }

    private List<DocumentInfo> children(Uri tree, String parentId) throws Exception {
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId);
        String[] projection = {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
                DocumentsContract.Document.COLUMN_FLAGS
        };
        List<DocumentInfo> result = new ArrayList<>();
        try (Cursor cursor = resolver.query(children, projection, null, null, null)) {
            if (cursor == null) throw new IllegalStateException("SAF provider did not return a document listing.");
            while (cursor.moveToNext()) {
                String id = cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID));
                result.add(readInfo(DocumentsContract.buildDocumentUriUsingTree(tree, id), cursor));
            }
        }
        return result;
    }

    private DocumentInfo query(Uri uri) throws Exception { return query(resolver, uri); }

    private static DocumentInfo query(ContentResolver resolver, Uri uri) throws Exception {
        String[] projection = {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
                DocumentsContract.Document.COLUMN_FLAGS
        };
        try (Cursor cursor = resolver.query(uri, projection, null, null, null)) {
            if (cursor == null || !cursor.moveToFirst()) throw new IllegalStateException("SAF document is unavailable.");
            return readInfo(uri, cursor);
        }
    }

    private static DocumentInfo readInfo(Uri uri, Cursor cursor) {
        int size = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE);
        int modified = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED);
        int flags = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_FLAGS);
        return new DocumentInfo(uri,
                cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)),
                cursor.getString(cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)),
                size < 0 || cursor.isNull(size) ? -1L : cursor.getLong(size),
                modified < 0 || cursor.isNull(modified) ? 0L : cursor.getLong(modified),
                flags < 0 || cursor.isNull(flags) ? 0 : cursor.getInt(flags));
    }

    private static InputStream bounded(InputStream input, long length) {
        return new FilterInputStream(input) {
            private long remaining = length;
            @Override public int read() throws IOException {
                if (remaining <= 0) return -1;
                int value = super.read();
                if (value < 0) throw new EOFException("SAF managed document truncated during read.");
                remaining--;
                return value;
            }
            @Override public int read(byte[] bytes, int offset, int count) throws IOException {
                if (remaining <= 0) return -1;
                int read = super.read(bytes, offset, (int)Math.min((long)count, remaining));
                if (read < 0) throw new EOFException("SAF managed document truncated during range read.");
                remaining -= read;
                return read;
            }
        };
    }

    private static void skipExactly(InputStream input, long bytes) throws IOException {
        long remaining = bytes;
        byte[] discard = new byte[65536];
        while (remaining > 0) {
            long skipped = input.skip(remaining);
            if (skipped > 0) { remaining -= skipped; continue; }
            int read = input.read(discard, 0, (int)Math.min((long)discard.length, remaining));
            if (read < 0) throw new EOFException("SAF document ended before requested offset.");
            remaining -= read;
        }
    }

    private static final class DocumentInfo {
        final Uri uri;
        final String name;
        final String mimeType;
        final long size;
        final long modified;
        final int flags;
        DocumentInfo(Uri uri, String name, String mimeType, long size, long modified, int flags) {
            this.uri = uri; this.name = name; this.mimeType = mimeType;
            this.size = size; this.modified = modified; this.flags = flags;
        }
        boolean directory() { return DocumentsContract.Document.MIME_TYPE_DIR.equals(mimeType); }
    }
}
