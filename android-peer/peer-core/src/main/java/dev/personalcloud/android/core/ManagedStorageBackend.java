package dev.personalcloud.android.core;

import java.io.OutputStream;
import java.util.Collection;
import java.util.Map;

/**
 * Byte-storage boundary for authenticated network-managed files.
 * Implementations own physical publication and location identifiers; the core owns
 * member authentication, logical paths, SHA-256 verification and catalogue metadata.
 */
public interface ManagedStorageBackend {
    String storageId();

    UploadSession beginUpload(String fileId, String relativePath, long expectedSize) throws Exception;

    Map<String, Object> stat(String storageKey) throws Exception;

    ExternalReferenceStore.NetworkReferenceContent open(String storageKey) throws Exception;

    void delete(String storageKey) throws Exception;

    /**
     * Verify indexed objects after a restart. Implementations must preserve unindexed
     * provider documents: missing local metadata is not proof that user data is disposable.
     */
    void reconcile(Collection<String> referencedStorageKeys) throws Exception;

    interface UploadSession extends AutoCloseable {
        OutputStream outputStream() throws Exception;
        /** Close and publish the already-created unique provider object. */
        String commit() throws Exception;
        /** Best-effort removal of an incomplete upload. Safe to call more than once. */
        void abort();
        @Override void close();
    }
}
