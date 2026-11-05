package dev.personalcloud.android.core;

import java.util.List;
import java.util.Map;

/**
 * Platform adapter for user-owned storage that cannot be represented as a java.nio Path
 * (for example Android Storage Access Framework document trees).
 * Implementations must enforce member-scoped grants and must never copy source bytes merely
 * to create a reference. Recovery for destructive operations is owned by the implementation.
 */
public interface ExternalReferenceStore {
    Map<String, Object> grantReference(String memberId, String selector, String permission) throws Exception;
    void revokeReference(String grantId) throws Exception;
    boolean hasGrant(String memberId, String grantId);
    boolean hasGrantForOwner(String grantId);
    List<Map<String, Object>> listReferencesForMember(String memberId) throws Exception;
    List<Map<String, Object>> browseReference(String memberId, String grantId, String relativeDirectory) throws Exception;
    Map<String, Object> statReference(String memberId, String grantId, String relativePath) throws Exception;
    NetworkReferenceContent openReference(String memberId, String grantId, String relativePath) throws Exception;
    Map<String, Object> deleteReference(String memberId, String grantId, String relativePath) throws Exception;
    List<Map<String, Object>> searchReferences(String memberId, String query, int limit) throws Exception;

    /** A seekable read-only view over a file owned by an external storage provider. */
    interface NetworkReferenceContent {
        long size() throws Exception;
        java.io.InputStream openRange(long offset, long length) throws Exception;
    }
}
