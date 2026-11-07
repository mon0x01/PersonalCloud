package dev.personalcloud.android.core;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Signed, TLS-authenticated client for member-scoped reference and managed storage APIs. */
public final class NetworkPeerConnector {
    private NetworkPeerConnector() { }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> listReferences(String endpoint, NetworkMembershipClient membership,
                                                           String trustedCaPath) throws Exception {
        Object value = get(endpoint, "/network/references", membership, trustedCaPath).get("references");
        return rows(value, "reference grants");
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> browseReference(String endpoint, String grantId, String relativePath,
                                                             NetworkMembershipClient membership,
                                                             String trustedCaPath) throws Exception {
        String path = "/network/references/" + encode(grantId) + "/entries?path=" + encode(relativePath);
        return rows(get(endpoint, path, membership, trustedCaPath).get("entries"), "reference directory");
    }

    public static Map<String, Object> statReference(String endpoint, String grantId, String relativePath,
                                                    NetworkMembershipClient membership,
                                                    String trustedCaPath) throws Exception {
        String path = "/network/references/" + encode(grantId) + "/stat?path=" + encode(relativePath);
        return get(endpoint, path, membership, trustedCaPath);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> searchReferences(String endpoint, String query, int limit,
                                                             NetworkMembershipClient membership,
                                                             String trustedCaPath) throws Exception {
        String path = "/network/search?q=" + encode(query) + "&limit=" + Math.max(1, Math.min(100, limit));
        return rows(get(endpoint, path, membership, trustedCaPath).get("results"), "search results");
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> listManagedFiles(String endpoint, NetworkMembershipClient membership,
                                                             String trustedCaPath) throws Exception {
        return rows(get(endpoint, "/network/managed/files", membership, trustedCaPath).get("files"), "managed files");
    }

    public static Map<String, Object> statManagedFile(String endpoint, String fileId,
                                                      NetworkMembershipClient membership,
                                                      String trustedCaPath) throws Exception {
        return get(endpoint, "/network/managed/files/" + encode(fileId), membership, trustedCaPath);
    }

    public static Map<String, Object> uploadManagedFile(String endpoint, String destinationRelativePath,
                                                        java.nio.file.Path source, NetworkMembershipClient membership,
                                                        String trustedCaPath, long maximumBytes) throws Exception {
        java.nio.file.Path file = source.toAbsolutePath().normalize();
        if (java.nio.file.Files.isSymbolicLink(file)
                || !java.nio.file.Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Managed placement source must be a regular non-symlink file.");
        }
        return PeerConnector.putSignedResumableManagedFile(endpoint, destinationRelativePath,
                () -> java.nio.file.Files.newInputStream(file, java.nio.file.LinkOption.NOFOLLOW_LINKS),
                java.nio.file.Files.size(file), membership, trustedCaPath, maximumBytes);
    }

    /** Uploads directly from a reopenable source such as an Android SAF document, without staging a local copy. */
    public static Map<String, Object> uploadManagedFile(String endpoint, String destinationRelativePath,
                                                        PeerConnector.InputStreamSource source, long declaredSize,
                                                        NetworkMembershipClient membership, String trustedCaPath,
                                                        long maximumBytes) throws Exception {
        return PeerConnector.putSignedResumableManagedFile(endpoint, destinationRelativePath, source, declaredSize,
                membership, trustedCaPath, maximumBytes);
    }

    /** Creates a receiver-side managed transfer using a sender-stable ID before any bytes are sent. */
    public static Map<String,Object> createManagedTransfer(String endpoint, String transferId,
                                                            String destinationRelativePath, long size,
                                                            String sha256, NetworkMembershipClient membership,
                                                            String trustedCaPath) throws Exception {
        return PeerConnector.createSignedTransferSession(endpoint, transferId, destinationRelativePath,
                size, sha256, membership, trustedCaPath);
    }

    /** Resume a previously-created direct transfer using a reopenable source such as an Android SAF URI. */
    public static Map<String,Object> resumeManagedFile(String endpoint, String transferId,
                                                       PeerConnector.InputStreamSource source, long declaredSize,
                                                       NetworkMembershipClient membership, String trustedCaPath,
                                                       long maximumBytes) throws Exception {
        return PeerConnector.resumeSignedManagedFile(endpoint, transferId, source, declaredSize,
                membership, trustedCaPath, maximumBytes);
    }

    public static Map<String,Object> transferStatus(String endpoint, String transferId,
                                                    NetworkMembershipClient membership, String trustedCaPath) throws Exception {
        String path = "/network/transfers/" + encode(transferId);
        return get(endpoint, path, membership, trustedCaPath);
    }

    public static Map<String,Object> abortTransfer(String endpoint, String transferId,
                                                   NetworkMembershipClient membership, String trustedCaPath) throws Exception {
        String path = "/network/transfers/" + encode(transferId);
        return delete(endpoint, path, membership, trustedCaPath);
    }

    public static Map<String,Object> deleteReference(String endpoint, String grantId, String relativePath,
                                                     NetworkMembershipClient membership, String trustedCaPath) throws Exception {
        String path = "/network/references/" + encode(grantId) + "?path=" + encode(relativePath);
        return delete(endpoint, path, membership, trustedCaPath);
    }

    public static Map<String,Object> deleteManagedFile(String endpoint, String fileId,
                                                       NetworkMembershipClient membership, String trustedCaPath) throws Exception {
        String path = "/network/managed/files/" + encode(fileId);
        return delete(endpoint, path, membership, trustedCaPath);
    }

    public static PeerConnector.RangeResult readReferenceRange(String endpoint, String grantId, String relativePath,
                                                               long offset, int length,
                                                               NetworkMembershipClient membership,
                                                               String trustedCaPath) throws Exception {
        String path = "/network/references/" + encode(grantId) + "/content?path=" + encode(relativePath)
                + "&offset=" + offset + "&length=" + length;
        return PeerConnector.readSignedRange(endpoint, path, offset, length, membership, trustedCaPath);
    }

    public static PeerConnector.RangeResult readManagedRange(String endpoint, String fileId, long offset, int length,
                                                              NetworkMembershipClient membership,
                                                              String trustedCaPath) throws Exception {
        String path = "/network/managed/files/" + encode(fileId) + "/content?offset=" + offset + "&length=" + length;
        return PeerConnector.readSignedRange(endpoint, path, offset, length, membership, trustedCaPath);
    }

    public static List<Map<String,Object>> listFilesystemRoots(String endpoint,
                                                               NetworkMembershipClient membership,
                                                               String trustedCaPath) throws Exception {
        Object value = get(endpoint, "/network/fs/roots", membership, trustedCaPath).get("roots");
        return rows(value, "eligible filesystem roots");
    }

    public static List<Map<String,Object>> browseFilesystem(String endpoint, String rootId, String relativePath,
                                                             NetworkMembershipClient membership,
                                                             String trustedCaPath) throws Exception {
        Object value = get(endpoint, filesystemPath(rootId, "entries", relativePath),
                membership, trustedCaPath).get("entries");
        return rows(value, "eligible filesystem entries");
    }

    public static Map<String,Object> statFilesystem(String endpoint, String rootId, String relativePath,
                                                    NetworkMembershipClient membership,
                                                    String trustedCaPath) throws Exception {
        return get(endpoint, filesystemPath(rootId, "stat", relativePath), membership, trustedCaPath);
    }

    public static PeerConnector.RangeResult readFilesystemRange(String endpoint, String rootId, String relativePath,
                                                                 long offset, int length,
                                                                 NetworkMembershipClient membership,
                                                                 String trustedCaPath) throws Exception {
        String path = filesystemPath(rootId, "content", relativePath) + "&offset=" + offset + "&length=" + length;
        return PeerConnector.readSignedRange(endpoint, path, offset, length, membership, trustedCaPath);
    }

    public static Map<String,Object> createFilesystemDirectory(String endpoint, String rootId, String relativePath,
                                                                NetworkMembershipClient membership,
                                                                String trustedCaPath) throws Exception {
        Map<String,Object> body = new LinkedHashMap<>();
        body.put("path", relativePath == null ? "" : relativePath);
        String path = "/network/fs/" + encodePath(rootId) + "/directories";
        return PeerConnector.postSignedJson(endpoint, path, body,
                membership.createAuthHeaders("POST", path, Json.stringify(body).getBytes(StandardCharsets.UTF_8)),
                trustedCaPath);
    }

    public static Map<String,Object> moveFilesystemEntry(String endpoint, String rootId, String from, String to,
                                                          boolean overwrite, String approvalId,
                                                          NetworkMembershipClient membership,
                                                          String trustedCaPath) throws Exception {
        Map<String,Object> body = new LinkedHashMap<>();
        body.put("from", from);
        body.put("to", to);
        body.put("overwrite", overwrite);
        body.put("approvalId", approvalId == null ? "" : approvalId);
        body.put("destinationApprovalId", "");
        String path = "/network/fs/" + encodePath(rootId) + "/move";
        return PeerConnector.postSignedJson(endpoint, path, body,
                membership.createAuthHeaders("POST", path, Json.stringify(body).getBytes(StandardCharsets.UTF_8)),
                trustedCaPath);
    }

    public static Map<String,Object> deleteFilesystemEntry(String endpoint, String rootId, String relativePath,
                                                            boolean recursive, String approvalId,
                                                            NetworkMembershipClient membership,
                                                            String trustedCaPath) throws Exception {
        String path = "/network/fs/" + encodePath(rootId) + "/entry?path=" + encodePath(relativePath)
                + "&recursive=" + recursive + "&approvalId=" + encodePath(approvalId);
        return delete(endpoint, path, membership, trustedCaPath);
    }

    public static Map<String,Object> uploadFilesystemFile(String endpoint, String rootId, String relativePath,
                                                           java.nio.file.Path source, boolean overwrite,
                                                           String approvalId,
                                                           NetworkMembershipClient membership,
                                                           String trustedCaPath, long maximumBytes) throws Exception {
        return PeerConnector.putSignedFilesystemFile(endpoint, rootId, relativePath, source, overwrite, approvalId,
                membership, trustedCaPath, maximumBytes);
    }

    private static String filesystemPath(String rootId, String action, String relativePath) {
        return "/network/fs/" + encodePath(rootId) + "/" + action + "?path=" + encodePath(relativePath);
    }

    private static String encodePath(String value) {
        return encode(value == null ? "" : value).replace("+", "%20");
    }

    public static String activeEndpoint(NetworkMembershipClient membership, String memberId) {
        if (!membership.isActiveMember(memberId)) throw new SecurityException("The requested device is not an active network member.");
        for (Map<String, Object> row : membership.members()) {
            if (memberId.equals(row.get("nodeId"))) {
                Object endpoint = row.get("endpoint");
                if (endpoint instanceof String value && !value.isBlank()) return value;
            }
        }
        throw new IllegalStateException("The active network member has no registered direct endpoint.");
    }

    private static Map<String, Object> get(String endpoint, String path, NetworkMembershipClient membership,
                                           String trustedCaPath) throws Exception {
        String rawPath = path;
        return PeerConnector.getSignedJson(endpoint, rawPath,
                membership.createAuthHeaders("GET", rawPath, new byte[0]), trustedCaPath);
    }

    private static Map<String,Object> delete(String endpoint, String path, NetworkMembershipClient membership,
                                             String trustedCaPath) throws Exception {
        return PeerConnector.deleteSignedJson(endpoint, path,
                membership.createAuthHeaders("DELETE", path, new byte[0]), trustedCaPath);
    }

    private static List<Map<String, Object>> rows(Object value, String label) throws Exception {
        if (!(value instanceof List<?> list)) throw new IllegalStateException("Peer returned invalid " + label + ".");
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IllegalStateException("Peer returned an invalid row in " + label + ".");
            Map<String, Object> row = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) row.put(String.valueOf(entry.getKey()), entry.getValue());
            result.add(row);
        }
        return List.copyOf(result);
    }

    private static String encode(String value) {
        if (value == null) value = "";
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
