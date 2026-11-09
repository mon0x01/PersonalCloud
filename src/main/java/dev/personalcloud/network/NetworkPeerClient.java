package dev.personalcloud.network;

import dev.personalcloud.net.Json;
import dev.personalcloud.net.RemotePeerClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Direct authenticated HTTPS client for member-to-member control, metadata and file operations. */
public final class NetworkPeerClient {
    private final HttpClient client;

    public NetworkPeerClient() throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        String truststore = System.getenv("PERSONALCLOUD_TLS_TRUSTSTORE");
        String password = System.getenv("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD");
        if (truststore != null && !truststore.isBlank()) {
            if (password == null || password.isBlank()) throw new IllegalArgumentException("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD is required with the configured truststore.");
            java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(Path.of(truststore))) { store.load(input, password.toCharArray()); }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            managers.init(store);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, managers.getTrustManagers(), null);
            builder.sslContext(ssl);
        }
        client = builder.build();
    }

    public Map<String, Object> getJson(String baseUrl, String path, NetworkMembershipService membership) throws Exception {
        HttpRequest.Builder request = request(baseUrl, path, "GET", new byte[0], membership);
        HttpResponse<String> response = client.send(request.GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return parseResponse(response.statusCode(), response.body());
    }

    public Map<String, Object> deleteJson(String baseUrl, String path, NetworkMembershipService membership) throws Exception {
        HttpRequest.Builder request = request(baseUrl, path, "DELETE", new byte[0], membership);
        HttpResponse<String> response = client.send(request.DELETE().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return parseResponse(response.statusCode(), response.body());
    }

    public Map<String, Object> postJson(String baseUrl, String path, Map<String, Object> body,
                                        NetworkMembershipService membership) throws Exception {
        byte[] bytes = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        HttpRequest.Builder request = request(baseUrl, path, "POST", bytes, membership)
                .header("Content-Type", "application/json; charset=UTF-8");
        HttpResponse<String> response = client.send(request.POST(HttpRequest.BodyPublishers.ofByteArray(bytes)).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return parseResponse(response.statusCode(), response.body());
    }

    public Map<String, Object> listRemoteReferences(String baseUrl, NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, "/network/references", membership);
    }

    public Map<String, Object> browseRemoteReference(String baseUrl, String grantId, String relativePath,
                                                      NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, referencePath(grantId, "entries", relativePath), membership);
    }

    public Map<String, Object> statRemoteReference(String baseUrl, String grantId, String relativePath,
                                                    NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, referencePath(grantId, "stat", relativePath), membership);
    }

    public Map<String, Object> searchRemoteReferences(String baseUrl, String query, int limit,
                                                        NetworkMembershipService membership) throws Exception {
        String path = "/network/search?q=" + encode(query == null ? "" : query) + "&limit=" + Math.max(1, Math.min(limit, 100));
        return getJson(baseUrl, path, membership);
    }

    public RemoteDownloadResult downloadRemoteReference(String baseUrl, String grantId, String relativePath,
                                                          Path destination, NetworkMembershipService membership,
                                                          long maximumBytes) throws Exception {
        Map<String, Object> metadata = statRemoteReference(baseUrl, grantId, relativePath, membership);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The selected remote path is not a regular file.");
        long expectedSize = number(metadata.get("size"));
        if (expectedSize < 0 || expectedSize > maximumBytes) throw new IllegalArgumentException("Remote file exceeds the configured download limit.");
        Path requested = destination.toAbsolutePath().normalize();
        Path requestedParent = requested.getParent();
        if (requestedParent == null || requested.getFileName() == null || !Files.isDirectory(requestedParent)) throw new IllegalArgumentException("Destination parent directory does not exist.");
        Path parent = requestedParent.toRealPath();
        Path target = parent.resolve(requested.getFileName().toString());
        if (Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Destination already exists; PersonalCloud will not overwrite it.");
        Path temporary = Files.createTempFile(parent, ".personalcloud-download-", ".part");
        try {
            String path = referencePath(grantId, "content", relativePath);
            HttpRequest.Builder request = request(baseUrl, path, "GET", new byte[0], membership);
            HttpResponse<InputStream> response = client.send(request.GET().build(), HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                try (InputStream ignored = response.body()) { }
                throw new java.io.IOException("Remote file download failed with HTTP " + response.statusCode() + ".");
            }
            String expectedHash = response.headers().firstValue("X-Content-SHA256").orElse("").toLowerCase(java.util.Locale.ROOT);
            if (!expectedHash.matches("[a-f0-9]{64}")) throw new java.io.IOException("Remote file response did not include a valid SHA-256 digest.");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            try (InputStream input = response.body(); OutputStream output = Files.newOutputStream(temporary,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > maximumBytes || copied > expectedSize) throw new java.io.IOException("Remote file exceeded its declared or configured size limit.");
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
            }
            String actualHash = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedSize || !MessageDigest.isEqual(expectedHash.getBytes(StandardCharsets.US_ASCII), actualHash.getBytes(StandardCharsets.US_ASCII))) {
                throw new java.io.IOException("Remote download failed size or SHA-256 integrity verification.");
            }
            // Atomic create-if-absent publication; never rely on a racy move existence check.
            Files.createLink(target, temporary);
            Files.delete(temporary);
            return new RemoteDownloadResult(target, copied, actualHash);
        } finally { Files.deleteIfExists(temporary); }
    }


    /** Reads a bounded byte range from a remotely shared reference without downloading the entire file. */
    public RemoteRangeResult readRemoteReferenceRange(String baseUrl, String grantId, String relativePath,
                                                       long offset, int length,
                                                       NetworkMembershipService membership) throws Exception {
        if (offset < 0 || length < 0 || length > 8 * 1024 * 1024) {
            throw new IllegalArgumentException("Remote read range is outside the permitted bounds.");
        }
        Map<String, Object> metadata = statRemoteReference(baseUrl, grantId, relativePath, membership);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The selected remote reference is not a file.");
        long size = number(metadata.get("size"));
        if (offset >= size || length == 0) return new RemoteRangeResult(new byte[0], size,
                String.valueOf(metadata.getOrDefault("sha256", "")));
        int bounded = (int) Math.min((long) length, size - offset);
        String path = referencePath(grantId, "content", relativePath) + "&offset=" + offset + "&length=" + bounded;
        return readRange(baseUrl, path, offset, bounded, size, membership);
    }

    /** Reads a bounded byte range from a remote managed file. */
    public RemoteRangeResult readRemoteManagedRange(String baseUrl, String fileId, long expectedSize,
                                                     long offset, int length,
                                                     NetworkMembershipService membership) throws Exception {
        if (offset < 0 || length < 0 || length > 8 * 1024 * 1024 || expectedSize < 0) {
            throw new IllegalArgumentException("Remote managed-file range is outside the permitted bounds.");
        }
        if (offset >= expectedSize || length == 0) return new RemoteRangeResult(new byte[0], expectedSize, "");
        int bounded = (int) Math.min((long) length, expectedSize - offset);
        String path = "/network/managed/files/" + encode(fileId) + "/content?offset=" + offset + "&length=" + bounded;
        return readRange(baseUrl, path, offset, bounded, expectedSize, membership);
    }

    private RemoteRangeResult readRange(String baseUrl, String path, long offset, int length, long expectedSize,
                                         NetworkMembershipService membership) throws Exception {
        HttpRequest.Builder request = request(baseUrl, path, "GET", new byte[0], membership);
        request.timeout(Duration.ofSeconds(30));
        HttpResponse<InputStream> response = client.send(request.GET().build(), HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 206) {
            try (InputStream ignored = response.body()) { }
            throw new java.io.IOException("Remote range read failed with HTTP " + response.statusCode() + ".");
        }
        String contentRange = response.headers().firstValue("Content-Range").orElse("");
        String expectedPrefix = "bytes " + offset + "-" + (offset + length - 1) + "/" + expectedSize;
        if (!expectedPrefix.equals(contentRange)) {
            try (InputStream ignored = response.body()) { }
            throw new java.io.IOException("Remote range response did not match the requested byte range.");
        }
        String fullHash = response.headers().firstValue("X-Content-SHA256").orElse("").toLowerCase(java.util.Locale.ROOT);
        String rangeHash = response.headers().firstValue("X-Content-Range-SHA256").orElse("").toLowerCase(java.util.Locale.ROOT);
        try (InputStream input = response.body()) {
            byte[] bytes = input.readNBytes(length);
            if (bytes.length != length || input.read() != -1) throw new java.io.IOException("Remote range response length did not match its Content-Range.");
            return validateRangePayload(bytes, contentRange, rangeHash, fullHash, offset, length, expectedSize);
        }
    }

    /** Validates the exact range framing and its SHA-256 digest before exposing bytes to callers. */
    static RemoteRangeResult validateRangePayload(byte[] bytes, String contentRange, String rangeHash,
                                                   String fullHash, long offset, int length,
                                                   long expectedSize) throws java.io.IOException {
        if (offset < 0 || length <= 0 || expectedSize < 0 || offset > expectedSize - length) {
            throw new java.io.IOException("Remote range metadata is outside the expected file bounds.");
        }
        String expectedRange = "bytes " + offset + "-" + (offset + length - 1) + "/" + expectedSize;
        if (!expectedRange.equals(contentRange)) {
            throw new java.io.IOException("Remote range response did not match the requested byte range.");
        }
        if (bytes == null || bytes.length != length) {
            throw new java.io.IOException("Remote range response length did not match its Content-Range.");
        }
        String normalizedRangeHash = rangeHash == null ? "" : rangeHash.toLowerCase(java.util.Locale.ROOT);
        if (!normalizedRangeHash.matches("[a-f0-9]{64}")) {
            throw new java.io.IOException("Remote range response did not include a valid range SHA-256 digest.");
        }
        String normalizedFullHash = fullHash == null ? "" : fullHash.toLowerCase(java.util.Locale.ROOT);
        if (!normalizedFullHash.isBlank() && !normalizedFullHash.matches("[a-f0-9]{64}")) {
            throw new java.io.IOException("Remote range response included an invalid full-content digest.");
        }
        try {
            String actualRangeHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (!MessageDigest.isEqual(normalizedRangeHash.getBytes(StandardCharsets.US_ASCII),
                    actualRangeHash.getBytes(StandardCharsets.US_ASCII))) {
                throw new java.io.IOException("Remote range content failed SHA-256 integrity verification.");
            }
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable in this Java runtime.", impossible);
        }
        return new RemoteRangeResult(bytes, expectedSize, normalizedFullHash);
    }

    public Map<String, Object> deleteRemoteReference(String baseUrl, String grantId, String relativePath,
                                                      NetworkMembershipService membership) throws Exception {
        return deleteJson(baseUrl, referencePath(grantId, null, relativePath), membership);
    }

    public Map<String, Object> uploadManagedFile(String baseUrl, String destinationRelativePath, Path source,
                                                  NetworkMembershipService membership, long maximumBytes) throws Exception {
        Path file = source.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Managed placement source must be a regular non-symlink file.");
        }
        long size = Files.size(file);
        if (size < 0 || size > maximumBytes) throw new IllegalArgumentException("Source file exceeds the configured managed-file transfer limit.");
        String fullHash = sha256(file);
        String transferId = java.util.UUID.randomUUID().toString();
        try {
            createManagedTransfer(baseUrl, transferId, destinationRelativePath, size, fullHash, membership);
            return resumeManagedFile(baseUrl, transferId, file, membership, maximumBytes);
        } catch (Exception interrupted) {
            throw new RemoteTransferInterruptedException(transferId,
                    "Direct transfer was interrupted. The destination retained verified chunks; resume with this transfer ID.", interrupted);
        }
    }

    /** Idempotently creates a receiver session with a sender-persisted ID before sending any bytes. */
    public Map<String,Object> createManagedTransfer(String baseUrl, String transferId, String destinationRelativePath,
                                                     long size, String sha256,
                                                     NetworkMembershipService membership) throws Exception {
        String canonicalId;
        try {
            canonicalId = java.util.UUID.fromString(transferId).toString();
            if (!canonicalId.equalsIgnoreCase(transferId)) throw new IllegalArgumentException("Transfer ID must be a canonical UUID.");
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("Transfer ID must be a canonical UUID.", invalid);
        }
        if (size < 0 || !sha256.matches("[a-fA-F0-9]{64}")) {
            throw new IllegalArgumentException("Managed transfer metadata is invalid.");
        }
        return postJson(baseUrl, "/network/transfers", Map.of("transferId", canonicalId,
                "path", destinationRelativePath, "size", size, "sha256", sha256.toLowerCase(java.util.Locale.ROOT)), membership);
    }

    /** Resumes an existing receiver-side session after a disconnect or process restart. */
    public Map<String,Object> resumeManagedFile(String baseUrl, String transferId, Path source,
                                                NetworkMembershipService membership, long maximumBytes) throws Exception {
        Path file = source.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Managed placement source must be a regular non-symlink file.");
        }
        long size = Files.size(file);
        String fullHash = sha256(file);
        if (size < 0 || size > maximumBytes) throw new IllegalArgumentException("Source file exceeds the configured managed-file transfer limit.");
        Map<String,Object> status = getJson(baseUrl, "/network/transfers/" + encode(transferId), membership);
        if (number(status.get("size")) != size || !fullHash.equals(String.valueOf(status.get("sha256")))) {
            throw new SecurityException("Local source no longer matches the original transfer session.");
        }
        if ("COMMITTED".equals(status.get("state"))) {
            Object value = status.get("receipt");
            if (value instanceof Map<?, ?> receipt) {
                Map<String,Object> result = new LinkedHashMap<>();
                for (Map.Entry<?,?> entry : receipt.entrySet()) {
                    if (entry.getKey() instanceof String key) result.put(key, entry.getValue());
                }
                result.put("transferId", transferId);
                result.put("transferState", "COMMITTED");
                return result;
            }
            throw new SecurityException("Destination reports a committed transfer without its durable receipt.");
        }
        int chunkSize = Math.toIntExact(number(status.get("chunkSize")));
        if (chunkSize < 64 * 1024 || chunkSize > 16 * 1024 * 1024) throw new SecurityException("Destination advertised an invalid chunk size.");
        java.util.Set<Integer> received = new java.util.HashSet<>();
        Object receivedValue = status.get("receivedChunks");
        if (receivedValue instanceof java.util.List<?> list) {
            for (Object item : list) if (item instanceof Number n) received.add(n.intValue());
        }
        try (InputStream input = Files.newInputStream(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            int index = 0;
            while (true) {
                byte[] chunk = input.readNBytes(chunkSize);
                if (chunk.length == 0) break;
                if (!received.contains(index)) putTransferChunk(baseUrl, transferId, index, chunk, membership);
                index++;
            }
            if (index != number(status.get("chunkCount"))) throw new SecurityException("Source changed while the transfer was being read.");
        }
        return postJson(baseUrl, "/network/transfers/" + encode(transferId) + "/commit", Map.of(), membership);
    }

    public Map<String,Object> transferStatus(String baseUrl, String transferId,
                                             NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, "/network/transfers/" + encode(transferId), membership);
    }

    /** Fetches source or destination metadata for a coordinated transfer plan. */
    public Map<String,Object> coordinatedMetadata(String baseUrl, String role, String rootId, String relativePath,
                                                  NetworkMembershipService membership) throws Exception {
        String path = "/network/coordinated/metadata?role=" + encode(role)
                + "&rootId=" + encode(rootId) + "&path=" + encode(relativePath == null ? "" : relativePath);
        return getJson(baseUrl, path, membership);
    }

    /** Creates the destination session for a signed coordinated ticket. */
    public Map<String,Object> createCoordinatedTransfer(String baseUrl, String transferId,
                                                        Map<String,Object> ticket, String ticketSignature,
                                                        NetworkMembershipService membership) throws Exception {
        Map<String,Object> body = new LinkedHashMap<>();
        body.put("kind", "coordinated");
        body.put("transferId", transferId);
        body.put("ticket", ticket);
        body.put("ticketSignature", ticketSignature);
        return postJson(baseUrl, "/network/transfers", body, membership);
    }

    /** Asks the source device to execute a coordinated ticket directly to the destination. */
    public Map<String,Object> executeCoordinatedTransfer(String sourceBaseUrl, Map<String,Object> ticket,
                                                         String ticketSignature,
                                                         NetworkMembershipService membership) throws Exception {
        Map<String,Object> body = new LinkedHashMap<>();
        body.put("ticket", ticket);
        body.put("ticketSignature", ticketSignature);
        return postJson(sourceBaseUrl, "/network/coordinated/transfers", body, membership);
    }

    public Map<String,Object> coordinatedStatus(String sourceBaseUrl, String requestId,
                                                NetworkMembershipService membership) throws Exception {
        return getJson(sourceBaseUrl, "/network/coordinated/transfers/" + encode(requestId), membership);
    }

    public Map<String,Object> abortTransfer(String baseUrl, String transferId,
                                            NetworkMembershipService membership) throws Exception {
        return deleteJson(baseUrl, "/network/transfers/" + encode(transferId), membership);
    }

    /**
     * Sends one already-bounded chunk to a receiver session. Exposed so
     * interruption and resume tests can seed verified chunks without
     * reimplementing the authenticated chunk envelope.
     */
    public void sendTransferChunk(String baseUrl, String transferId, int index, byte[] bytes,
                                  NetworkMembershipService membership) throws Exception {
        putTransferChunk(baseUrl, transferId, index, bytes, membership);
    }

    private void putTransferChunk(String baseUrl, String transferId, int index, byte[] bytes,
                                 NetworkMembershipService membership) throws Exception {
        String chunkHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        String path = "/network/transfers/" + encode(transferId) + "/chunks/" + index;
        Map<String,Object> metadata = new LinkedHashMap<>();
        metadata.put("transferId", transferId); metadata.put("index", index);
        metadata.put("length", bytes.length); metadata.put("sha256", chunkHash);
        byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(RemotePeerClient.normalizeBaseUrl(baseUrl) + path))
                .timeout(Duration.ofMinutes(3))
                .header("Accept", "application/json")
                .header("Content-Type", "application/octet-stream")
                .header("X-PC-Chunk-Length", Integer.toString(bytes.length))
                .header("X-PC-Chunk-SHA256", chunkHash);
        membership.createAuthHeaders("PUT", path, signedMetadata).forEach(builder::header);
        HttpResponse<String> response = client.send(builder.PUT(HttpRequest.BodyPublishers.ofByteArray(bytes)).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        parseResponse(response.statusCode(), response.body());
    }

    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[256 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    public Map<String, Object> listManagedFiles(String baseUrl, NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, "/network/managed/files", membership);
    }

    public Map<String, Object> statManagedFile(String baseUrl, String fileId, NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, "/network/managed/files/" + encode(fileId), membership);
    }

    public RemoteDownloadResult downloadManagedFile(String baseUrl, String fileId, Path destination,
                                                       NetworkMembershipService membership, long maximumBytes) throws Exception {
        Map<String, Object> metadata = statManagedFile(baseUrl, fileId, membership);
        long expectedSize = number(metadata.get("size"));
        String expectedHash = String.valueOf(metadata.get("sha256")).toLowerCase(java.util.Locale.ROOT);
        if (expectedSize < 0 || expectedSize > maximumBytes || !expectedHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Remote managed-file metadata is invalid or exceeds the local transfer limit.");
        }
        return downloadBinary(baseUrl, "/network/managed/files/" + encode(fileId) + "/content", expectedSize,
                expectedHash, destination, membership, maximumBytes);
    }

    public Map<String, Object> deleteManagedFile(String baseUrl, String fileId, NetworkMembershipService membership) throws Exception {
        return deleteJson(baseUrl, "/network/managed/files/" + encode(fileId), membership);
    }

    public Map<String, Object> listFilesystemRoots(String baseUrl, NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, "/network/fs/roots", membership);
    }

    public Map<String, Object> browseFilesystem(String baseUrl, String rootId, String relativePath,
                                                NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, filesystemPath(rootId, "entries", relativePath), membership);
    }

    public Map<String, Object> statFilesystem(String baseUrl, String rootId, String relativePath,
                                              NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, filesystemPath(rootId, "stat", relativePath), membership);
    }

    /** Reads a bounded byte range from a remote eligible filesystem file. */
    public RemoteRangeResult readRemoteFilesystemRange(String baseUrl, String rootId, String relativePath,
                                                       long offset, int length,
                                                       NetworkMembershipService membership) throws Exception {
        if (offset < 0 || length < 0 || length > 8 * 1024 * 1024) {
            throw new IllegalArgumentException("Remote filesystem range is outside the permitted bounds.");
        }
        Map<String, Object> metadata = statFilesystem(baseUrl, rootId, relativePath, membership);
        if (!"FILE".equals(metadata.get("kind"))) {
            throw new IllegalArgumentException("The selected remote path is not a regular file.");
        }
        long size = number(metadata.get("size"));
        if (size < 0) throw new java.io.IOException("Remote filesystem stat did not report a valid size.");
        if (offset >= size || length == 0) return new RemoteRangeResult(new byte[0], size, "");
        int bounded = (int) Math.min((long) length, size - offset);
        String path = filesystemPath(rootId, "content", relativePath) + "&offset=" + offset + "&length=" + bounded;
        return readRange(baseUrl, path, offset, bounded, size, membership);
    }

    public Map<String, Object> createFilesystemDirectory(String baseUrl, String rootId, String relativePath,
                                                          NetworkMembershipService membership) throws Exception {
        return postJson(baseUrl, "/network/fs/" + encode(rootId) + "/directories",
                Map.of("path", relativePath == null ? "" : relativePath), membership);
    }

    public Map<String, Object> moveFilesystemEntry(String baseUrl, String rootId, String from, String to,
                                                    boolean overwrite, String approvalId,
                                                    NetworkMembershipService membership) throws Exception {
        return moveFilesystemEntry(baseUrl, rootId, from, to, overwrite, approvalId, "", membership);
    }

    public Map<String, Object> moveFilesystemEntry(String baseUrl, String rootId, String from, String to,
                                                    boolean overwrite, String approvalId,
                                                    String destinationApprovalId,
                                                    NetworkMembershipService membership) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("from", from);
        body.put("to", to);
        body.put("overwrite", overwrite);
        body.put("approvalId", approvalId == null ? "" : approvalId);
        body.put("destinationApprovalId", destinationApprovalId == null ? "" : destinationApprovalId);
        return postJson(baseUrl, "/network/fs/" + encode(rootId) + "/move", body, membership);
    }

    public Map<String, Object> deleteFilesystemEntry(String baseUrl, String rootId, String relativePath,
                                                      boolean recursive, String approvalId,
                                                      NetworkMembershipService membership) throws Exception {
        String path = "/network/fs/" + encode(rootId) + "/entry?path=" + encode(relativePath == null ? "" : relativePath)
                + "&recursive=" + recursive + "&approvalId=" + encode(approvalId == null ? "" : approvalId);
        return deleteJson(baseUrl, path, membership);
    }

    public Map<String, Object> requestFilesystemApproval(String baseUrl, String rootId, String relativePath,
                                                          String operation, long ttlSeconds,
                                                          NetworkMembershipService membership) throws Exception {
        return postJson(baseUrl, "/network/fs/" + encode(rootId) + "/approvals",
                Map.of("path", relativePath == null ? "" : relativePath, "operation", operation,
                        "ttlSeconds", ttlSeconds), membership);
    }

    public Map<String, Object> filesystemApprovalStatus(String baseUrl, String approvalId,
                                                        NetworkMembershipService membership) throws Exception {
        return getJson(baseUrl, "/network/fs/approvals/" + encode(approvalId), membership);
    }

    public Map<String, Object> uploadFilesystemFile(String baseUrl, String rootId, String relativePath, Path source,
                                                     boolean overwrite, String approvalId,
                                                     NetworkMembershipService membership, long maximumBytes) throws Exception {
        Path file = source.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Filesystem upload source must be a regular non-symlink file.");
        }
        long size = Files.size(file);
        if (size < 0 || size > maximumBytes) throw new IllegalArgumentException("Source file exceeds the configured transfer limit.");
        String hash = sha256(file);
        String path = "/network/fs/" + encode(rootId) + "/content?path=" + encode(relativePath == null ? "" : relativePath)
                + "&overwrite=" + overwrite;
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("path", relativePath == null ? "" : relativePath);
        metadata.put("size", size);
        metadata.put("sha256", hash);
        metadata.put("overwrite", overwrite);
        metadata.put("approvalId", approvalId == null ? "" : approvalId);
        byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(RemotePeerClient.normalizeBaseUrl(baseUrl) + path))
                .timeout(Duration.ofMinutes(30))
                .header("Accept", "application/json")
                .header("Content-Type", "application/octet-stream")
                .header("X-PC-File-Length", Long.toString(size))
                .header("X-PC-File-SHA256", hash);
        if (approvalId != null && !approvalId.isBlank()) builder.header("X-PC-Approval-ID", approvalId);
        membership.createAuthHeaders("PUT", path, signedMetadata).forEach(builder::header);
        HttpResponse<String> response = client.send(builder.PUT(HttpRequest.BodyPublishers.ofFile(file)).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return parseResponse(response.statusCode(), response.body());
    }

    public RemoteDownloadResult downloadFilesystemFile(String baseUrl, String rootId, String relativePath,
                                                        Path destination, NetworkMembershipService membership,
                                                        long maximumBytes) throws Exception {
        Map<String, Object> metadata = statFilesystem(baseUrl, rootId, relativePath, membership);
        if (!"FILE".equals(metadata.get("kind"))) throw new IllegalArgumentException("The selected remote path is not a regular file.");
        long expectedSize = number(metadata.get("size"));
        if (expectedSize < 0 || expectedSize > maximumBytes) throw new IllegalArgumentException("Remote file exceeds the configured download limit.");
        String path = filesystemPath(rootId, "content", relativePath);
        HttpRequest.Builder request = request(baseUrl, path, "GET", new byte[0], membership);
        request.timeout(Duration.ofMinutes(30));
        HttpResponse<InputStream> response = client.send(request.GET().build(), HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            try (InputStream ignored = response.body()) { }
            throw new java.io.IOException("Remote filesystem download failed with HTTP " + response.statusCode() + ".");
        }
        String expectedHash = response.headers().firstValue("X-Content-SHA256").orElse("").toLowerCase(java.util.Locale.ROOT);
        if (!expectedHash.matches("[a-f0-9]{64}")) {
            try (InputStream ignored = response.body()) { }
            throw new java.io.IOException("Remote filesystem response did not include a valid SHA-256 digest.");
        }
        Path requested = destination.toAbsolutePath().normalize();
        Path requestedParent = requested.getParent();
        if (requestedParent == null || requested.getFileName() == null || !Files.isDirectory(requestedParent)) {
            try (InputStream ignored = response.body()) { }
            throw new IllegalArgumentException("Destination parent directory does not exist.");
        }
        Path parent = requestedParent.toRealPath();
        Path target = parent.resolve(requested.getFileName().toString());
        if (Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try (InputStream ignored = response.body()) { }
            throw new IllegalArgumentException("Destination already exists; PersonalCloud will not overwrite it.");
        }
        Path temporary = Files.createTempFile(parent, ".personalcloud-download-", ".part");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            try (InputStream input = response.body(); OutputStream output = Files.newOutputStream(temporary,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > maximumBytes || copied > expectedSize) throw new java.io.IOException("Remote file exceeded its declared or configured size limit.");
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
            }
            String actualHash = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedSize || !expectedHash.equals(actualHash)) {
                throw new java.io.IOException("Remote download failed size or SHA-256 integrity verification.");
            }
            Files.createLink(target, temporary);
            Files.delete(temporary);
            return new RemoteDownloadResult(target, copied, actualHash);
        } finally { Files.deleteIfExists(temporary); }
    }

    private static String filesystemPath(String rootId, String action, String relativePath) {
        return "/network/fs/" + encode(rootId) + "/" + action + "?path=" + encode(relativePath == null ? "" : relativePath);
    }

    private RemoteDownloadResult downloadBinary(String baseUrl, String path, long expectedSize, String expectedHash,
                                                 Path destination, NetworkMembershipService membership,
                                                 long maximumBytes) throws Exception {
        Path requested = destination.toAbsolutePath().normalize();
        Path requestedParent = requested.getParent();
        if (requestedParent == null || requested.getFileName() == null || !Files.isDirectory(requestedParent)) throw new IllegalArgumentException("Destination parent directory does not exist.");
        Path parent = requestedParent.toRealPath();
        Path target = parent.resolve(requested.getFileName().toString());
        if (Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Destination already exists; PersonalCloud will not overwrite it.");
        Path temporary = Files.createTempFile(parent, ".personalcloud-download-", ".part");
        try {
            HttpRequest.Builder request = request(baseUrl, path, "GET", new byte[0], membership);
            request.timeout(Duration.ofMinutes(30));
            HttpResponse<InputStream> response = client.send(request.GET().build(), HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                try (InputStream ignored = response.body()) { }
                throw new java.io.IOException("Remote file download failed with HTTP " + response.statusCode() + ".");
            }
            String responseHash = response.headers().firstValue("X-Content-SHA256").orElse("").toLowerCase(java.util.Locale.ROOT);
            if (!expectedHash.equals(responseHash)) throw new java.io.IOException("Remote file response digest does not match its signed metadata.");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            try (InputStream input = response.body(); OutputStream output = Files.newOutputStream(temporary,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied = Math.addExact(copied, read);
                    if (copied > maximumBytes || copied > expectedSize) throw new java.io.IOException("Remote file exceeded its declared or configured size limit.");
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                }
            }
            String actualHash = HexFormat.of().formatHex(digest.digest());
            if (copied != expectedSize || !expectedHash.equals(actualHash)) throw new java.io.IOException("Remote download failed size or SHA-256 integrity verification.");
            // Atomic create-if-absent publication; never rely on a racy move existence check.
            Files.createLink(target, temporary);
            Files.delete(temporary);
            return new RemoteDownloadResult(target, copied, actualHash);
        } finally { Files.deleteIfExists(temporary); }
    }

    private HttpRequest.Builder request(String baseUrl, String path, String method, byte[] body,
                                        NetworkMembershipService membership) throws Exception {
        String base = RemotePeerClient.normalizeBaseUrl(baseUrl);
        Map<String, String> auth = membership.createAuthHeaders(method, path, body);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .timeout(Duration.ofSeconds(30)).header("Accept", "application/json");
        auth.forEach(request::header);
        return request;
    }

    private static String referencePath(String grantId, String operation, String relativePath) {
        String path = "/network/references/" + encode(grantId);
        if (operation != null) path += "/" + operation;
        return path + "?path=" + encode(relativePath == null ? "" : relativePath);
    }

    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static long number(Object value) {
        if (value instanceof Number number) return number.longValue();
        try { return Long.parseLong(String.valueOf(value)); } catch (Exception ignored) { return -1; }
    }

    private static Map<String, Object> parseResponse(int status, String body) throws Exception {
        Map<String, Object> result;
        try { result = Json.object(body); }
        catch (Exception malformed) { throw new java.io.IOException("The network member returned an invalid JSON response (HTTP " + status + ").", malformed); }
        if (status < 200 || status >= 300) {
            Object error = result.get("error");
            throw new java.io.IOException(error == null ? "Network member returned HTTP " + status : String.valueOf(error));
        }
        return result;
    }

    public record RemoteDownloadResult(Path path, long sizeBytes, String sha256) { }
    public record RemoteRangeResult(byte[] bytes, long totalSize, String sha256) { }
}
