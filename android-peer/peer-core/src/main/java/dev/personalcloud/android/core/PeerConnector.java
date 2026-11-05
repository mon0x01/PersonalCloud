package dev.personalcloud.android.core;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** HTTPS-only (except loopback HTTP) client for the PersonalCloud node protocol. */
public final class PeerConnector {
    private PeerConnector() { }
    public static final class TransferInterruptedException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String transferId;
        public TransferInterruptedException(String transferId, Throwable cause) {
            super("Direct transfer interrupted. Receiver session " + transferId
                    + " retains verified chunks for a future resume.", cause);
            this.transferId = transferId;
        }
        public String transferId() { return transferId; }
    }

    public static final class PairResult { public final String nodeId,nodeName,token,baseUrl; PairResult(String i,String n,String t,String u){nodeId=i;nodeName=n;token=t;baseUrl=u;} }
    @FunctionalInterface public interface InputStreamSource { InputStream open() throws Exception; }

    /** Small JSON GET helper used by the signed network-membership protocol. */
    static Map<String,Object> getJson(String base,String path,String caPath)throws Exception{
        HttpURLConnection connection=open(normalize(base)+path,caPath);
        connection.setRequestMethod("GET");connection.setConnectTimeout(8000);connection.setReadTimeout(15000);
        int status=connection.getResponseCode();Map<String,Object> result=readJson(connection);
        if(status!=200)throw new IllegalStateException("PersonalCloud network request failed with HTTP "+status+": "+String.valueOf(result.get("error")));
        return result;
    }

    /** Authenticated JSON GET for the signed PersonalCloud network API. */
    static Map<String,Object> getSignedJson(String base,String path,Map<String,String> headers,String caPath)throws Exception{
        HttpURLConnection connection=open(normalize(base)+path,caPath);
        connection.setRequestMethod("GET");connection.setConnectTimeout(8000);connection.setReadTimeout(15000);
        for(Map.Entry<String,String> entry:headers.entrySet())connection.setRequestProperty(entry.getKey(),entry.getValue());
        int status=connection.getResponseCode();Map<String,Object> result=readJson(connection);
        if(status<200||status>=300)throw new IllegalStateException("Authenticated PersonalCloud request failed with HTTP "+status+": "+String.valueOf(result.get("error")));
        return result;
    }

    /** Authenticated JSON DELETE for signed network storage operations. */
    static Map<String,Object> deleteSignedJson(String base, String path, Map<String,String> headers, String caPath) throws Exception {
        HttpURLConnection connection = open(normalize(base) + path, caPath);
        connection.setRequestMethod("DELETE");
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(30000);
        for (Map.Entry<String,String> entry : headers.entrySet()) connection.setRequestProperty(entry.getKey(), entry.getValue());
        int status = connection.getResponseCode();
        Map<String,Object> result = readJson(connection);
        if (status != 200) throw new IllegalStateException("Authenticated PersonalCloud deletion failed with HTTP " + status + ": " + String.valueOf(result.get("error")));
        return result;
    }

    /** Signed random-access read for the private network storage API. */
    static RangeResult readSignedRange(String base, String path, long offset, int length,
                                       NetworkMembershipClient membership, String caPath) throws Exception {
        if (offset < 0 || length < 1 || length > 8 * 1024 * 1024 || offset > Long.MAX_VALUE - length) {
            throw new IllegalArgumentException("Signed remote range must be between 1 byte and 8 MiB.");
        }
        String rawPath = path;
        HttpURLConnection connection = open(normalize(base) + rawPath, caPath);
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(30000);
        for (Map.Entry<String,String> header : membership.createAuthHeaders("GET", rawPath, new byte[0]).entrySet()) {
            connection.setRequestProperty(header.getKey(), header.getValue());
        }
        try {
            int status = connection.getResponseCode();
            String contentRange = connection.getHeaderField("Content-Range");
            if (status == 416) {
                if (contentRange == null || !contentRange.matches("bytes \\*/[0-9]+")) {
                    throw new IllegalStateException("Signed peer returned an invalid unsatisfied-range response.");
                }
                long total = Long.parseLong(contentRange.substring(contentRange.indexOf('/') + 1));
                if (offset < total) throw new IllegalStateException("Signed peer rejected a satisfiable byte range.");
                InputStream errorBody = connection.getErrorStream();
                if (errorBody != null) errorBody.close();
                return new RangeResult(new byte[0], total, "");
            }
            if (status != 206) throw new IllegalStateException("Signed remote range failed with HTTP " + status + ": " + readText(connection));
            if (contentRange == null || !contentRange.matches("bytes [0-9]+-[0-9]+/[0-9]+")) {
                throw new IllegalStateException("Signed peer returned an invalid Content-Range.");
            }
            String[] fields = contentRange.substring(6).split("[-/]");
            long start = Long.parseLong(fields[0]), end = Long.parseLong(fields[1]), total = Long.parseLong(fields[2]);
            long expectedEnd = Math.min(offset + length - 1L, total - 1L);
            if (start != offset || end != expectedEnd || end < start || total <= end) {
                throw new IllegalStateException("Signed peer returned a byte range different from the request.");
            }
            byte[] bytes;
            try (InputStream input = new BufferedInputStream(connection.getInputStream());
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192]; int read;
                while ((read = input.read(buffer)) != -1) {
                    if (output.size() + read > length) throw new IllegalStateException("Signed peer exceeded the requested byte range.");
                    output.write(buffer, 0, read);
                }
                bytes = output.toByteArray();
            }
            if (bytes.length != end - start + 1) throw new IllegalStateException("Signed peer returned a truncated byte range.");
            String expectedHash = connection.getHeaderField("X-Content-Range-SHA256");
            String actualHash = hex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (expectedHash == null || !MessageDigest.isEqual(expectedHash.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII),
                    actualHash.getBytes(StandardCharsets.US_ASCII))) {
                throw new SecurityException("Signed remote range failed SHA-256 verification.");
            }
            return new RangeResult(bytes, total, actualHash);
        } finally { connection.disconnect(); }
    }

    /** Direct signed managed-file upload; only a small metadata descriptor is signed, never a buffered file body. */
    static Map<String,Object> putSignedManagedFile(String base, String destinationRelativePath, Path source,
                                                   NetworkMembershipClient membership, String caPath,
                                                   long maximumBytes) throws Exception {
        Path file = source.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Managed placement source must be a regular non-symlink file.");
        }
        long size = Files.size(file);
        if (size < 0 || size > maximumBytes) throw new IllegalArgumentException("Managed source exceeds the configured file limit.");
        return putSignedManagedFile(base, destinationRelativePath,
                () -> Files.newInputStream(file, java.nio.file.LinkOption.NOFOLLOW_LINKS), size,
                membership, caPath, maximumBytes);
    }

    /**
     * Direct upload from a reopenable content source (for example Android SAF). The content is
     * hashed in a first streaming pass and streamed directly to the peer in a second pass; no
     * local staging copy is created. The second pass is re-hashed to detect source mutation.
     */
    static Map<String,Object> putSignedManagedFile(String base, String destinationRelativePath,
                                                   InputStreamSource source, long declaredSize,
                                                   NetworkMembershipClient membership, String caPath,
                                                   long maximumBytes) throws Exception {
        if (source == null || membership == null) throw new IllegalArgumentException("Managed upload source and membership are required.");
        String normalizedPath = normalizeManagedDestinationPath(destinationRelativePath);
        if (declaredSize < -1) throw new IllegalArgumentException("Managed source size metadata is invalid.");
        if (declaredSize > maximumBytes) throw new IllegalArgumentException("Managed source exceeds the configured file limit.");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long size = 0;
        try (InputStream input = source.open()) {
            if (input == null) throw new IllegalStateException("Managed upload source returned no input stream.");
            byte[] buffer = new byte[128 * 1024]; int read;
            while ((read = input.read(buffer)) != -1) {
                size = Math.addExact(size, read);
                if (size > maximumBytes || (declaredSize >= 0 && size > declaredSize)) {
                    throw new IllegalArgumentException("Managed source exceeds its declared or configured file limit.");
                }
                digest.update(buffer, 0, read);
            }
        }
        if (declaredSize >= 0 && size != declaredSize) throw new IllegalStateException("Managed source size does not match provider metadata.");
        String sha256 = hex(digest.digest());
        String rawPath = "/network/managed/files?path=" + encode(normalizedPath);
        Map<String,Object> metadata = new java.util.LinkedHashMap<>();
        metadata.put("path", normalizedPath); metadata.put("size", size); metadata.put("sha256", sha256);
        byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
        HttpURLConnection connection = open(normalize(base) + rawPath, caPath);
        connection.setRequestMethod("PUT"); connection.setDoOutput(true);
        connection.setConnectTimeout(8000); connection.setReadTimeout(30 * 60 * 1000);
        connection.setFixedLengthStreamingMode(size);
        connection.setRequestProperty("Content-Type", "application/octet-stream");
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("X-PC-File-Length", Long.toString(size));
        connection.setRequestProperty("X-PC-File-SHA256", sha256);
        for (Map.Entry<String,String> header : membership.createAuthHeaders("PUT", rawPath, signedMetadata).entrySet()) {
            connection.setRequestProperty(header.getKey(), header.getValue());
        }
        try {
            MessageDigest uploadedDigest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = source.open();
                 OutputStream output = new BufferedOutputStream(connection.getOutputStream())) {
                if (input == null) throw new IllegalStateException("Managed upload source returned no input stream for transfer.");
                byte[] buffer = new byte[128 * 1024]; int read; long sent = 0;
                while ((read = input.read(buffer)) != -1) {
                    sent = Math.addExact(sent, read);
                    if (sent > size) throw new IllegalStateException("Managed source changed size during transfer.");
                    uploadedDigest.update(buffer, 0, read); output.write(buffer, 0, read);
                }
                String uploadedHash = hex(uploadedDigest.digest());
                if (sent != size || !MessageDigest.isEqual(sha256.getBytes(StandardCharsets.US_ASCII), uploadedHash.getBytes(StandardCharsets.US_ASCII))) {
                    throw new SecurityException("Managed source changed between digest verification and transfer.");
                }
            }
            int status = connection.getResponseCode();
            Map<String,Object> response = readJson(connection);
            if (status != 201) throw new IllegalStateException("Managed placement failed with HTTP " + status + ": " + String.valueOf(response.get("error")));
            if (!sha256.equals(String.valueOf(response.get("sha256")))) throw new SecurityException("Destination did not confirm the uploaded file digest.");
            return response;
        } finally { connection.disconnect(); }
    }

    /** Chunked direct managed placement with a receiver-persisted session and restart-safe resume state. */
    static Map<String,Object> putSignedResumableManagedFile(String base, String destinationRelativePath,
                                                            InputStreamSource source, long declaredSize,
                                                            NetworkMembershipClient membership, String caPath,
                                                            long maximumBytes) throws Exception {
        if (source == null || membership == null) throw new IllegalArgumentException("Managed upload source and membership are required.");
        String normalizedPath = normalizeManagedDestinationPath(destinationRelativePath);
        if (declaredSize < -1 || declaredSize > maximumBytes) throw new IllegalArgumentException("Managed source size metadata is invalid.");
        MessageDigest initial = MessageDigest.getInstance("SHA-256");
        long size = 0;
        try (InputStream input = source.open()) {
            if (input == null) throw new IllegalStateException("Managed upload source returned no input stream.");
            byte[] buffer = new byte[128 * 1024]; int read;
            while ((read = input.read(buffer)) != -1) {
                size = Math.addExact(size, read);
                if (size > maximumBytes || (declaredSize >= 0 && size > declaredSize)) throw new IllegalArgumentException("Managed source exceeds its declared or configured limit.");
                initial.update(buffer, 0, read);
            }
        }
        if (declaredSize >= 0 && size != declaredSize) throw new IllegalStateException("Managed source size does not match provider metadata.");
        String fullHash = hex(initial.digest());
        String transferId = java.util.UUID.randomUUID().toString();
        try {
            createSignedTransferSession(base, transferId, normalizedPath, size, fullHash, membership, caPath);
        } catch (Exception failure) {
            // The receiver may have accepted the create request even if its response was lost.
            // Keep the sender-generated ID available so callers can resume the same session.
            throw new TransferInterruptedException(transferId, failure);
        }
        return transferManagedFile(base, transferId, source, size, fullHash, membership, caPath);
    }

    /** Creates a receiver session with a sender-persisted UUID; replaying the request is idempotent. */
    static Map<String,Object> createSignedTransferSession(String base, String transferId,
                                                           String destinationRelativePath, long size,
                                                           String sha256, NetworkMembershipClient membership,
                                                           String caPath) throws Exception {
        String canonicalId;
        try {
            canonicalId = java.util.UUID.fromString(transferId).toString();
            if (!canonicalId.equalsIgnoreCase(transferId)) throw new IllegalArgumentException();
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("Transfer ID must be a canonical UUID.", invalid);
        }
        String normalizedPath = normalizeManagedDestinationPath(destinationRelativePath);
        String normalizedHash = sha256 == null ? "" : sha256.toLowerCase(java.util.Locale.ROOT);
        if (size < 0 || !normalizedHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Managed transfer metadata is invalid.");
        }
        String createPath = "/network/transfers";
        Map<String,Object> createBody = new java.util.LinkedHashMap<>();
        createBody.put("transferId", canonicalId);
        createBody.put("path", normalizedPath);
        createBody.put("size", size);
        createBody.put("sha256", normalizedHash);
        byte[] createBytes = Json.stringify(createBody).getBytes(StandardCharsets.UTF_8);
        Map<String,String> createHeaders = membership.createAuthHeaders("POST", createPath, createBytes);
        return postSignedJson(base, createPath, createBody, createHeaders, caPath);
    }

    /** Reopens an existing receiver-side session after a process restart or network interruption. */
    static Map<String,Object> resumeSignedManagedFile(String base, String transferId,
                                                       InputStreamSource source, long declaredSize,
                                                       NetworkMembershipClient membership, String caPath,
                                                       long maximumBytes) throws Exception {
        if (transferId == null || !transferId.matches("[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("A valid transfer session identifier is required.");
        }
        if (source == null || membership == null || declaredSize < -1 || declaredSize > maximumBytes) {
            throw new IllegalArgumentException("Managed resume source metadata is invalid.");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long size = 0;
        try (InputStream input = source.open()) {
            if (input == null) throw new IllegalStateException("Managed resume source returned no input stream.");
            byte[] buffer = new byte[128 * 1024]; int read;
            while ((read = input.read(buffer)) != -1) {
                size = Math.addExact(size, read);
                if (size > maximumBytes || (declaredSize >= 0 && size > declaredSize)) {
                    throw new IllegalArgumentException("Managed resume source exceeds its declared or configured limit.");
                }
                digest.update(buffer, 0, read);
            }
        }
        if (declaredSize >= 0 && size != declaredSize) throw new IllegalStateException("Managed resume source size does not match provider metadata.");
        return transferManagedFile(base, transferId, source, size, hex(digest.digest()), membership, caPath);
    }

    private static Map<String,Object> transferManagedFile(String base, String transferId,
                                                            InputStreamSource source, long size, String fullHash,
                                                            NetworkMembershipClient membership, String caPath) throws Exception {
        try {
            String statusPath = "/network/transfers/" + encode(transferId);
            Map<String,Object> status = getSignedJson(base, statusPath,
                    membership.createAuthHeaders("GET", statusPath, new byte[0]), caPath);
            if (!(status.get("size") instanceof Number) || ((Number)status.get("size")).longValue() != size
                    || !fullHash.equals(String.valueOf(status.get("sha256")))) {
                throw new SecurityException("Destination transfer session does not match the selected source.");
            }
            if ("COMMITTED".equals(status.get("state"))) {
                Object value = status.get("receipt");
                if (!(value instanceof Map<?,?> receipt)) {
                    throw new SecurityException("Destination reports a committed transfer without its durable receipt.");
                }
                Map<String,Object> result = new java.util.LinkedHashMap<String,Object>();
                for (Map.Entry<?,?> entry : receipt.entrySet()) {
                    if (entry.getKey() instanceof String) result.put((String)entry.getKey(), entry.getValue());
                }
                result.put("transferId", transferId);
                result.put("transferState", "COMMITTED");
                return result;
            }
            int chunkSize = ((Number)status.get("chunkSize")).intValue();
            if (chunkSize < 64 * 1024 || chunkSize > 16 * 1024 * 1024) throw new SecurityException("Destination advertised an invalid chunk size.");
            java.util.HashSet<Integer> received = new java.util.HashSet<Integer>();
            Object chunks = status.get("receivedChunks");
            if (chunks instanceof List<?>) for (Object value : (List<?>)chunks) if (value instanceof Number) received.add(((Number)value).intValue());

            MessageDigest streamed = MessageDigest.getInstance("SHA-256");
            try (InputStream input = source.open()) {
                if (input == null) throw new IllegalStateException("Managed upload source returned no stream for transfer.");
                int index = 0; long sent = 0;
                while (sent < size) {
                    int wanted = (int)Math.min((long)chunkSize, size - sent);
                    byte[] chunk = input.readNBytes(wanted);
                    if (chunk.length != wanted) throw new IllegalStateException("Managed source changed size during transfer.");
                    streamed.update(chunk); sent += chunk.length;
                    if (!received.contains(index)) {
                        String chunkHash = hex(MessageDigest.getInstance("SHA-256").digest(chunk));
                        String chunkPath = statusPath + "/chunks/" + index;
                        Map<String,Object> metadata = new java.util.LinkedHashMap<>();
                        metadata.put("transferId", transferId); metadata.put("index", index);
                        metadata.put("length", chunk.length); metadata.put("sha256", chunkHash);
                        byte[] signedMetadata = Json.stringify(metadata).getBytes(StandardCharsets.UTF_8);
                        HttpURLConnection connection = open(normalize(base) + chunkPath, caPath);
                        connection.setRequestMethod("PUT"); connection.setDoOutput(true);
                        connection.setConnectTimeout(8000); connection.setReadTimeout(180000);
                        connection.setFixedLengthStreamingMode(chunk.length);
                        connection.setRequestProperty("Content-Type", "application/octet-stream");
                        connection.setRequestProperty("X-PC-Chunk-Length", Integer.toString(chunk.length));
                        connection.setRequestProperty("X-PC-Chunk-SHA256", chunkHash);
                        for (Map.Entry<String,String> header : membership.createAuthHeaders("PUT", chunkPath, signedMetadata).entrySet()) {
                            connection.setRequestProperty(header.getKey(), header.getValue());
                        }
                        try (OutputStream output = new BufferedOutputStream(connection.getOutputStream())) { output.write(chunk); }
                        int responseCode = connection.getResponseCode();
                        Map<String,Object> response = readJson(connection);
                        if (responseCode != 200) throw new IllegalStateException("Transfer chunk failed with HTTP " + responseCode + ": " + String.valueOf(response.get("error")));
                        connection.disconnect();
                    }
                    index++;
                }
                if (input.read() != -1 || sent != size || !fullHash.equals(hex(streamed.digest()))) {
                    throw new SecurityException("Managed source changed between hashing and transfer.");
                }
            }
            String commitPath = statusPath + "/commit";
            return postSignedJson(base, commitPath, java.util.Collections.<String,Object>emptyMap(),
                    membership.createAuthHeaders("POST", commitPath,
                            Json.stringify(java.util.Collections.<String,Object>emptyMap()).getBytes(StandardCharsets.UTF_8)), caPath);
        } catch (Exception failure) {
            throw new TransferInterruptedException(transferId, failure);
        }
    }

    private static String normalizeManagedDestinationPath(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("A managed destination path is required.");
        String path = value.replace('\\', '/');
        if (path.startsWith("/") || path.matches("^[A-Za-z]:.*") || path.indexOf('\0') >= 0 || path.length() > 1024) {
            throw new IllegalArgumentException("Managed destination must be a relative path of at most 1024 characters.");
        }
        for (String segment : path.split("/", -1)) {
            if (segment.isBlank() || segment.equals(".") || segment.equals("..") || segment.length() > 255) {
                throw new IllegalArgumentException("Managed destination contains an unsafe path segment.");
            }
        }
        return path;
    }

    /** Authenticated JSON POST; the signature is bound to the exact serialized request body. */
    static Map<String,Object> postSignedJson(String base,String path,Map<String,Object> body,Map<String,String> headers,String caPath)throws Exception{
        HttpURLConnection connection=open(normalize(base)+path,caPath);
        connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setConnectTimeout(8000);connection.setReadTimeout(20000);
        connection.setRequestProperty("Content-Type","application/json; charset=UTF-8");
        for(Map.Entry<String,String> entry:headers.entrySet())connection.setRequestProperty(entry.getKey(),entry.getValue());
        byte[] payload=Json.stringify(body).getBytes(StandardCharsets.UTF_8);connection.setFixedLengthStreamingMode(payload.length);
        try(OutputStream output=connection.getOutputStream()){output.write(payload);}
        int status=connection.getResponseCode();Map<String,Object> result=readJson(connection);
        if(status<200||status>=300)throw new IllegalStateException("Authenticated PersonalCloud request failed with HTTP "+status+": "+String.valueOf(result.get("error")));
        return result;
    }

    /** Small JSON POST helper used by enrollment; the password itself is never transmitted. */
    static Map<String,Object> postJson(String base,String path,Map<String,Object> body,String caPath)throws Exception{
        HttpURLConnection connection=open(normalize(base)+path,caPath);
        connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setConnectTimeout(8000);connection.setReadTimeout(20000);
        connection.setRequestProperty("Content-Type","application/json; charset=UTF-8");
        byte[] payload=Json.stringify(body).getBytes(StandardCharsets.UTF_8);connection.setFixedLengthStreamingMode(payload.length);
        try(OutputStream output=connection.getOutputStream()){output.write(payload);}
        int status=connection.getResponseCode();Map<String,Object> result=readJson(connection);
        if(status!=200)throw new IllegalStateException("PersonalCloud network enrollment failed with HTTP "+status+": "+String.valueOf(result.get("error")));
        return result;
    }

    public static PairResult pair(String base,String nodeId,String nodeName,String code,String caPath)throws Exception{
        String url=normalize(base)+"/node/pair";Map<String,String> form=new HashMap<String,String>();form.put("nodeId",nodeId);form.put("nodeName",nodeName);form.put("code",code);
        HttpURLConnection c=open(url,caPath);c.setRequestMethod("POST");c.setDoOutput(true);c.setConnectTimeout(8000);c.setReadTimeout(12000);c.setRequestProperty("Content-Type","application/x-www-form-urlencoded; charset=UTF-8");byte[] body=form(form).getBytes(StandardCharsets.UTF_8);c.setFixedLengthStreamingMode(body.length);try(OutputStream out=c.getOutputStream()){out.write(body);}Map<String,Object> json=readJson(c);if(c.getResponseCode()!=200)throw new IllegalArgumentException(String.valueOf(json.get("error")));return new PairResult(String.valueOf(json.get("nodeId")),String.valueOf(json.get("nodeName")),String.valueOf(json.get("accessToken")),normalize(base));
    }
    @SuppressWarnings("unchecked") public static List<Map<String,Object>> listShares(String base,String token,String caPath)throws Exception{HttpURLConnection c=authorized(base+"/node/shares",token,caPath);Map<String,Object> j=readJson(c);if(c.getResponseCode()!=200)throw new IllegalStateException(String.valueOf(j.get("error")));Object v=j.get("shares");List<Map<String,Object>> out=new ArrayList<Map<String,Object>>();if(v instanceof List)for(Object item:(List<?>)v)if(item instanceof Map)out.add((Map<String,Object>)item);return out;}
    public static void download(String base,String token,String shareId,Path destination,String caPath)throws Exception{
        Path requested=destination.toAbsolutePath().normalize();
        Path requestedParent=requested.getParent();
        if(requestedParent==null||requested.getFileName()==null)throw new IllegalArgumentException("Download destination must name a file inside a directory.");
        Files.createDirectories(requestedParent);
        Path parent=requestedParent.toRealPath();
        Path target=parent.resolve(requested.getFileName().toString());
        if(Files.exists(target,java.nio.file.LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Download destination already exists; refusing to overwrite it.");

        String url=base+"/node/shares/"+encode(shareId)+"/content";
        HttpURLConnection c=authorized(url,token,caPath);
        Path temp=null;
        boolean committed=false;
        try{
            int status=c.getResponseCode();
            if(status!=200)throw new IllegalStateException("Download rejected with HTTP "+status+": "+readText(c));
            long announced=c.getContentLengthLong();
            if(announced< -1||announced>20L*1024*1024*1024)throw new IllegalStateException("Remote file exceeds the Android peer's 20 GiB transfer limit or has an invalid Content-Length.");
            String expected=c.getHeaderField("X-Content-SHA256");
            if(expected==null||!expected.matches("[a-fA-F0-9]{64}"))throw new SecurityException("Remote peer did not provide a valid SHA-256 digest.");
            temp=Files.createTempFile(parent,".personalcloud-download-",".part");
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            long total=0;
            try(InputStream in=new BufferedInputStream(c.getInputStream());OutputStream out=new BufferedOutputStream(Files.newOutputStream(temp,java.nio.file.StandardOpenOption.WRITE,java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,java.nio.file.LinkOption.NOFOLLOW_LINKS))){
                byte[] b=new byte[65536];int n;
                while((n=in.read(b))!=-1){total=Math.addExact(total,n);if(total>20L*1024*1024*1024)throw new IllegalStateException("Remote file exceeds the Android peer's 20 GiB transfer limit.");digest.update(b,0,n);out.write(b,0,n);}
            }
            if(announced>=0&&total!=announced)throw new IllegalStateException("Downloaded byte count does not match Content-Length.");
            String actual=hex(digest.digest());
            if(!MessageDigest.isEqual(expected.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII),actual.getBytes(StandardCharsets.US_ASCII)))throw new SecurityException("Downloaded file checksum did not match the peer's SHA-256 header.");
            // Publish atomically without replacing a concurrently-created destination.
            // Files.move can race between its existence check and the underlying rename.
            Files.createLink(target,temp);
            Files.delete(temp);
            committed=true;
        }finally{
            if(!committed&&temp!=null)Files.deleteIfExists(temp);
            c.disconnect();
        }
    }
    /** Reads a bounded random-access range without downloading the complete remote file. */
    public static RangeResult readRange(String base,String token,String shareId,long offset,int length,String caPath)throws Exception{
        if(offset<0||length<1||length>8*1024*1024||offset>Long.MAX_VALUE-length)throw new IllegalArgumentException("Remote range must be between 1 byte and 8 MiB with a non-negative offset.");
        HttpURLConnection c=authorized(base+"/node/shares/"+encode(shareId)+"/content",token,caPath);
        c.setRequestProperty("Range","bytes="+offset+"-"+(offset+length-1));
        try{
            int status=c.getResponseCode();
            String contentRange=c.getHeaderField("Content-Range");
            if(status==416){
                if(contentRange==null||!contentRange.matches("bytes \\*/[0-9]+"))throw new IllegalStateException("Remote peer returned an invalid unsatisfied-range response.");
                long total=Long.parseLong(contentRange.substring(contentRange.indexOf('/')+1));
                if(offset<total)throw new IllegalStateException("Remote peer rejected a range that should be satisfiable.");
                InputStream errorBody=c.getErrorStream();if(errorBody!=null)errorBody.close();
                return new RangeResult(new byte[0],total,"");
            }
            if(status!=206)throw new IllegalStateException("Remote range read failed with HTTP "+status+": "+readText(c));
            if(contentRange==null||!contentRange.matches("bytes [0-9]+-[0-9]+/[0-9]+"))throw new IllegalStateException("Remote peer returned an invalid Content-Range.");
            String[] parts=contentRange.substring(6).split("[-/]");
            long start=Long.parseLong(parts[0]),end=Long.parseLong(parts[1]),total=Long.parseLong(parts[2]);
            long expectedEnd=Math.min(offset+length-1,total-1);
            if(start!=offset||end!=expectedEnd||end<start||total<=end)throw new IllegalStateException("Remote range response does not match the requested offset and length.");
            try(InputStream input=new BufferedInputStream(c.getInputStream());ByteArrayOutputStream bytes=new ByteArrayOutputStream()){
                byte[] buffer=new byte[8192];int n;while((n=input.read(buffer))!=-1){if(bytes.size()+n>length)throw new IllegalStateException("Remote range response exceeded the requested length.");bytes.write(buffer,0,n);}
                byte[] result=bytes.toByteArray();if(result.length!=end-start+1)throw new IllegalStateException("Remote range response was truncated.");
                String expectedHash=c.getHeaderField("X-Content-Range-SHA256");String actualHash=hex(MessageDigest.getInstance("SHA-256").digest(result));
                if(expectedHash==null||!MessageDigest.isEqual(expectedHash.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII),actualHash.getBytes(StandardCharsets.US_ASCII)))throw new SecurityException("Remote range checksum did not match the peer's SHA-256 header.");
                return new RangeResult(result,total,actualHash);
            }
        }finally{c.disconnect();}
    }

    public static final class RangeResult{
        public final byte[] bytes;public final long totalSize;public final String sha256;
        RangeResult(byte[] bytes,long totalSize,String sha256){this.bytes=bytes;this.totalSize=totalSize;this.sha256=sha256;}
    }

    public static void revoke(String base,String token,String caPath)throws Exception{HttpURLConnection c=authorized(base+"/node/peer",token,caPath);c.setRequestMethod("DELETE");int status=c.getResponseCode();if(status!=200)throw new IllegalStateException("Peer revocation failed with HTTP "+status);c.disconnect();}
    private static HttpURLConnection authorized(String url,String token,String ca)throws Exception{HttpURLConnection c=open(url,ca);c.setRequestProperty("Authorization","Bearer "+token);c.setConnectTimeout(8000);c.setReadTimeout(30000);return c;}
    private static HttpURLConnection open(String input,String ca)throws Exception{URL url=URI.create(input).toURL();if("http".equalsIgnoreCase(url.getProtocol())){if(!InetAddress.getByName(url.getHost()).isLoopbackAddress())throw new SecurityException("Unencrypted HTTP is permitted only for loopback testing.");HttpURLConnection plain=(HttpURLConnection)url.openConnection();plain.setInstanceFollowRedirects(false);return plain;}if(!"https".equalsIgnoreCase(url.getProtocol()))throw new IllegalArgumentException("Peer URL must use HTTPS.");HttpsURLConnection c=(HttpsURLConnection)url.openConnection();c.setInstanceFollowRedirects(false);if(ca==null||ca.trim().length()==0)throw new SecurityException("Import the peer's trusted CA certificate before connecting.");c.setSSLSocketFactory(context(ca).getSocketFactory());return c;}
    private static SSLContext context(String caPath)throws Exception{CertificateFactory cf=CertificateFactory.getInstance("X.509");X509Certificate cert;try(InputStream in=Files.newInputStream(java.nio.file.Paths.get(caPath))){cert=(X509Certificate)cf.generateCertificate(in);}KeyStore ks=KeyStore.getInstance(KeyStore.getDefaultType());ks.load(null);ks.setCertificateEntry("personalcloud-peer-ca",cert);TrustManagerFactory tmf=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tmf.init(ks);SSLContext ctx=SSLContext.getInstance("TLS");ctx.init(null,tmf.getTrustManagers(),null);return ctx;}
    private static Map<String,Object> readJson(HttpURLConnection c)throws Exception{int status=c.getResponseCode();InputStream in=status>=400?c.getErrorStream():c.getInputStream();ByteArrayOutputStream b=new ByteArrayOutputStream();if(in!=null)try(InputStream x=in){byte[] buf=new byte[8192];int n;while((n=x.read(buf))!=-1){if(b.size()+n>1024*1024)throw new IllegalStateException("Peer response exceeds 1 MiB.");b.write(buf,0,n);}}c.disconnect();return Json.object(new String(b.toByteArray(),StandardCharsets.UTF_8));}
    private static String readText(HttpURLConnection c)throws Exception{InputStream in=c.getErrorStream();if(in==null)return "";try(InputStream x=in){ByteArrayOutputStream b=new ByteArrayOutputStream();byte[] a=new byte[2048];int n;while((n=x.read(a))!=-1){if(b.size()+n>65536)break;b.write(a,0,n);}return new String(b.toByteArray(),StandardCharsets.UTF_8);}}
    private static String normalize(String value)throws Exception{if(value==null)throw new IllegalArgumentException("Peer URL is required.");URI u=URI.create(value.trim().replaceAll("/+$",""));if(u.getHost()==null||u.getUserInfo()!=null||u.getQuery()!=null||u.getFragment()!=null||(u.getPath()!=null&&u.getPath().length()>0&&!"/".equals(u.getPath()))||!("https".equalsIgnoreCase(u.getScheme())||"http".equalsIgnoreCase(u.getScheme())))throw new IllegalArgumentException("Invalid peer URL.");if("http".equalsIgnoreCase(u.getScheme())&&!InetAddress.getByName(u.getHost()).isLoopbackAddress())throw new SecurityException("LAN peers require HTTPS.");return u.getScheme()+"://"+u.getRawAuthority();}
    private static String form(Map<String,String> m){StringBuilder b=new StringBuilder();for(Map.Entry<String,String>e:m.entrySet()){if(b.length()>0)b.append('&');b.append(encode(e.getKey())).append('=').append(encode(e.getValue()));}return b.toString();}
    private static String encode(String s){try{return URLEncoder.encode(s,"UTF-8");}catch(Exception e){throw new IllegalArgumentException(e);}}
    private static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format(Locale.ROOT,"%02x",v&255));return s.toString();}
}
