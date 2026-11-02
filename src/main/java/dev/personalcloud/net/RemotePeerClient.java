package dev.personalcloud.net;

import dev.personalcloud.core.PeerService;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class RemotePeerClient {
    private final HttpClient client = buildClient();

    private static HttpClient buildClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NEVER);
        String truststore = System.getenv("PERSONALCLOUD_TLS_TRUSTSTORE");
        String password = System.getenv("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD");
        if (truststore != null && !truststore.isBlank()) {
            if (password == null) throw new IllegalArgumentException("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD is required with a custom truststore.");
            try {
                java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
                try (InputStream input = java.nio.file.Files.newInputStream(java.nio.file.Path.of(truststore))) {
                    store.load(input, password.toCharArray());
                }
                javax.net.ssl.TrustManagerFactory managers = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
                managers.init(store);
                javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLS");
                ssl.init(null, managers.getTrustManagers(), null);
                builder.sslContext(ssl);
            } catch (Exception error) {
                throw new IllegalStateException("Unable to load the configured TLS truststore.", error);
            }
        }
        return builder.build();
    }

    public Map<String, Object> pair(String baseUrl, String localNodeId, String localName, String code) throws Exception {
        String normalized = normalizeBaseUrl(baseUrl);
        String body = form(Map.of("nodeId", localNodeId, "nodeName", localName, "code", code));
        HttpRequest request = HttpRequest.newBuilder(URI.create(normalized + "/node/pair"))
                .timeout(Duration.ofSeconds(12))
                .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> data = Json.object(response.body());
        if (response.statusCode() != 200) throw new IllegalArgumentException(message(data, "Pairing failed with HTTP " + response.statusCode()));
        data.put("baseUrl", normalized);
        return data;
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listShares(Map<String, String> peer) throws Exception {
        HttpRequest request = authorized(peer, "/node/shares").GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> data = Json.object(response.body());
        if (response.statusCode() != 200) throw new RemotePeerException(response.statusCode(), message(data, "Remote node returned HTTP " + response.statusCode()));
        Object items = data.get("shares");
        return items instanceof List<?> list ? (List<Map<String, Object>>) (List<?>) list : List.of();
    }

    public record DownloadResponse(int statusCode, long contentLength, String contentRange, String sha256, InputStream body) { }

    public DownloadResponse openShare(Map<String, String> peer, String shareId, String range) throws Exception {
        HttpRequest.Builder builder = authorized(peer, "/node/shares/" + encodePath(shareId) + "/content")
                .timeout(Duration.ofMinutes(10)).GET();
        if (range != null && !range.isBlank()) builder.header("Range", range);
        HttpResponse<InputStream> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200 && response.statusCode() != 206) {
            String message;
            try (InputStream body = response.body()) { message = new String(body.readAllBytes(), StandardCharsets.UTF_8); }
            throw new RemotePeerException(response.statusCode(), "Remote download failed: " + message);
        }
        long contentLength = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
        String contentRange = response.headers().firstValue("Content-Range").orElse(null);
        String sha256 = response.headers().firstValue("X-Content-SHA256").orElse(null);
        return new DownloadResponse(response.statusCode(), contentLength, contentRange, sha256, response.body());
    }

    public InputStream openFolderArchive(Map<String, String> peer, String grantId) throws Exception {
        HttpRequest request = authorized(peer, "/node/shares/" + encodePath(grantId) + "/archive")
                .timeout(Duration.ofMinutes(10)).GET().build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            String detail;
            try (InputStream body = response.body()) { detail = new String(body.readAllBytes(), StandardCharsets.UTF_8); }
            throw new RemotePeerException(response.statusCode(), "Remote folder download failed: " + detail);
        }
        return response.body();
    }

    public boolean health(Map<String, String> peer) throws Exception {
        HttpRequest request = authorized(peer, "/node/health").timeout(Duration.ofSeconds(5)).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return response.statusCode() == 200;
    }

    public void revokePairing(Map<String, String> peer) throws Exception {
        HttpRequest request = authorized(peer, "/node/peer").DELETE().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            String detail;
            try { detail = message(Json.object(response.body()), response.body()); }
            catch (Exception ignored) { detail = response.body(); }
            throw new RemotePeerException(response.statusCode(), "Remote pairing revocation failed: " + detail);
        }
    }

    public void deleteShare(Map<String, String> peer, String shareId) throws Exception {
        HttpRequest request = authorized(peer, "/node/shares/" + encodePath(shareId)).DELETE().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            String detail;
            try { detail = message(Json.object(response.body()), response.body()); }
            catch (Exception ignored) { detail = response.body(); }
            throw new RemotePeerException(response.statusCode(), "Remote delete failed: " + detail);
        }
    }

    public static String normalizeBaseUrl(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Peer URL is required.");
        String input = value.trim().replaceAll("/+$", "");
        URI uri;
        try { uri = URI.create(input); }
        catch (Exception e) { throw new IllegalArgumentException("Peer URL is invalid."); }
        if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Peer URL must be an http:// or https:// address without embedded credentials.");
        }
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            try {
                boolean loopback = java.net.InetAddress.getByName(uri.getHost()).isLoopbackAddress();
                if (!loopback) throw new IllegalArgumentException("Unencrypted HTTP is allowed only for loopback testing. Use HTTPS for LAN or internet peers.");
            } catch (java.net.UnknownHostException error) {
                throw new IllegalArgumentException("Peer hostname could not be resolved. Use HTTPS for network peers.");
            }
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null || (uri.getRawPath() != null && !uri.getRawPath().isEmpty() && !uri.getRawPath().equals("/"))) {
            throw new IllegalArgumentException("Peer URL must contain only scheme, host, and optional port.");
        }
        return uri.getScheme() + "://" + uri.getRawAuthority();
    }

    private HttpRequest.Builder authorized(Map<String, String> peer, String path) {
        String base = peer.get("baseUrl");
        String token = peer.get("accessToken");
        return HttpRequest.newBuilder(URI.create(base + path))
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json, application/octet-stream");
    }

    private static String encodePath(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }

    private static String form(Map<String, String> values) {
        StringBuilder result = new StringBuilder();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (!result.isEmpty()) result.append('&');
            result.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            result.append('=');
            result.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return result.toString();
    }

    private static String message(Map<String, Object> data, String fallback) {
        Object message = data.get("error");
        return message == null ? fallback : String.valueOf(message);
    }
}
