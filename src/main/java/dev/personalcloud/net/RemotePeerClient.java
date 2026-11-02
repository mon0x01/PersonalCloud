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
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(8))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

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

    public InputStream openShare(Map<String, String> peer, String shareId) throws Exception {
        HttpRequest request = authorized(peer, "/node/shares/" + encodePath(shareId) + "/content")
                .timeout(Duration.ofMinutes(10)).GET().build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            String message;
            try (InputStream body = response.body()) { message = new String(body.readAllBytes(), StandardCharsets.UTF_8); }
            throw new RemotePeerException(response.statusCode(), "Remote download failed: " + message);
        }
        return response.body();
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
