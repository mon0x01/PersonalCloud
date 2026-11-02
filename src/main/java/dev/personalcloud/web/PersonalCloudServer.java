package dev.personalcloud.web;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.net.Json;
import dev.personalcloud.net.RemotePeerClient;
import dev.personalcloud.net.RemotePeerException;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;

public final class PersonalCloudServer {
    private final AppConfig config;
    private final StateStore store;
    private final FileService files;
    private final PeerService peers;
    private final GrantService grants;
    private final RemotePeerClient remote = new RemotePeerClient();
    private HttpServer server;
    private java.util.concurrent.ExecutorService executor;

    public PersonalCloudServer(AppConfig config, StateStore store, FileService files,
                               PeerService peers, GrantService grants) {
        this.config = config;
        this.store = store;
        this.files = files;
        this.peers = peers;
        this.grants = grants;
    }

    public void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress(config.bindAddress(), config.port()), 64);
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(1);
        if (executor != null) executor.shutdown();
    }

    private void handle(HttpExchange exchange) {
        try {
            securityHeaders(exchange.getResponseHeaders());
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase();

            if (path.equals("/node/info") && method.equals("GET")) {
                sendJson(exchange, 200, peers.nodeInfo());
                return;
            }
            if (path.equals("/node/pair") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                String token = peers.acceptInvitation(form.get("code"), form.get("nodeId"), form.get("nodeName"));
                Map<String, Object> response = new LinkedHashMap<>(peers.nodeInfo());
                response.put("accessToken", token);
                sendJson(exchange, 200, response);
                return;
            }
            if (path.startsWith("/node/shares") || path.equals("/node/peer")) {
                handleNodeApi(exchange, path, method);
                return;
            }
            if (!isAdmin(exchange)) {
                exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"PersonalCloud\", charset=\"UTF-8\"");
                sendJson(exchange, 401, Map.of("error", "Authentication required. Use username admin and the password printed on first startup."));
                return;
            }
            if ((method.equals("POST") || method.equals("DELETE")) && !sameOriginMutation(exchange)) {
                sendJson(exchange, 403, Map.of("error", "Cross-origin state changes are not allowed."));
                return;
            }

            if (path.equals("/") && method.equals("GET")) {
                serveResource(exchange, "/web/index.html", "text/html; charset=UTF-8");
            } else if (path.equals("/app.css") && method.equals("GET")) {
                serveResource(exchange, "/web/app.css", "text/css; charset=UTF-8");
            } else if (path.equals("/app.js") && method.equals("GET")) {
                serveResource(exchange, "/web/app.js", "text/javascript; charset=UTF-8");
            } else if (path.equals("/api/status") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("nodeId", config.nodeId(), "nodeName", config.nodeName(),
                        "port", config.port(), "storageRoot", files.root().toString(), "protocol", "personalcloud-node/1"));
            } else if (path.equals("/api/files") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("files", files.listFiles()));
            } else if (path.equals("/api/files/download") && method.equals("GET")) {
                downloadLocalFile(exchange, query(exchange).get("path"));
            } else if (path.equals("/api/peers") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("peers", peers.listPeers()));
            } else if (path.equals("/api/trusted-peers") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("peers", peers.trustedPeers()));
            } else if (path.equals("/api/invites") && method.equals("POST")) {
                sendJson(exchange, 201, peers.createInvitation());
            } else if (path.equals("/api/peers") && method.equals("POST")) {
                addPeer(exchange);
            } else if (path.startsWith("/api/peers/") && method.equals("DELETE")) {
                String nodeId = decode(path.substring("/api/peers/".length()));
                String direction = query(exchange).getOrDefault("direction", "OUTGOING");
                if ("INCOMING".equals(direction)) {
                    peers.removeTrustedPeer(nodeId);
                } else {
                    Map<String, String> outgoing = peers.outgoingPeer(nodeId);
                    if (outgoing != null) remote.revokePairing(outgoing);
                    peers.removeOutgoingPeer(nodeId);
                }
                sendJson(exchange, 200, Map.of("ok", true));
            } else if (path.equals("/api/grants") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("grants", grants.listAll()));
            } else if (path.equals("/api/grants") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                sendJson(exchange, 201, grants.create(form.get("peerId"), form.get("path"), form.get("permission")));
            } else if (path.startsWith("/api/grants/") && method.equals("DELETE")) {
                grants.revoke(decode(path.substring("/api/grants/".length())));
                sendJson(exchange, 200, Map.of("ok", true));
            } else if (path.equals("/api/remote-shares") && method.equals("GET")) {
                listRemoteShares(exchange, query(exchange).get("peerId"));
            } else if (path.startsWith("/api/remote-download/") && method.equals("GET")) {
                String[] parts = path.substring("/api/remote-download/".length()).split("/", 2);
                if (parts.length != 2) throw new IllegalArgumentException("Remote download URL is incomplete.");
                downloadRemoteFile(exchange, decode(parts[0]), decode(parts[1]));
            } else if (path.startsWith("/api/remote-shares/") && method.equals("DELETE")) {
                String[] parts = path.substring("/api/remote-shares/".length()).split("/", 2);
                if (parts.length != 2) throw new IllegalArgumentException("Remote share URL is incomplete.");
                deleteRemoteFile(exchange, decode(parts[0]), decode(parts[1]));
            } else {
                sendJson(exchange, 404, Map.of("error", "Route not found."));
            }
        } catch (Throwable error) {
            try {
                int status = error instanceof RemotePeerException remoteError ? remoteError.statusCode()
                        : error instanceof SecurityException ? 403
                        : error instanceof IllegalArgumentException ? 400 : 500;
                String message = error.getMessage() == null ? "Unexpected server error." : error.getMessage();
                sendJson(exchange, status, Map.of("error", message));
            } catch (Exception ignored) {
                exchange.close();
            }
        } finally {
            // Streaming handlers close their exchange after copying the response.
        }
    }

    private void handleNodeApi(HttpExchange exchange, String path, String method) throws Exception {
        String token = bearer(exchange);
        Map<String, String> peer = peers.authenticateIncoming(token);
        if (peer == null) {
            sendJson(exchange, 401, Map.of("error", "Invalid or revoked peer token."));
            return;
        }
        String peerId = peer.get("_id");
        if (path.equals("/node/shares") && method.equals("GET")) {
            sendJson(exchange, 200, Map.of("shares", grants.listForPeer(peerId)));
            return;
        }
        if (path.equals("/node/peer") && method.equals("DELETE")) {
            peers.removeTrustedPeer(peerId);
            sendJson(exchange, 200, Map.of("ok", true));
            return;
        }
        String prefix = "/node/shares/";
        String remainder = path.substring(prefix.length());
        if (method.equals("GET") && remainder.endsWith("/content")) {
            String shareId = decode(remainder.substring(0, remainder.length() - "/content".length()));
            Map<String, String> grant = grants.getGrant(shareId);
            if (grant == null || !peerId.equals(grant.get("peerId"))) {
                sendJson(exchange, 404, Map.of("error", "Shared file not found."));
                return;
            }
            String relativePath = grant.get("relativePath");
            Map<String, Object> metadata = files.metadata(relativePath);
            try (InputStream input = files.open(relativePath)) {
                exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                setAttachmentName(exchange.getResponseHeaders(), String.valueOf(metadata.get("name")));
                exchange.sendResponseHeaders(200, 0);
                try (OutputStream output = exchange.getResponseBody()) { copy(input, output); }
            }
            return;
        }
        if (method.equals("DELETE")) {
            String shareId = decode(remainder);
            String deletedPath = grants.deleteSharedOriginal(shareId, peerId);
            sendJson(exchange, 200, Map.of("ok", true, "deleted", deletedPath));
            return;
        }
        sendJson(exchange, 404, Map.of("error", "Node route not found."));
    }

    private void addPeer(HttpExchange exchange) throws Exception {
        Map<String, String> form = readForm(exchange);
        String baseUrl = RemotePeerClient.normalizeBaseUrl(form.get("baseUrl"));
        Map<String, Object> remoteInfo = remote.pair(baseUrl, config.nodeId(), config.nodeName(), form.get("code"));
        String nodeId = String.valueOf(remoteInfo.get("nodeId"));
        String nodeName = String.valueOf(remoteInfo.get("nodeName"));
        String token = String.valueOf(remoteInfo.get("accessToken"));
        if (nodeId.equals(config.nodeId()) || "null".equals(nodeId) || token.isBlank() || "null".equals(token)) throw new IllegalArgumentException("Remote node returned invalid pairing information.");
        peers.saveOutgoingPeer(nodeId, nodeName, baseUrl, token);
        sendJson(exchange, 201, Map.of("nodeId", nodeId, "nodeName", nodeName, "baseUrl", baseUrl));
    }

    private void listRemoteShares(HttpExchange exchange, String peerId) throws Exception {
        if (peerId == null || peerId.isBlank()) throw new IllegalArgumentException("peerId is required.");
        Map<String, String> peer = peers.outgoingPeer(peerId);
        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found. Add or pair the device first.");
        sendJson(exchange, 200, Map.of("shares", remote.listShares(peer), "peerId", peerId,
                "peerName", peer.getOrDefault("name", "Remote device")));
    }

    private void downloadRemoteFile(HttpExchange exchange, String peerId, String shareId) throws Exception {
        Map<String, String> peer = peers.outgoingPeer(peerId);
        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
        Map<String, Object> share = remote.listShares(peer).stream()
                .filter(item -> shareId.equals(String.valueOf(item.get("shareId"))))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Remote share not found or access was revoked."));
        try (InputStream input = remote.openShare(peer, shareId)) {
            exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
            setAttachmentName(exchange.getResponseHeaders(), String.valueOf(share.get("name")));
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output); }
        }
    }

    private void deleteRemoteFile(HttpExchange exchange, String peerId, String shareId) throws Exception {
        Map<String, String> peer = peers.outgoingPeer(peerId);
        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
        remote.deleteShare(peer, shareId);
        sendJson(exchange, 200, Map.of("ok", true));
    }

    private void downloadLocalFile(HttpExchange exchange, String relativePath) throws Exception {
        Map<String, Object> metadata = files.metadata(relativePath);
        try (InputStream input = files.open(relativePath)) {
            exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
            setAttachmentName(exchange.getResponseHeaders(), String.valueOf(metadata.get("name")));
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output); }
        }
    }

    private boolean isAdmin(HttpExchange exchange) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Basic ")) return false;
        try {
            String decoded = new String(java.util.Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0 || !"admin".equals(decoded.substring(0, separator))) return false;
            byte[] supplied = decoded.substring(separator + 1).getBytes(StandardCharsets.UTF_8);
            byte[] expected = config.adminPassword().getBytes(StandardCharsets.UTF_8);
            return java.security.MessageDigest.isEqual(supplied, expected);
        } catch (Exception e) { return false; }
    }

    private static boolean sameOriginMutation(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        String referer = exchange.getRequestHeaders().getFirst("Referer");
        // Non-browser clients such as curl do not send Origin or Referer. Browser mutations do.
        if ((origin == null || origin.isBlank()) && (referer == null || referer.isBlank())) return true;
        String host = exchange.getRequestHeaders().getFirst("Host");
        if (host == null || host.isBlank()) return false;
        String expected = "http://" + host;
        if (origin != null && !origin.isBlank()) return expected.equalsIgnoreCase(origin.trim());
        return referer != null && referer.regionMatches(true, 0, expected + "/", 0, expected.length() + 1);
    }

    private static String bearer(HttpExchange exchange) {
        String value = exchange.getRequestHeaders().getFirst("Authorization");
        return value != null && value.startsWith("Bearer ") ? value.substring(7).trim() : null;
    }

    private static Map<String, String> readForm(HttpExchange exchange) throws Exception {
        byte[] body = exchange.getRequestBody().readNBytes(65_537);
        if (body.length > 65_536) throw new IllegalArgumentException("Request body is too large.");
        String text = new String(body, StandardCharsets.UTF_8);
        Map<String, String> result = new LinkedHashMap<>();
        if (text.isBlank()) return result;
        for (String item : text.split("&")) {
            int equals = item.indexOf('=');
            String key = equals < 0 ? item : item.substring(0, equals);
            String value = equals < 0 ? "" : item.substring(equals + 1);
            result.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return result;
    }

    private static Map<String, String> query(HttpExchange exchange) {
        Map<String, String> result = new LinkedHashMap<>();
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null || raw.isBlank()) return result;
        for (String item : raw.split("&")) {
            int equals = item.indexOf('=');
            String key = equals < 0 ? item : item.substring(0, equals);
            String value = equals < 0 ? "" : item.substring(equals + 1);
            result.put(decode(key), decode(value));
        }
        return result;
    }

    private static String decode(String value) { return URLDecoder.decode(value, StandardCharsets.UTF_8); }

    private static void sendJson(HttpExchange exchange, int status, Object value) throws Exception {
        byte[] bytes = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
    }

    private static void serveResource(HttpExchange exchange, String resource, String contentType) throws Exception {
        try (InputStream input = PersonalCloudServer.class.getResourceAsStream(resource)) {
            if (input == null) {
                sendJson(exchange, 404, Map.of("error", "Dashboard resource not found: " + resource));
                return;
            }
            byte[] bytes = input.readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
        }
    }

    private static void setAttachmentName(Headers headers, String name) {
        String encoded = URLEncoder.encode(name, StandardCharsets.UTF_8).replace("+", "%20");
        headers.set("Content-Disposition", "attachment; filename*=UTF-8''" + encoded);
    }

    private static void copy(InputStream input, OutputStream output) throws Exception {
        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = input.read(buffer)) != -1) output.write(buffer, 0, read);
        output.flush();
    }

    private static void securityHeaders(Headers headers) {
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    }
}
