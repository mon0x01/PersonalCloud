package dev.personalcloud.protocol;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.net.Json;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Headless peer-protocol integration tests. The server must not expose a browser dashboard. */
public final class PeerProtocolServerTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-peer-protocol-test-");
        PeerProtocolServer server = null;
        FileService files = null;
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path managed = Files.createDirectory(workspace.resolve("managed"));
            byte[] payload = "direct peer protocol contract\nwith byte ranges\n".getBytes(StandardCharsets.UTF_8);
            Files.write(managed.resolve("protocol.txt"), payload);

            int port = freePort();
            AppConfig config = new AppConfig("Protocol Test Node", "protocol-node-a", "127.0.0.1", port,
                    data, managed, null, null, 20L * 1024 * 1024 * 1024);
            StateStore state = new StateStore(data);
            files = new FileService(managed);
            PeerService peers = new PeerService(state, config);
            VersionService versions = new VersionService(data, files);
            GrantService grants = new GrantService(state, files, peers, versions, config.maxFileBytes());
            server = new PeerProtocolServer(config, files, peers, grants, new AuditLog(data));
            server.start();

            HttpClient http = HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(3)).build();
            String base = "http://127.0.0.1:" + port;

            HttpResponse<String> info = http.send(HttpRequest.newBuilder(URI.create(base + "/node/info")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(info.statusCode() == 200, "node info must be publicly readable for pairing discovery");
            check(info.body().contains("protocol-node-a") && info.body().contains("personalcloud-node/1"),
                    "node info must expose stable protocol identity");

            HttpResponse<String> root = http.send(HttpRequest.newBuilder(URI.create(base + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(root.statusCode() == 404, "the node endpoint must not serve the retired browser dashboard");

            Map<String, Object> invite = peers.createInvitation();
            String code = String.valueOf(invite.get("code"));
            String form = "code=" + encode(code) + "&nodeId=protocol-node-b&nodeName=Protocol%20Test%20Peer";
            HttpRequest pairRequest = HttpRequest.newBuilder(URI.create(base + "/node/pair"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build();
            HttpResponse<String> paired = http.send(pairRequest, HttpResponse.BodyHandlers.ofString());
            check(paired.statusCode() == 200, "valid one-time invitation must pair: " + paired.body());
            String token = String.valueOf(Json.object(paired.body()).get("accessToken"));
            check(token.length() >= 32, "pairing response must include an access token");

            HttpRequest healthRequest = HttpRequest.newBuilder(URI.create(base + "/node/health"))
                    .header("Authorization", "Bearer " + token).GET().build();
            HttpResponse<String> health = http.send(healthRequest, HttpResponse.BodyHandlers.ofString());
            check(health.statusCode() == 200 && health.body().contains("protocol-node-a"),
                    "authenticated peer health must succeed");

            grants.create("protocol-node-b", "protocol.txt", "VIEW");
            HttpRequest sharesRequest = HttpRequest.newBuilder(URI.create(base + "/node/shares"))
                    .header("Authorization", "Bearer " + token).GET().build();
            HttpResponse<String> shares = http.send(sharesRequest, HttpResponse.BodyHandlers.ofString());
            check(shares.statusCode() == 200, "trusted peer must list only its authorized shares");
            @SuppressWarnings("unchecked") List<Map<String, Object>> items = (List<Map<String, Object>>) (List<?>) Json.object(shares.body()).get("shares");
            check(items.size() == 1 && "protocol.txt".equals(items.get(0).get("name")), "share listing must return the granted file");
            String shareId = String.valueOf(items.get(0).get("shareId"));

            HttpRequest contentRequest = HttpRequest.newBuilder(URI.create(base + "/node/shares/" + encodePath(shareId) + "/content"))
                    .header("Authorization", "Bearer " + token).GET().build();
            HttpResponse<byte[]> content = http.send(contentRequest, HttpResponse.BodyHandlers.ofByteArray());
            check(content.statusCode() == 200 && java.util.Arrays.equals(payload, content.body()), "peer download must stream original bytes");
            String expectedHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
            check(expectedHash.equals(content.headers().firstValue("X-Content-SHA256").orElse("")), "download must advertise SHA-256");

            HttpRequest rangeRequest = HttpRequest.newBuilder(URI.create(base + "/node/shares/" + encodePath(shareId) + "/content"))
                    .header("Authorization", "Bearer " + token).header("Range", "bytes=7-18").GET().build();
            HttpResponse<byte[]> range = http.send(rangeRequest, HttpResponse.BodyHandlers.ofByteArray());
            check(range.statusCode() == 206, "peer API must support bounded byte ranges");
            check(java.util.Arrays.equals(range.body(), java.util.Arrays.copyOfRange(payload, 7, 19)), "range response must match requested original bytes");

            HttpRequest replayRequest = HttpRequest.newBuilder(URI.create(base + "/node/pair"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build();
            HttpResponse<String> replay = http.send(replayRequest, HttpResponse.BodyHandlers.ofString());
            check(replay.statusCode() == 400, "one-time invitation must reject replay");

            HttpRequest revokeRequest = HttpRequest.newBuilder(URI.create(base + "/node/peer"))
                    .header("Authorization", "Bearer " + token).DELETE().build();
            HttpResponse<String> revoked = http.send(revokeRequest, HttpResponse.BodyHandlers.ofString());
            check(revoked.statusCode() == 200, "peer must be able to revoke its own incoming trust relationship");
            HttpResponse<String> afterRevoke = http.send(healthRequest, HttpResponse.BodyHandlers.ofString());
            check(afterRevoke.statusCode() == 401, "revoked peer token must no longer authenticate");

            HttpRequest unknownApi = HttpRequest.newBuilder(URI.create(base + "/api/auth/login")).GET().build();
            HttpResponse<String> oldApi = http.send(unknownApi, HttpResponse.BodyHandlers.ofString());
            check(oldApi.statusCode() == 404, "retired browser administration routes must not remain exposed");
        } finally {
            if (server != null) server.close();
            if (files != null) files.close();
            deleteTree(workspace);
        }
        System.out.println("PASS: headless peer protocol, one-time pairing, token authentication/revocation, share authorization, full/range streaming, SHA-256, replay rejection and no browser routes.");
    }

    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static String encodePath(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) { return socket.getLocalPort(); }
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (Exception ignored) { }
            });
        }
    }
}
