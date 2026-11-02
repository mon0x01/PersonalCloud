package dev.personalcloud.web;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.SecurityMonitor;
import dev.personalcloud.core.PasswordService;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.core.TotpService;
import dev.personalcloud.core.SessionManager;
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
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public final class PersonalCloudServer {
    private final AppConfig config;
    private final StateStore store;
    private final FileService files;
    private final PeerService peers;
    private final GrantService grants;
    private final RemotePeerClient remote = new RemotePeerClient();
    private final AuditLog audit;
    private final SecurityMonitor security = new SecurityMonitor();
    private final PasswordService passwords;
    private final VersionService versions;
    private final TotpService totp;
    private final SessionManager sessions = new SessionManager();
    private HttpServer server;
    private java.util.concurrent.ExecutorService executor;

    public PersonalCloudServer(AppConfig config, StateStore store, FileService files,
                               PeerService peers, GrantService grants, VersionService versions) throws Exception {
        this.config = config;
        this.store = store;
        this.files = files;
        this.peers = peers;
        this.grants = grants;
        this.audit = new AuditLog(config.dataDirectory());
        this.passwords = new PasswordService(config);
        this.versions = versions;
        this.totp = new TotpService(store, config.dataDirectory());
    }

    public void start() throws Exception {
        InetSocketAddress address = new InetSocketAddress(config.bindAddress(), config.port());
        if (config.tlsKeystore() != null) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(config.tlsKeystore())) {
                keyStore.load(input, config.tlsKeystorePassword().toCharArray());
            }
            KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            managers.init(keyStore, config.tlsKeystorePassword().toCharArray());
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(managers.getKeyManagers(), null, null);
            HttpsServer https = HttpsServer.create(address, 64);
            https.setHttpsConfigurator(new HttpsConfigurator(ssl));
            server = https;
        } else {
            server = HttpServer.create(address, 64);
        }
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(1);
        if (executor != null) executor.shutdown();
        files.close();
    }

    private void handle(HttpExchange exchange) {
        try {
            securityHeaders(exchange.getResponseHeaders());
            if (exchange instanceof HttpsExchange) exchange.getResponseHeaders().set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase();

            if (path.equals("/node/info") && method.equals("GET")) {
                sendJson(exchange, 200, peers.nodeInfo());
                return;
            }
            if (path.equals("/node/pair") && method.equals("POST")) {
                String actor = clientAddress(exchange);
                if (!security.pairingAllowed(actor)) {
                    sendJson(exchange, 429, Map.of("error", "Pairing attempts are temporarily rate-limited for this address."));
                    return;
                }
                try {
                    Map<String, String> form = readForm(exchange);
                    String token = peers.acceptInvitation(form.get("code"), form.get("nodeId"), form.get("nodeName"));
                    Map<String, Object> response = new LinkedHashMap<>(peers.nodeInfo());
                    response.put("accessToken", token);
                    security.pairingSucceeded(actor);
                    audit.record("PAIR_ACCEPTED", actor, "node=" + form.get("nodeId"));
                    sendJson(exchange, 200, response);
                } catch (Exception failure) {
                    security.pairingFailed(actor);
                    audit.record("PAIR_REJECTED", actor, "invalid pairing attempt");
                    throw failure;
                }
                return;
            }
            if (path.startsWith("/node/shares") || path.equals("/node/peer") || path.equals("/node/health")) {
                handleNodeApi(exchange, path, method);
                return;
            }
            String actor = clientAddress(exchange);
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");

            // Static dashboard resources are public; all data and mutation routes remain authenticated.
            if (path.equals("/") && method.equals("GET")) {
                serveResource(exchange, "/web/index.html", "text/html; charset=UTF-8");
                return;
            }
            if (path.equals("/app.css") && method.equals("GET")) {
                serveResource(exchange, "/web/app.css", "text/css; charset=UTF-8");
                return;
            }
            if (path.equals("/app.js") && method.equals("GET")) {
                serveResource(exchange, "/web/app.js", "text/javascript; charset=UTF-8");
                return;
            }
            if (path.equals("/api/auth/status") && method.equals("GET")) {
                boolean authenticated = sessions.valid(sessionToken(exchange)) || (!totp.isEnabled() && isBasicAdmin(exchange));
                sendJson(exchange, 200, Map.of("authenticated", authenticated, "mfaEnabled", totp.isEnabled(),
                        "sessionSeconds", SessionManager.SESSION_SECONDS));
                return;
            }
            if (path.equals("/api/auth/login") && method.equals("POST")) {
                if (!sameOriginMutation(exchange)) {
                    sendJson(exchange, 403, Map.of("error", "Cross-origin state changes are not allowed."));
                    return;
                }
                if (!security.loginAllowed(actor)) {
                    sendJson(exchange, 429, Map.of("error", "Too many failed login attempts. Try again after the temporary lockout."));
                    return;
                }
                Map<String, String> form = readForm(exchange);
                boolean passwordValid = "admin".equals(form.get("username")) && passwords.verify(form.get("password"));
                boolean mfaValid = passwordValid && (!totp.isEnabled() || totp.verifyAndConsume(form.get("code")));
                if (!passwordValid || !mfaValid) {
                    security.loginFailed(actor);
                    audit.record("AUTH_FAILED", actor, "invalid administrator login or authenticator code");
                    sendJson(exchange, 401, Map.of("error", "Username, password, or authenticator/recovery code is incorrect."));
                    return;
                }
                security.loginSucceeded(actor);
                String token = sessions.create();
                setSessionCookie(exchange, token);
                audit.record("AUTH_LOGIN", actor, "administrator session created");
                sendJson(exchange, 200, Map.of("ok", true, "mfaEnabled", totp.isEnabled(), "sessionSeconds", SessionManager.SESSION_SECONDS));
                return;
            }
            if (path.equals("/api/auth/logout") && method.equals("POST")) {
                if (!sameOriginMutation(exchange)) {
                    sendJson(exchange, 403, Map.of("error", "Cross-origin state changes are not allowed."));
                    return;
                }
                sessions.revoke(sessionToken(exchange));
                clearSessionCookie(exchange);
                sendJson(exchange, 200, Map.of("ok", true));
                return;
            }

            if (!isAdmin(exchange)) {
                if (authorization != null && !security.loginAllowed(actor)) {
                    sendJson(exchange, 429, Map.of("error", "Too many failed login attempts. Try again after the temporary lockout."));
                    return;
                }
                if (authorization != null) {
                    security.loginFailed(actor);
                    audit.record("AUTH_FAILED", actor, "invalid administrator credentials or MFA required");
                }
                sendJson(exchange, 401, Map.of("error", "Authentication required. Sign in through the PersonalCloud dashboard."));
                return;
            }
            if (authorization != null && !totp.isEnabled()) security.loginSucceeded(actor);
            if ((method.equals("POST") || method.equals("PUT") || method.equals("DELETE")) && !sameOriginMutation(exchange)) {
                sendJson(exchange, 403, Map.of("error", "Cross-origin state changes are not allowed."));
                return;
            }

            if (path.equals("/api/status") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("appVersion", "1.0.0", "nodeId", config.nodeId(), "nodeName", config.nodeName(),
                        "port", config.port(), "storageRoot", files.root().toString(), "storageRevision", files.storageRevision(),
                        "protocol", "personalcloud-node/1", "tlsEnabled", config.tlsKeystore() != null,
                        "maxUploadBytes", config.maxUploadBytes()));
            } else if (path.equals("/api/files") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("files", files.listFiles()));
            } else if (path.equals("/api/folders") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("folders", files.listFolders()));
            } else if (path.equals("/api/files/download") && method.equals("GET")) {
                downloadLocalFile(exchange, query(exchange).get("path"));
            } else if (path.equals("/api/files/preview") && method.equals("GET")) {
                String relative = query(exchange).get("path");
                String preview = files.previewText(relative, 256 * 1024);
                byte[] bytes = preview.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
                exchange.getResponseHeaders().set("Content-Disposition", "inline");
                exchange.getResponseHeaders().set("Cache-Control", "no-store");
                exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
            } else if (path.equals("/api/files/upload") && method.equals("POST")) {
                String relative = query(exchange).get("path");
                boolean createParents = "true".equalsIgnoreCase(query(exchange).get("createParents"));
                long uploaded = files.upload(relative, exchange.getRequestBody(), config.maxUploadBytes(), createParents);
                audit.record("FILE_UPLOADED", actor, "path=" + relative + "; bytes=" + uploaded);
                sendJson(exchange, 201, Map.of("ok", true, "path", relative, "bytes", uploaded));
            } else if (path.equals("/api/files/move") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                String source = files.validateAndGetRelativeSharePath(form.get("source"));
                String destination = files.move(source, form.get("destination"));
                grants.rewritePaths(source, destination);
                audit.record("FILE_OR_FOLDER_MOVED", actor, "from=" + source + "; to=" + destination);
                sendJson(exchange, 200, Map.of("ok", true, "path", destination));
            } else if (path.equals("/api/files") && method.equals("DELETE")) {
                String relative = files.validateAndGetRelativeFile(query(exchange).get("path"));
                Map<String, Object> snapshot = versions.snapshot(relative, "LOCAL_DELETE", config.maxUploadBytes());
                files.delete(relative);
                grants.removeGrantsForDeletedPath(relative);
                audit.record("LOCAL_FILE_DELETED", actor, "path=" + relative + "; version=" + snapshot.get("id"));
                sendJson(exchange, 200, Map.of("ok", true, "versionId", snapshot.get("id")));
            } else if (path.equals("/api/versions") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("versions", versions.list(query(exchange).get("path"))));
            } else if (path.equals("/api/versions") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                Map<String, Object> snapshot = versions.snapshot(form.get("path"), "MANUAL", config.maxUploadBytes());
                audit.record("FILE_VERSION_CREATED", actor, "path=" + form.get("path") + "; version=" + snapshot.get("id"));
                sendJson(exchange, 201, snapshot);
            } else if (path.startsWith("/api/versions/") && path.endsWith("/restore") && method.equals("POST")) {
                String id = path.substring("/api/versions/".length(), path.length() - "/restore".length());
                Map<String, String> form = readForm(exchange);
                Map<String, Object> restored = versions.restore(decode(id), form.get("destination"), config.maxUploadBytes());
                audit.record("FILE_VERSION_RESTORED", actor, "version=" + id + "; path=" + restored.get("path"));
                sendJson(exchange, 201, restored);
            } else if (path.equals("/api/folders") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                files.createFolder(form.get("path"));
                audit.record("FOLDER_CREATED", actor, "path=" + form.get("path"));
                sendJson(exchange, 201, Map.of("ok", true));
            } else if (path.equals("/api/peers") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("peers", peers.listPeers()));
            } else if (path.equals("/api/trusted-peers") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("peers", peers.trustedPeers()));
            } else if (path.equals("/api/invites") && method.equals("POST")) {
                audit.record("PAIR_INVITATION_CREATED", actor, "one-time invitation generated");
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
                audit.record("PEER_REMOVED", actor, "node=" + nodeId + "; direction=" + direction);
                sendJson(exchange, 200, Map.of("ok", true));
            } else if (path.equals("/api/grants") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("grants", grants.listAll()));
            } else if (path.equals("/api/grants") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                Map<String, Object> created = grants.create(form.get("peerId"), form.get("path"), form.get("permission"));
                audit.record("GRANT_CREATED", actor, "peer=" + form.get("peerId") + "; permission=" + form.get("permission") + "; path=" + form.get("path"));
                sendJson(exchange, 201, created);
            } else if (path.startsWith("/api/grants/") && method.equals("DELETE")) {
                String grantId = decode(path.substring("/api/grants/".length()));
                grants.revoke(grantId);
                audit.record("GRANT_REVOKED", actor, "grant=" + grantId);
                sendJson(exchange, 200, Map.of("ok", true));
            } else if (path.equals("/api/remote-shares") && method.equals("GET")) {
                listRemoteShares(exchange, query(exchange).get("peerId"));
            } else if (path.equals("/api/activity") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("events", audit.recent(100)));
            } else if (path.equals("/api/mfa/status") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("enabled", totp.isEnabled(), "remainingRecoveryCodes", totp.remainingRecoveryCodes()));
            } else if (path.equals("/api/mfa/setup") && method.equals("POST")) {
                if (totp.isEnabled()) throw new IllegalArgumentException("MFA is already enabled. Disable it before starting a new setup.");
                sendJson(exchange, 200, totp.beginSetup());
            } else if (path.equals("/api/mfa/enable") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                java.util.List<String> recoveryCodes = totp.enable(form.get("code"));
                // Invalidate all pre-MFA sessions, then issue one fresh session for this browser.
                sessions.revokeAll();
                setSessionCookie(exchange, sessions.create());
                audit.record("MFA_ENABLED", actor, "authenticator MFA enabled");
                sendJson(exchange, 200, Map.of("ok", true, "recoveryCodes", recoveryCodes));
            } else if (path.equals("/api/mfa/disable") && method.equals("POST")) {
                Map<String, String> form = readForm(exchange);
                if (!passwords.verify(form.get("password"))) throw new SecurityException("Administrator password is incorrect.");
                totp.disable(form.get("code"));
                sessions.revokeAll();
                setSessionCookie(exchange, sessions.create());
                audit.record("MFA_DISABLED", actor, "authenticator MFA disabled");
                sendJson(exchange, 200, Map.of("ok", true));
            } else if (path.equals("/api/admin/password") && method.equals("PUT")) {
                Map<String, String> form = readForm(exchange);
                passwords.change(form.get("currentPassword"), form.get("newPassword"));
                sessions.revokeAll();
                clearSessionCookie(exchange);
                audit.record("ADMIN_PASSWORD_CHANGED", actor, "administrator password rotated; sessions revoked");
                sendJson(exchange, 200, Map.of("ok", true, "message", "Password changed. Sign in again with the new password."));
            } else if (path.equals("/api/peers/health") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("health", peerHealth()));
            } else if (path.startsWith("/api/remote-folder-download/") && method.equals("GET")) {
                String[] parts = path.substring("/api/remote-folder-download/".length()).split("/", 2);
                if (parts.length != 2) throw new IllegalArgumentException("Remote folder download URL is incomplete.");
                downloadRemoteFolder(exchange, decode(parts[0]), decode(parts[1]));
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
        if (path.equals("/node/health") && method.equals("GET")) {
            sendJson(exchange, 200, Map.of("ok", true, "nodeId", config.nodeId(), "time", java.time.Instant.now().toString()));
            return;
        }
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
        if (method.equals("GET") && remainder.endsWith("/archive")) {
            String grantId = decode(remainder.substring(0, remainder.length() - "/archive".length()));
            streamFolderArchive(exchange, grantId, peerId);
            return;
        }
        if (method.equals("GET") && remainder.endsWith("/content")) {
            String shareId = decode(remainder.substring(0, remainder.length() - "/content".length()));
            String relativePath = grants.resolveSharePath(shareId, peerId);
            Map<String, Object> metadata = files.metadata(relativePath);
            streamFile(exchange, relativePath, String.valueOf(metadata.get("name")));
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

    private void streamFolderArchive(HttpExchange exchange, String grantId, String peerId) throws Exception {
        String folder = grants.folderPathForPeer(grantId, peerId);
        java.util.List<String> paths = grants.folderFilesForPeer(grantId, peerId);
        String name = folder.substring(folder.lastIndexOf('/') + 1) + ".zip";
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/zip");
        setAttachmentName(headers, name);
        exchange.sendResponseHeaders(200, 0);
        try (java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(exchange.getResponseBody())) {
            String prefix = folder.endsWith("/") ? folder : folder + "/";
            for (String path : paths) {
                String entryName = path.substring(prefix.length());
                zip.putNextEntry(new java.util.zip.ZipEntry(safeZipEntryName(entryName)));
                try (InputStream input = files.open(path)) { copy(input, zip); }
                zip.closeEntry();
            }
            zip.finish();
        }
    }


    private static String safeZipEntryName(String relativeName) {
        String portable = relativeName.replace('\\', '_');
        if (portable.isBlank() || portable.startsWith("/") || portable.matches("^[A-Za-z]:.*")) {
            throw new IllegalArgumentException("Invalid path in shared folder archive.");
        }
        for (String segment : portable.split("/")) {
            if (segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("Invalid path in shared folder archive.");
            }
        }
        return portable;
    }

    private void downloadRemoteFolder(HttpExchange exchange, String peerId, String grantId) throws Exception {
        Map<String, String> peer = peers.outgoingPeer(peerId);
        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
        Map<String, Object> folder = remote.listShares(peer).stream()
                .filter(item -> grantId.equals(String.valueOf(item.get("shareId"))) && "FOLDER".equals(item.get("kind")))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Remote folder not found or access was revoked."));
        try (InputStream input = remote.openFolderArchive(peer, grantId)) {
            exchange.getResponseHeaders().set("Content-Type", "application/zip");
            setAttachmentName(exchange.getResponseHeaders(), String.valueOf(folder.get("name")) + ".zip");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output); }
        }
    }

    private java.util.List<Map<String, Object>> peerHealth() {
        java.util.List<Map<String, Object>> result = new java.util.ArrayList<>();
        for (Map<String, Object> row : peers.listPeers()) {
            String id = String.valueOf(row.get("nodeId"));
            if (!"OUTGOING".equals(row.get("direction"))) {
                result.add(Map.of("nodeId", id, "status", "PAIRED_INCOMING", "reachable", false));
                continue;
            }
            try {
                Map<String, String> peer = peers.outgoingPeer(id);
                boolean reachable = remote.health(peer);
                result.add(Map.of("nodeId", id, "status", reachable ? "ONLINE" : "OFFLINE", "reachable", reachable));
            } catch (Exception error) {
                result.add(Map.of("nodeId", id, "status", "OFFLINE", "reachable", false));
            }
        }
        return result;
    }

    private void downloadRemoteFile(HttpExchange exchange, String peerId, String shareId) throws Exception {
        Map<String, String> peer = peers.outgoingPeer(peerId);
        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
        Map<String, Object> share = remote.listShares(peer).stream()
                .filter(item -> shareId.equals(String.valueOf(item.get("shareId"))))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Remote share not found or access was revoked."));
        String range = exchange.getRequestHeaders().getFirst("Range");
        RemotePeerClient.DownloadResponse response = remote.openShare(peer, shareId, range);
        try (InputStream input = response.body()) {
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "application/octet-stream");
            setAttachmentName(headers, String.valueOf(share.get("name")));
            headers.set("Accept-Ranges", "bytes");
            if (response.contentRange() != null) headers.set("Content-Range", response.contentRange());
            if (response.sha256() != null) headers.set("X-Content-SHA256", response.sha256());
            headers.set("Accept-Ranges", "bytes");
            exchange.sendResponseHeaders(response.statusCode(), response.contentLength());
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output, response.contentLength()); }
        }
    }

    private void deleteRemoteFile(HttpExchange exchange, String peerId, String shareId) throws Exception {
        Map<String, String> peer = peers.outgoingPeer(peerId);
        if (peer == null) throw new IllegalArgumentException("Outgoing peer not found.");
        remote.deleteShare(peer, shareId);
        audit.record("REMOTE_FILE_DELETED", clientAddress(exchange), "peer=" + peerId + "; share=" + shareId);
        sendJson(exchange, 200, Map.of("ok", true));
    }

    private void downloadLocalFile(HttpExchange exchange, String relativePath) throws Exception {
        Map<String, Object> metadata = files.metadata(relativePath);
        streamFile(exchange, relativePath, String.valueOf(metadata.get("name")));
    }

    private void streamFile(HttpExchange exchange, String relativePath, String name) throws Exception {
        long size = ((Number) files.metadata(relativePath).get("size")).longValue();
        long start = 0;
        long end = size - 1;
        int status = 200;
        String requested = exchange.getRequestHeaders().getFirst("Range");
        if (requested != null && !requested.isBlank()) {
            long[] range = parseRange(requested, size);
            if (range == null) {
                exchange.getResponseHeaders().set("Content-Range", "bytes */" + size);
                exchange.sendResponseHeaders(416, -1);
                exchange.close();
                return;
            }
            start = range[0];
            end = range[1];
            status = 206;
        }
        long length = Math.max(0, end - start + 1);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Accept-Ranges", "bytes");
        headers.set("X-Content-SHA256", files.sha256(relativePath));
        setAttachmentName(headers, name);
        if (status == 206) headers.set("Content-Range", "bytes " + start + "-" + end + "/" + size);
        try (InputStream input = files.open(relativePath)) {
            input.skipNBytes(start);
            exchange.sendResponseHeaders(status, length);
            try (OutputStream output = exchange.getResponseBody()) { copy(input, output, length); }
        }
    }

    private static long[] parseRange(String header, long size) {
        if (size <= 0 || header == null || !header.startsWith("bytes=") || header.indexOf(',') >= 0) return null;
        String value = header.substring(6).trim();
        int dash = value.indexOf('-');
        if (dash < 0) return null;
        try {
            String left = value.substring(0, dash).trim();
            String right = value.substring(dash + 1).trim();
            long start, end;
            if (left.isEmpty()) {
                long suffix = Long.parseLong(right);
                if (suffix <= 0) return null;
                start = Math.max(0, size - suffix);
                end = size - 1;
            } else {
                start = Long.parseLong(left);
                end = right.isEmpty() ? size - 1 : Math.min(Long.parseLong(right), size - 1);
            }
            if (start < 0 || start >= size || end < start) return null;
            return new long[]{start, end};
        } catch (NumberFormatException error) { return null; }
    }

    private boolean isAdmin(HttpExchange exchange) throws Exception {
        if (sessions.valid(sessionToken(exchange))) return true;
        return !totp.isEnabled() && isBasicAdmin(exchange);
    }

    private boolean isBasicAdmin(HttpExchange exchange) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Basic ")) return false;
        try {
            String decoded = new String(java.util.Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0 || !"admin".equals(decoded.substring(0, separator))) return false;
            return passwords.verify(decoded.substring(separator + 1));
        } catch (Exception e) { return false; }
    }

    private static String sessionToken(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Cookie");
        if (header == null) return null;
        for (String part : header.split(";")) {
            String item = part.trim();
            int equals = item.indexOf('=');
            if (equals > 0 && SessionManager.COOKIE_NAME.equals(item.substring(0, equals))) return item.substring(equals + 1);
        }
        return null;
    }

    private void setSessionCookie(HttpExchange exchange, String token) {
        String cookie = SessionManager.COOKIE_NAME + "=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + SessionManager.SESSION_SECONDS;
        if (config.tlsKeystore() != null) cookie += "; Secure";
        exchange.getResponseHeaders().add("Set-Cookie", cookie);
    }

    private void clearSessionCookie(HttpExchange exchange) {
        String cookie = SessionManager.COOKIE_NAME + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
        if (config.tlsKeystore() != null) cookie += "; Secure";
        exchange.getResponseHeaders().add("Set-Cookie", cookie);
    }

    private static boolean sameOriginMutation(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        String referer = exchange.getRequestHeaders().getFirst("Referer");
        // Non-browser clients such as curl do not send Origin or Referer. Browser mutations do.
        if ((origin == null || origin.isBlank()) && (referer == null || referer.isBlank())) return true;
        String host = exchange.getRequestHeaders().getFirst("Host");
        if (host == null || host.isBlank()) return false;
        String scheme = exchange instanceof HttpsExchange ? "https://" : "http://";
        String expected = scheme + host;
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

    private static void copy(InputStream input, OutputStream output, long remaining) throws Exception {
        byte[] buffer = new byte[64 * 1024];
        long left = remaining;
        while (left > 0) {
            int read = input.read(buffer, 0, (int) Math.min(buffer.length, left));
            if (read < 0) throw new java.io.IOException("File changed or stream ended before the requested range was complete.");
            output.write(buffer, 0, read);
            left -= read;
        }
        output.flush();
    }

    private static String clientAddress(HttpExchange exchange) {
        return exchange.getRemoteAddress() == null ? "unknown" : exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private static void securityHeaders(Headers headers) {
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    }
}
