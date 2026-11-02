package dev.personalcloud.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class PeerService {
    private final StateStore store;
    private final AppConfig config;
    private final TokenVault tokenVault;

    public PeerService(StateStore store, AppConfig config) throws Exception {
        this.store = store;
        this.config = config;
        this.tokenVault = new TokenVault(config.dataDirectory());
    }

    public Map<String, Object> nodeInfo() {
        return Map.of("nodeId", config.nodeId(), "nodeName", config.nodeName(), "protocol", "personalcloud-node/1");
    }

    public Map<String, Object> createInvitation() throws Exception {
        Instant now = Instant.now();
        for (Map<String, String> old : store.records("invite")) {
            try {
                if (Instant.parse(old.get("expiresAt")).isBefore(now)) store.removeRecord("invite", old.get("_id"));
            } catch (Exception ignored) { store.removeRecord("invite", old.get("_id")); }
        }
        String code = SecretFiles.randomCode();
        String hash = hash(code);
        Instant expires = Instant.now().plusSeconds(600);
        store.putRecord("invite", hash, Map.of("expiresAt", expires.toString()));
        return Map.of("code", code, "expiresAt", expires.toString(), "validForSeconds", 600);
    }

    public synchronized String acceptInvitation(String code, String remoteNodeId, String remoteNodeName) throws Exception {
        if (code == null || !code.matches("[A-Fa-f0-9]{16}")) throw new IllegalArgumentException("Invalid pairing code.");
        if (remoteNodeId == null || remoteNodeId.isBlank() || remoteNodeId.length() > 100) throw new IllegalArgumentException("Invalid remote node ID.");
        if (remoteNodeId.equals(config.nodeId())) throw new IllegalArgumentException("A device cannot pair with itself.");
        String hash = hash(code.toUpperCase());
        Map<String, String> invitation = store.getRecord("invite", hash);
        if (invitation == null) throw new IllegalArgumentException("Pairing code is invalid or has already been used.");
        Instant expiry = Instant.parse(invitation.get("expiresAt"));
        if (Instant.now().isAfter(expiry)) {
            store.removeRecord("invite", hash);
            throw new IllegalArgumentException("Pairing code has expired. Generate a new code.");
        }
        store.removeRecord("invite", hash);
        String token = SecretFiles.randomToken();
        Map<String, String> trusted = new LinkedHashMap<>();
        trusted.put("name", safeName(remoteNodeName));
        trusted.put("tokenHash", hash(token));
        trusted.put("createdAt", Instant.now().toString());
        store.putRecord("trusted", remoteNodeId, trusted);
        return token;
    }

    public void saveOutgoingPeer(String nodeId, String name, String baseUrl, String token) throws Exception {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("name", safeName(name));
        fields.put("baseUrl", baseUrl);
        fields.put("accessToken", tokenVault.encrypt(token));
        fields.put("createdAt", Instant.now().toString());
        store.putRecord("peer", nodeId, fields);
    }

    public List<Map<String, Object>> listPeers() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : store.records("trusted")) {
            result.add(Map.of("nodeId", row.get("_id"), "name", row.getOrDefault("name", "Unknown device"),
                    "direction", "INCOMING", "createdAt", row.getOrDefault("createdAt", "")));
        }
        for (Map<String, String> row : store.records("peer")) {
            result.add(Map.of("nodeId", row.get("_id"), "name", row.getOrDefault("name", "Unknown device"),
                    "baseUrl", row.getOrDefault("baseUrl", ""), "direction", "OUTGOING",
                    "createdAt", row.getOrDefault("createdAt", "")));
        }
        result.sort((a, b) -> String.valueOf(a.get("name")).compareToIgnoreCase(String.valueOf(b.get("name"))));
        return result;
    }

    public List<Map<String, Object>> trustedPeers() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : store.records("trusted")) {
            result.add(Map.of("nodeId", row.get("_id"), "name", row.getOrDefault("name", "Unknown device")));
        }
        return result;
    }

    public Map<String, String> authenticateIncoming(String token) throws Exception {
        if (token == null || token.isBlank()) return null;
        String incomingHash = hash(token);
        for (Map<String, String> row : store.records("trusted")) {
            String storedHash = row.get("tokenHash");
            if (storedHash != null && MessageDigest.isEqual(storedHash.getBytes(StandardCharsets.UTF_8), incomingHash.getBytes(StandardCharsets.UTF_8))) {
                return row;
            }
        }
        return null;
    }

    public Map<String, String> outgoingPeer(String nodeId) {
        Map<String, String> row = store.getRecord("peer", nodeId);
        if (row == null) return null;
        String stored = row.get("accessToken");
        try {
            if (stored != null && !tokenVault.isEncrypted(stored)) {
                row.put("accessToken", tokenVault.encrypt(stored));
                store.putRecord("peer", nodeId, row);
            }
            row.put("accessToken", tokenVault.decrypt(row.get("accessToken")));
            return row;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot decrypt saved peer credentials. Restore data/vault.key or pair this device again.", e);
        }
    }

    public void removeOutgoingPeer(String nodeId) throws Exception { store.removeRecord("peer", nodeId); }

    public void removeTrustedPeer(String nodeId) throws Exception {
        store.removeRecord("trusted", nodeId);
        for (Map<String, String> grant : store.records("grant")) {
            if (nodeId.equals(grant.get("peerId"))) store.removeRecord("grant", grant.get("_id"));
        }
    }

    private static String safeName(String value) {
        if (value == null || value.isBlank()) return "Unnamed device";
        return value.length() > 80 ? value.substring(0, 80) : value;
    }

    public static String hash(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
