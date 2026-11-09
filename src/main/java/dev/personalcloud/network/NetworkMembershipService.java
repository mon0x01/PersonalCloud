package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.SecretFiles;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.net.Json;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Private network account, device identity and member-certificate lifecycle.
 * The account password is used only to submit an enrollment request. Day-to-day peer
 * authentication uses an individual device Ed25519 key and its signed membership chain.
 */
public final class NetworkMembershipService {
    private static final int PBKDF2_ITERATIONS = 310_000;
    private static final int PBKDF2_BITS = 256;
    private static final long CHALLENGE_LIFETIME_SECONDS = 90;
    private static final long ENROLLMENT_LIFETIME_SECONDS = 15 * 60;
    private static final int MAX_PENDING = 50;
    private static final long AUTH_CLOCK_SKEW_SECONDS = 60;
    private static final long ONLINE_TTL_SECONDS = 90;
    private static final long ONLINE_FUTURE_TOLERANCE_SECONDS = 60;

    private final StateStore store;
    private final AppConfig config;
    private final DeviceIdentity identity;
    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();

    public NetworkMembershipService(StateStore store, AppConfig config) throws Exception {
        this.store = store;
        this.config = config;
        this.identity = new DeviceIdentity(config.dataDirectory());
    }

    public DeviceIdentity identity() { return identity; }

    public synchronized Map<String, Object> status() {
        Map<String, String> network = network();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("joined", network != null);
        result.put("nodeId", config.nodeId());
        result.put("nodeName", config.nodeName());
        result.put("networkId", network == null ? "" : network.getOrDefault("networkId", ""));
        result.put("networkName", network == null ? "" : network.getOrDefault("networkName", ""));
        result.put("accountName", network == null ? "" : network.getOrDefault("accountName", ""));
        result.put("members", network == null ? 0 : store.records("member").stream()
                .filter(row -> "ACTIVE".equals(row.getOrDefault("status", "ACTIVE"))).count());
        result.put("pendingRequests", network == null ? 0 : store.records("enrollment").stream()
                .filter(row -> "PENDING".equals(row.get("status"))).count());
        return result;
    }

    public synchronized Map<String, Object> bootstrap(String networkName, String accountName, char[] password) throws Exception {
        if (network() != null) throw new IllegalStateException("This device already belongs to a PersonalCloud network. Leave that network explicitly before creating another.");
        String safeNetworkName = validateDisplayName(networkName, "Network name");
        String safeAccount = validateAccountName(accountName);
        validatePassword(password);
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        byte[] verifier = derivePassword(password, salt);
        String endpoint = localEndpoint();
        String certificate = MembershipCertificate.createRoot(config.nodeId(), config.nodeName(), endpoint,
                identity.publicKeyBase64(), identity.privateKey());
        MembershipCertificate.CertificateInfo root = MembershipCertificate.verify(certificate);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("networkId", root.networkId());
        fields.put("networkName", safeNetworkName);
        fields.put("accountName", safeAccount);
        fields.put("salt", Base64.getEncoder().encodeToString(salt));
        fields.put("accountVerifier", Base64.getEncoder().encodeToString(verifier));
        fields.put("rootNodeId", config.nodeId());
        fields.put("rootCertificate", certificate);
        fields.put("localCertificate", certificate);
        fields.put("createdAt", Instant.now().toString());
        store.putRecord("network", "active", fields);
        saveMember(root, "ACTIVE", Instant.now().toString(), 0L);
        return status();
    }

    public Map<String, Object> createChallenge() throws Exception {
        Map<String, String> network = requireNetwork();
        purgeTransientState();
        if (challenges.size() >= 1024) throw new IllegalStateException("Too many active enrollment challenges. Try again shortly.");
        String id = SecretFiles.randomToken();
        String nonce = SecretFiles.randomToken();
        challenges.put(id, new Challenge(nonce, Instant.now().plusSeconds(CHALLENGE_LIFETIME_SECONDS)));
        MembershipCertificate.CertificateInfo local = MembershipCertificate.verify(network.get("localCertificate"));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("networkId", network.get("networkId"));
        response.put("networkName", network.get("networkName"));
        response.put("accountName", network.get("accountName"));
        response.put("salt", network.get("salt"));
        response.put("challengeId", id);
        response.put("nonce", nonce);
        response.put("expiresInSeconds", CHALLENGE_LIFETIME_SECONDS);
        response.put("issuerNodeId", config.nodeId());
        response.put("issuerNodeName", config.nodeName());
        response.put("issuerEndpoint", localEndpoint());
        response.put("issuerCertificate", network.get("localCertificate"));
        return response;
    }

    public synchronized Map<String, Object> submitEnrollment(Map<String, Object> request) throws Exception {
        Map<String, String> network = requireNetwork();
        String challengeId = text(request, "challengeId");
        Challenge challenge = challenges.remove(challengeId);
        if (challenge == null || Instant.now().isAfter(challenge.expiresAt())) {
            throw new IllegalArgumentException("Enrollment challenge is invalid or expired. Request a new challenge.");
        }
        String networkId = text(request, "networkId");
        String accountName = text(request, "accountName");
        String nodeId = text(request, "nodeId");
        String nodeName = validateDisplayName(text(request, "nodeName"), "Device name");
        String publicKeyText = text(request, "publicKey");
        String endpoint = text(request, "endpoint");
        String proof = text(request, "proof");
        String requestSignature = text(request, "signature");
        if (!network.get("networkId").equals(networkId) || !network.get("accountName").equals(accountName)) {
            throw new SecurityException("The network name or account does not match this device's private network.");
        }
        if (nodeId.equals(config.nodeId()) || nodeId.length() > 100 || !nodeId.matches("[A-Za-z0-9._:-]{8,100}")) {
            throw new IllegalArgumentException("Invalid or duplicate device identity.");
        }
        PublicKey candidateKey = DeviceIdentity.decodePublicKey(publicKeyText);
        validateEndpoint(endpoint);
        String proofInput = proofInput(networkId, accountName, challengeId, challenge.nonce(), nodeId, nodeName, publicKeyText, endpoint);
        byte[] verifier = Base64.getDecoder().decode(network.get("accountVerifier"));
        byte[] suppliedProof = Base64.getDecoder().decode(proof);
        byte[] expectedProof = hmac(verifier, proofInput.getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedProof, suppliedProof)) throw new SecurityException("Network credentials are incorrect.");
        byte[] signed = requestInput(networkId, nodeId, nodeName, publicKeyText, endpoint, challengeId, proof);
        if (!DeviceIdentity.verify(candidateKey, signed, Base64.getDecoder().decode(requestSignature))) {
            throw new SecurityException("The enrollment request's device signature is invalid.");
        }
        Map<String, String> current = store.getRecord("member", nodeId);
        if (current != null && "REVOKED".equals(current.get("status"))) {
            throw new SecurityException("This device identity was revoked and cannot re-enroll. A new device identity is required.");
        }
        if (current != null && "ACTIVE".equals(current.get("status"))) {
            throw new IllegalArgumentException("This device is already a member of the network.");
        }
        for (Map<String, String> row : store.records("enrollment")) {
            if (nodeId.equals(row.get("nodeId")) && "PENDING".equals(row.get("status"))) {
                return Map.of("requestId", row.get("_id"), "status", "PENDING", "message", "An enrollment request for this device is already pending.");
            }
        }
        long pending = store.records("enrollment").stream().filter(row -> "PENDING".equals(row.get("status"))).count();
        if (pending >= MAX_PENDING) throw new IllegalStateException("The network has reached its pending enrollment request limit.");
        String requestId = UUID.randomUUID().toString();
        Map<String, String> record = new LinkedHashMap<>();
        record.put("nodeId", nodeId);
        record.put("nodeName", nodeName);
        record.put("publicKey", publicKeyText);
        record.put("endpoint", endpoint);
        record.put("status", "PENDING");
        record.put("createdAt", Instant.now().toString());
        record.put("expiresAt", Instant.now().plusSeconds(ENROLLMENT_LIFETIME_SECONDS).toString());
        store.putRecord("enrollment", requestId, record);
        return Map.of("requestId", requestId, "status", "PENDING", "expiresInSeconds", ENROLLMENT_LIFETIME_SECONDS);
    }

    public synchronized List<Map<String, Object>> pendingRequests() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : store.records("enrollment")) {
            if (!"PENDING".equals(row.get("status"))) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("requestId", row.get("_id"));
            item.put("nodeId", row.get("nodeId"));
            item.put("nodeName", row.get("nodeName"));
            item.put("endpoint", row.get("endpoint"));
            item.put("createdAt", row.get("createdAt"));
            result.add(item);
        }
        result.sort(Comparator.comparing(item -> String.valueOf(item.get("createdAt"))));
        return List.copyOf(result);
    }

    public synchronized Map<String, Object> approve(String requestId) throws Exception {
        Map<String, String> request = requirePending(requestId);
        Map<String, String> network = requireNetwork();
        String certificate = MembershipCertificate.issue(network.get("networkId"), request.get("nodeId"),
                request.get("nodeName"), request.get("endpoint"), request.get("publicKey"),
                network.get("localCertificate"), identity.privateKey());
        MembershipCertificate.CertificateInfo info = MembershipCertificate.verify(certificate);
        saveMember(info, "ACTIVE", Instant.now().toString(), 0L);
        request.put("status", "APPROVED");
        request.put("certificate", certificate);
        request.put("approvedAt", Instant.now().toString());
        store.putRecord("enrollment", requestId, request);
        return enrollmentResult(requestId);
    }

    public synchronized Map<String, Object> reject(String requestId, String reason) throws Exception {
        Map<String, String> request = requirePending(requestId);
        request.put("status", "REJECTED");
        request.put("reason", reason == null || reason.isBlank() ? "Rejected by a network member." : safeReason(reason));
        request.put("rejectedAt", Instant.now().toString());
        store.putRecord("enrollment", requestId, request);
        return Map.of("requestId", requestId, "status", "REJECTED");
    }

    public Map<String, Object> enrollmentResult(String requestId) {
        Map<String, String> row = store.getRecord("enrollment", requestId);
        if (row == null) throw new IllegalArgumentException("Enrollment request was not found or has expired.");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requestId", requestId);
        result.put("status", row.getOrDefault("status", "UNKNOWN"));
        if ("APPROVED".equals(row.get("status"))) {
            Map<String, String> network = network();
            result.put("networkId", network.get("networkId"));
            result.put("networkName", network.get("networkName"));
            result.put("accountName", network.get("accountName"));
            result.put("salt", network.get("salt"));
            result.put("certificate", row.get("certificate"));
            result.put("members", membersForWire());
        } else if ("REJECTED".equals(row.get("status"))) {
            result.put("reason", row.getOrDefault("reason", "Rejected."));
        }
        return result;
    }

    public synchronized Map<String, Object> acceptApproval(Map<String, Object> result, char[] password) throws Exception {
        if (network() != null) throw new IllegalStateException("This device already belongs to a network.");
        String status = text(result, "status");
        if (!"APPROVED".equals(status)) throw new IllegalArgumentException("The enrollment request has not been approved.");
        String networkId = text(result, "networkId");
        String networkName = text(result, "networkName");
        String accountName = validateAccountName(text(result, "accountName"));
        String certificate = text(result, "certificate");
        MembershipCertificate.CertificateInfo own = MembershipCertificate.verify(certificate);
        if (!own.networkId().equals(networkId) || !own.nodeId().equals(config.nodeId()) ||
                !own.publicKeyEncoded().equals(identity.publicKeyBase64())) {
            throw new SecurityException("The approved membership certificate does not belong to this device or network.");
        }
        List<MembershipCertificate.CertificateInfo> chain = MembershipCertificate.chain(certificate);
        MembershipCertificate.CertificateInfo root = chain.getFirst();
        byte[] salt = Base64.getDecoder().decode(textFromMemberBundle(result, "salt", ""));
        if (salt.length == 0) {
            // Existing peers deliberately do not disclose the password verifier. The challenge salt is
            // returned with the enrollment result so this device can persist the same account verifier.
            throw new SecurityException("The enrollment response omitted the network credential salt.");
        }
        validatePassword(password);
        byte[] verifier = derivePassword(password, salt);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("networkId", networkId);
        fields.put("networkName", validateDisplayName(networkName, "Network name"));
        fields.put("accountName", accountName);
        fields.put("salt", Base64.getEncoder().encodeToString(salt));
        fields.put("accountVerifier", Base64.getEncoder().encodeToString(verifier));
        fields.put("rootNodeId", root.nodeId());
        fields.put("rootCertificate", root.certificateJson());
        fields.put("localCertificate", certificate);
        fields.put("createdAt", Instant.now().toString());
        store.putRecord("network", "active", fields);
        Object bundle = result.get("members");
        if (bundle instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> map)) continue;
                String memberCert = stringValue(map.get("certificate"));
                if (memberCert.isBlank()) continue;
                MembershipCertificate.CertificateInfo info = MembershipCertificate.verify(memberCert);
                if (!info.networkId().equals(networkId)) throw new SecurityException("Member bundle contains a certificate from another network.");
                String statusValue = stringValue(map.get("status"));
                saveMember(info, "REVOKED".equals(statusValue) ? "REVOKED" : "ACTIVE",
                        stringValue(map.get("addedAt")), parseLong(map.get("lastSeenEpoch"), 0L));
            }
        }
        saveMember(own, "ACTIVE", Instant.now().toString(), 0L);
        for (MembershipCertificate.CertificateInfo info : chain) {
            Map<String, String> existing = store.getRecord("member", info.nodeId());
            if (existing == null) saveMember(info, "ACTIVE", info.issuedAt(), 0L);
            else if ("REVOKED".equals(existing.get("status"))) throw new SecurityException("The membership certificate was issued through a revoked network member.");
        }
        return status();
    }

    /**
     * Reconcile this node's mutable advertised endpoint with the address and port
     * configured for the currently running listener. The signed membership
     * certificate remains immutable; endpoint changes are authenticated through
     * subsequent signed presence/heartbeat exchanges.
     *
     * Only this node's own member row is changed. Remote member endpoints are
     * learned from their own signed heartbeats and are never rewritten here.
     */
    public synchronized Map<String, Object> reconcileLocalEndpoint() throws Exception {
        Map<String, String> network = network();
        if (network == null) {
            return Map.of("updated", false, "reason", "NOT_JOINED", "nodeId", config.nodeId());
        }

        String localCertificate = network.getOrDefault("localCertificate", "");
        MembershipCertificate.CertificateInfo own = MembershipCertificate.verify(localCertificate);
        if (!config.nodeId().equals(own.nodeId())
                || !network.getOrDefault("networkId", "").equals(own.networkId())
                || !identity.publicKeyBase64().equals(own.publicKeyEncoded())) {
            throw new SecurityException("The persisted local membership certificate does not match this node identity.");
        }

        Map<String, String> row = store.getRecord("member", config.nodeId());
        if (row == null) {
            saveMember(own, "ACTIVE", Instant.now().toString(), 0L);
            row = store.getRecord("member", config.nodeId());
        }
        if (row == null || !localCertificate.equals(row.get("certificate"))) {
            throw new SecurityException("The local member record does not match this node's signed membership certificate.");
        }
        if (!"ACTIVE".equals(row.getOrDefault("status", "ACTIVE"))) {
            throw new SecurityException("This node's local network membership is not active.");
        }

        String desiredEndpoint = localEndpoint();
        validateEndpoint(desiredEndpoint);
        String previousEndpoint = row.getOrDefault("endpoint", "");
        boolean changed = !desiredEndpoint.equals(previousEndpoint)
                || !Boolean.parseBoolean(row.getOrDefault("endpointVerified", "false"));
        if (changed) {
            row.put("endpoint", desiredEndpoint);
            row.put("endpointVerified", "true");
            row.put("endpointUpdatedAt", Instant.now().toString());
            row.put("endpointSource", "LOCAL_LISTENER_CONFIGURATION");
            row.put("online", "true");
            store.putRecord("member", config.nodeId(), row);
        }

        return Map.of("nodeId", config.nodeId(), "previousEndpoint", previousEndpoint,
                "endpoint", desiredEndpoint, "updated", changed,
                "endpointVerified", true);
    }

    public synchronized List<Map<String, Object>> members() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : store.records("member")) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("nodeId", row.get("_id"));
            item.put("nodeName", row.getOrDefault("name", "Unknown device"));
            item.put("endpoint", row.getOrDefault("endpoint", ""));
            item.put("status", row.getOrDefault("status", "ACTIVE"));
            item.put("addedAt", row.getOrDefault("addedAt", ""));
            item.put("lastSeenAt", row.getOrDefault("lastSeenAt", ""));
            item.put("lastSeenEpoch", parseLong(row.get("lastSeenEpoch"), 0L));
            item.put("online", row.get("_id").equals(config.nodeId()) || isFreshOnline(row, Instant.now().getEpochSecond()));
            item.put("revokedAt", row.getOrDefault("revokedAt", ""));
            result.add(item);
        }
        result.sort(Comparator.comparing(item -> String.valueOf(item.get("nodeName")).toLowerCase(java.util.Locale.ROOT)));
        return List.copyOf(result);
    }

    public synchronized List<Map<String, Object>> membersForWire() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, String> row : store.records("member")) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("nodeId", row.get("_id"));
            item.put("name", row.getOrDefault("name", "Unknown device"));
            item.put("endpoint", row.getOrDefault("endpoint", ""));
            item.put("status", row.getOrDefault("status", "ACTIVE"));
            item.put("certificate", row.getOrDefault("certificate", ""));
            item.put("addedAt", row.getOrDefault("addedAt", ""));
            item.put("lastSeenEpoch", parseLong(row.get("lastSeenEpoch"), 0L));
            item.put("online", row.get("_id").equals(config.nodeId()) || isFreshOnline(row, Instant.now().getEpochSecond()));
            item.put("revokedAt", row.getOrDefault("revokedAt", ""));
            result.add(item);
        }
        return List.copyOf(result);
    }

    public synchronized void importMembers(List<?> incoming) throws Exception {
        String networkId = requireNetwork().get("networkId");
        for (Object value : incoming) {
            if (!(value instanceof Map<?, ?> map)) continue;
            String certificate = stringValue(map.get("certificate"));
            if (certificate.isBlank()) continue;
            MembershipCertificate.CertificateInfo info = MembershipCertificate.verify(certificate);
            if (!networkId.equals(info.networkId())) throw new SecurityException("A received member certificate belongs to another network.");
            Map<String, String> existing = store.getRecord("member", info.nodeId());
            if (existing != null && !info.certificateJson().equals(existing.get("certificate"))) {
                throw new SecurityException("A received member catalogue attempted to replace an established device certificate.");
            }
            // A stale peer catalogue must never reactivate an identity already revoked locally.
            if (existing != null && "REVOKED".equals(existing.get("status"))) continue;
            String remoteStatus = stringValue(map.get("status"));
            if (existing == null) {
                saveMember(info, "REVOKED".equals(remoteStatus) ? "REVOKED" : "ACTIVE",
                        stringValue(map.get("addedAt")), parseLong(map.get("lastSeenEpoch"), 0L));
                if ("REVOKED".equals(remoteStatus)) {
                    Map<String, String> imported = store.getRecord("member", info.nodeId());
                    imported.put("revokedAt", stringValue(map.get("revokedAt")));
                    imported.put("online", "false");
                    store.putRecord("member", info.nodeId(), imported);
                }
            } else if ("REVOKED".equals(remoteStatus)) {
                existing.put("status", "REVOKED");
                existing.put("revokedAt", stringValue(map.get("revokedAt")));
                existing.put("online", "false");
                store.putRecord("member", info.nodeId(), existing);
            }
        }
    }

    private static boolean isFreshOnline(Map<String, String> member, long nowEpoch) {
        if (!Boolean.parseBoolean(member.getOrDefault("online", "false"))) return false;
        long lastSeen = parseLong(member.get("lastSeenEpoch"), 0L);
        return lastSeen > 0 && lastSeen <= nowEpoch + ONLINE_FUTURE_TOLERANCE_SECONDS
                && lastSeen >= nowEpoch - ONLINE_TTL_SECONDS;
    }

    public synchronized void recordHeartbeat(String nodeId, String endpoint, String nodeName) throws Exception {
        Map<String, String> member = store.getRecord("member", nodeId);
        if (member == null || !"ACTIVE".equals(member.getOrDefault("status", "ACTIVE"))) {
            throw new SecurityException("The heartbeat sender is not an active network member.");
        }
        validateEndpoint(endpoint);
        MembershipCertificate.CertificateInfo info = MembershipCertificate.verify(member.get("certificate"));
        if (!info.nodeName().equals(nodeName)) throw new SecurityException("Heartbeat device name does not match its signed membership certificate.");
        member.put("endpoint", endpoint);
        member.put("endpointVerified", "true");
        member.put("lastSeenAt", Instant.now().toString());
        member.put("lastSeenEpoch", Long.toString(Instant.now().getEpochSecond()));
        member.put("online", "true");
        store.putRecord("member", nodeId, member);
    }

    public synchronized Map<String, Object> setMemberEndpoint(String nodeId, String endpoint) throws Exception {
        if (nodeId == null || nodeId.isBlank() || nodeId.equals(config.nodeId())) {
            throw new IllegalArgumentException("A different network member node ID is required.");
        }

        String candidate = endpoint == null ? "" : endpoint.strip();
        validateEndpoint(candidate);
        java.net.URI parsed = java.net.URI.create(candidate);

        if (!"https".equalsIgnoreCase(parsed.getScheme())
                || parsed.getHost() == null || parsed.getPort() < 1
                || parsed.getRawUserInfo() != null || parsed.getRawQuery() != null
                || parsed.getRawFragment() != null
                || (parsed.getRawPath() != null && !parsed.getRawPath().isEmpty()
                    && !"/".equals(parsed.getRawPath()))) {
            throw new IllegalArgumentException("Use a direct HTTPS endpoint with an explicit port.");
        }

        Map<String, String> member = store.getRecord("member", nodeId);
        if (member == null || !"ACTIVE".equals(member.getOrDefault("status", "ACTIVE"))) {
            throw new SecurityException("The specified device is not an active network member.");
        }

        MembershipCertificate.CertificateInfo info =
                MembershipCertificate.verify(member.get("certificate"));
        if (!nodeId.equals(info.nodeId())
                || !requireNetwork().get("networkId").equals(info.networkId())) {
            throw new SecurityException("The specified device identity does not match this network.");
        }

        member.put("endpoint", candidate);
        member.put("endpointVerified", "false");
        member.put("online", "false");
        member.put("endpointVerified", "false");
        store.putRecord("member", nodeId, member);

        return Map.of("nodeId", nodeId, "endpoint", candidate,
                "endpointVerification", "PENDING", "online", false);
    }

    public synchronized void markOffline(String nodeId) throws Exception {
        Map<String, String> member = store.getRecord("member", nodeId);
        if (member == null || !"ACTIVE".equals(member.getOrDefault("status", "ACTIVE"))) return;
        if (nodeId.equals(config.nodeId())) return;
        member.put("online", "false");
        member.put("endpointVerified", "false");
        store.putRecord("member", nodeId, member);
    }

    public synchronized boolean authenticate(String method, String rawPath, Map<String, List<String>> headers,
                                             byte[] body) throws Exception {
        String nodeId = header(headers, "X-PC-Node-ID");
        String timestampText = header(headers, "X-PC-Timestamp");
        String nonce = header(headers, "X-PC-Nonce");
        String certificateEncoded = header(headers, "X-PC-Certificate");
        String signatureText = header(headers, "X-PC-Signature");
        if (nodeId.isBlank() || timestampText.isBlank() || nonce.isBlank() || certificateEncoded.isBlank() || signatureText.isBlank()) return false;
        long timestamp;
        try { timestamp = Long.parseLong(timestampText); } catch (NumberFormatException invalid) { return false; }
        long now = Instant.now().getEpochSecond();
        // Avoid Math.abs(now - timestamp): subtraction can overflow for Long.MIN_VALUE,
        // making an arbitrarily old signed request appear to be within the clock window.
        if (timestamp < now - AUTH_CLOCK_SKEW_SECONDS || timestamp > now + AUTH_CLOCK_SKEW_SECONDS) return false;
        if (nonce.length() < 20 || nonce.length() > 100 || !nonce.matches("[A-Za-z0-9_-]+")) return false;
        String certificateJson;
        try { certificateJson = new String(Base64.getDecoder().decode(certificateEncoded), StandardCharsets.UTF_8); }
        catch (Exception invalid) { return false; }
        MembershipCertificate.CertificateInfo info;
        try { info = MembershipCertificate.verify(certificateJson); }
        catch (Exception invalid) { return false; }
        Map<String, String> localNetwork = requireNetwork();
        if (!info.nodeId().equals(nodeId) || !info.networkId().equals(localNetwork.get("networkId"))) return false;
        List<MembershipCertificate.CertificateInfo> chain;
        try { chain = MembershipCertificate.chain(certificateJson); } catch (Exception invalid) { return false; }
        if (chain.isEmpty() || !chain.getFirst().nodeId().equals(localNetwork.get("rootNodeId"))) return false;
        Map<String, String> rootMember = store.getRecord("member", localNetwork.get("rootNodeId"));
        if (rootMember == null || "REVOKED".equals(rootMember.get("status"))) return false;
        for (MembershipCertificate.CertificateInfo item : chain) {
            Map<String, String> known = store.getRecord("member", item.nodeId());
            if (known != null && "REVOKED".equals(known.get("status"))) return false;
            if (known != null && !item.certificateJson().equals(known.get("certificate"))) return false;
        }
        String bodyHash = sha256Hex(body == null ? new byte[0] : body);
        String canonical = method.toUpperCase(java.util.Locale.ROOT) + "\n" + rawPath + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash;
        boolean valid;
        try { valid = DeviceIdentity.verify(info.publicKey(), canonical.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(signatureText)); }
        catch (Exception invalid) { valid = false; }
        if (!valid) return false;
        purgeTransientState();
        String replayKey = nodeId + "-" + nonce;
        if (store.getRecord("networkNonce", replayKey) != null) return false;
        Map<String, String> replay = new LinkedHashMap<>();
        replay.put("expiresEpoch", Long.toString(timestamp + AUTH_CLOCK_SKEW_SECONDS));
        store.putRecord("networkNonce", replayKey, replay);
        for (MembershipCertificate.CertificateInfo item : chain) {
            if (store.getRecord("member", item.nodeId()) == null) saveMember(item, "ACTIVE", item.issuedAt(), 0L);
        }
        return true;
    }

    public synchronized Map<String, String> createAuthHeaders(String method, String rawPath, byte[] body) throws Exception {
        Map<String, String> network = requireNetwork();
        long timestamp = Instant.now().getEpochSecond();
        String nonce = SecretFiles.randomToken();
        String bodyHash = sha256Hex(body == null ? new byte[0] : body);
        String canonical = method.toUpperCase(java.util.Locale.ROOT) + "\n" + rawPath + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash;
        String signature = Base64.getEncoder().encodeToString(identity.sign(canonical.getBytes(StandardCharsets.UTF_8)));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-PC-Node-ID", config.nodeId());
        headers.put("X-PC-Timestamp", Long.toString(timestamp));
        headers.put("X-PC-Nonce", nonce);
        headers.put("X-PC-Certificate", Base64.getEncoder().encodeToString(network.get("localCertificate").getBytes(StandardCharsets.UTF_8)));
        headers.put("X-PC-Signature", signature);
        headers.put("X-PC-Body-SHA256", bodyHash);
        return headers;
    }

    public synchronized boolean isActiveMember(String nodeId) {
        Map<String, String> member = store.getRecord("member", nodeId);
        return member != null && "ACTIVE".equals(member.getOrDefault("status", "ACTIVE"));
    }

    public synchronized Map<String, Object> memberDetails(String nodeId) {
        Map<String, String> row = store.getRecord("member", nodeId);
        if (row == null) return Map.of();
        return Map.of("nodeId", nodeId, "name", row.getOrDefault("name", "Unknown device"),
                "endpoint", row.getOrDefault("endpoint", ""), "status", row.getOrDefault("status", "ACTIVE"));
    }

    /** Returns the advertised direct endpoint for an active member, or fails closed. */
    public synchronized String activeMemberEndpoint(String nodeId) {
        Map<String, String> row = store.getRecord("member", nodeId);
        if (row == null || !"ACTIVE".equals(row.getOrDefault("status", "ACTIVE"))) {
            throw new SecurityException("The requested device is not an active network member.");
        }
        String endpoint = row.getOrDefault("endpoint", "");
        if (endpoint.isBlank()) {
            throw new IllegalStateException("The requested device has no advertised direct endpoint yet.");
        }
        return endpoint;
    }

    /** Returns the verified Ed25519 public key for an active member. */
    public synchronized java.security.PublicKey activeMemberPublicKey(String nodeId) throws Exception {
        Map<String, String> row = store.getRecord("member", nodeId);
        if (row == null || !"ACTIVE".equals(row.getOrDefault("status", "ACTIVE"))) {
            throw new SecurityException("The requested device is not an active network member.");
        }
        MembershipCertificate.CertificateInfo info = MembershipCertificate.verify(row.get("certificate"));
        if (!nodeId.equals(info.nodeId())) {
            throw new SecurityException("The member certificate does not match the requested device.");
        }
        return info.publicKey();
    }

    public synchronized void revokeMember(String nodeId) throws Exception {
        Map<String, String> network = requireNetwork();
        if (nodeId.equals(config.nodeId())) throw new IllegalArgumentException("A device cannot revoke its own membership from itself.");
        if (nodeId.equals(network.get("rootNodeId"))) throw new IllegalArgumentException("The network's root identity is the trust anchor. It cannot be revoked without a network identity-rotation procedure.");
        Map<String, String> member = store.getRecord("member", nodeId);
        if (member == null) throw new IllegalArgumentException("Network member not found.");
        member.put("status", "REVOKED");
        member.put("revokedAt", Instant.now().toString());
        store.putRecord("member", nodeId, member);
    }

    private void saveMember(MembershipCertificate.CertificateInfo info, String status, String addedAt, long lastSeenEpoch) throws Exception {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("name", info.nodeName());
        row.put("endpoint", info.endpoint());
        row.put("publicKey", info.publicKeyEncoded());
        row.put("certificate", info.certificateJson());
        row.put("status", status);
        row.put("addedAt", addedAt == null || addedAt.isBlank() ? info.issuedAt() : addedAt);
        row.put("lastSeenAt", "");
        row.put("lastSeenEpoch", Long.toString(lastSeenEpoch));
        row.put("online", info.nodeId().equals(config.nodeId()) ? "true" : "false");
        row.put("issuerNodeId", info.issuerNodeId());
        store.putRecord("member", info.nodeId(), row);
    }

    private Map<String, String> requirePending(String requestId) throws Exception {
        Map<String, String> request = store.getRecord("enrollment", requestId);
        if (request == null || !"PENDING".equals(request.get("status"))) throw new IllegalArgumentException("Pending enrollment request not found.");
        try {
            if (Instant.now().isAfter(Instant.parse(request.get("expiresAt")))) {
                request.put("status", "EXPIRED");
                store.putRecord("enrollment", requestId, request);
                throw new IllegalArgumentException("Enrollment request expired. The device must submit a new request.");
            }
        } catch (java.time.format.DateTimeParseException malformed) {
            store.removeRecord("enrollment", requestId);
            throw new IllegalStateException("Enrollment request metadata is invalid and was removed.");
        }
        return request;
    }

    private Map<String, String> network() { return store.getRecord("network", "active"); }
    private Map<String, String> requireNetwork() {
        Map<String, String> network = network();
        if (network == null) throw new IllegalStateException("This device has not joined a PersonalCloud network. Run 'network bootstrap' or 'network join'.");
        return network;
    }

    private void purgeTransientState() throws Exception {
        Instant now = Instant.now();
        challenges.entrySet().removeIf(entry -> now.isAfter(entry.getValue().expiresAt()));
        for (Map<String, String> row : store.records("networkNonce")) {
            if (parseLong(row.get("expiresEpoch"), 0L) < now.getEpochSecond()) store.removeRecord("networkNonce", row.get("_id"));
        }
    }

    public String localEndpointForProtocol() { return localEndpoint(); }

    private String localEndpoint() {
        String scheme = config.tlsKeystore() == null ? "http" : "https";
        String host = config.bindAddress();
        if ("0.0.0.0".equals(host) || "::".equals(host) || "0:0:0:0:0:0:0:0".equals(host)) {
            host = System.getenv("PERSONALCLOUD_ADVERTISE_ADDRESS");
            if (host == null || host.isBlank()) {
                throw new IllegalStateException("A wildcard listener cannot be advertised safely. Set PERSONALCLOUD_ADVERTISE_ADDRESS to an IP assigned to an active local interface, or bind directly to that address.");
            }
            host = host.strip();
            if (!host.matches("[0-9a-fA-F:.]+")) {
                throw new IllegalArgumentException("PERSONALCLOUD_ADVERTISE_ADDRESS must be a literal IPv4 or IPv6 address without a hostname or scope suffix.");
            }
            try {
                java.net.InetAddress address = java.net.InetAddress.getByName(host);
                java.net.NetworkInterface networkInterface = java.net.NetworkInterface.getByInetAddress(address);
                if (address.isAnyLocalAddress() || networkInterface == null || !networkInterface.isUp()) {
                    throw new IllegalArgumentException("PERSONALCLOUD_ADVERTISE_ADDRESS must be assigned to an active local interface.");
                }
            } catch (java.net.SocketException | java.net.UnknownHostException invalid) {
                throw new IllegalArgumentException("PERSONALCLOUD_ADVERTISE_ADDRESS is not an assigned local IP address.", invalid);
            }
        }
        String uriHost = host.contains(":") ? "[" + host.replace("%", "%25") + "]" : host;
        return scheme + "://" + uriHost + ":" + config.port();
    }

    private static byte[] derivePassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_BITS);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }

    public static byte[] derivePasswordForEnrollment(char[] password, byte[] salt) throws Exception {
        validatePassword(password);
        return derivePassword(password, salt);
    }

    public static String enrollmentProof(byte[] verifier, String networkId, String accountName, String challengeId,
                                         String nonce, String nodeId, String nodeName, String publicKey, String endpoint) throws Exception {
        return Base64.getEncoder().encodeToString(hmac(verifier,
                proofInput(networkId, accountName, challengeId, nonce, nodeId, nodeName, publicKey, endpoint)
                        .getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] enrollmentSignaturePayload(String networkId, String nodeId, String nodeName,
                                                    String publicKey, String endpoint, String challengeId, String proof) {
        return requestInput(networkId, nodeId, nodeName, publicKey, endpoint, challengeId, proof);
    }

    private static byte[] hmac(byte[] key, byte[] input) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input);
    }

    private static String proofInput(String networkId, String accountName, String challengeId, String nonce,
                                     String nodeId, String nodeName, String publicKey, String endpoint) {
        return String.join("\n", networkId, accountName, challengeId, nonce, nodeId, nodeName, publicKey, endpoint);
    }

    private static byte[] requestInput(String networkId, String nodeId, String nodeName, String publicKey,
                                       String endpoint, String challengeId, String proof) {
        return String.join("\n", networkId, nodeId, nodeName, publicKey, endpoint, challengeId, proof).getBytes(StandardCharsets.UTF_8);
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) throw new IllegalArgumentException("Request field '" + key + "' is required.");
        return text;
    }
    private static String textFromMemberBundle(Map<String, Object> map, String key, String fallback) {
        Object value = map.get(key);
        return value instanceof String text ? text : fallback;
    }
    private static String stringValue(Object value) { return value instanceof String text ? text : ""; }
    private static long parseLong(Object value, long fallback) {
        if (value instanceof Number number) return number.longValue();
        if (value instanceof String text) try { return Long.parseLong(text); } catch (NumberFormatException ignored) { }
        return fallback;
    }
    private static String header(Map<String, List<String>> headers, String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && entry.getValue() != null && !entry.getValue().isEmpty()) return entry.getValue().getFirst();
        }
        return "";
    }
    private static String safeReason(String reason) {
        String clean = reason.replaceAll("[\\p{Cntrl}]", " ").trim();
        return clean.length() > 200 ? clean.substring(0, 200) : clean;
    }
    private static String validateDisplayName(String value, String label) {
        if (value == null || value.isBlank() || value.length() > 80 || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(label + " must contain 1–80 printable characters.");
        }
        return value.trim();
    }
    private static String validateAccountName(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._-]{3,64}")) {
            throw new IllegalArgumentException("Network account name must be 3–64 characters using letters, numbers, dot, underscore or hyphen.");
        }
        return value;
    }
    private static void validatePassword(char[] password) {
        if (password == null || password.length < 12 || password.length > 256) {
            throw new IllegalArgumentException("Network password must contain between 12 and 256 characters.");
        }
        boolean letter = false, digit = false;
        for (char value : password) {
            if (Character.isLetter(value)) letter = true;
            if (Character.isDigit(value)) digit = true;
            if (Character.isISOControl(value)) throw new IllegalArgumentException("Network password cannot contain control characters.");
        }
        if (!letter || !digit) throw new IllegalArgumentException("Network password must contain at least one letter and one number.");
    }
    private static void validateEndpoint(String endpoint) throws Exception {
        java.net.URI uri;
        try { uri = java.net.URI.create(endpoint); }
        catch (Exception invalid) { throw new IllegalArgumentException("Peer endpoint is invalid."); }
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getPort() < 1 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("Peer endpoint must contain a host and valid port, without credentials or query parameters.");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !("http".equalsIgnoreCase(uri.getScheme()) && java.net.InetAddress.getByName(uri.getHost()).isLoopbackAddress())) {
            throw new SecurityException("Non-loopback PersonalCloud endpoints must use HTTPS.");
        }
    }

    private record Challenge(String nonce, Instant expiresAt) { }
}
