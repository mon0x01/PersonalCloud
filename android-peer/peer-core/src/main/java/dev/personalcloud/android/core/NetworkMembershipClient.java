package dev.personalcloud.android.core;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Android implementation of the desktop password-proof, signed membership and catalogue contract. */
public final class NetworkMembershipClient {
    private static final int PBKDF2_ITERATIONS = 310_000;
    private static final long AUTH_CLOCK_SKEW_SECONDS = 60;
    private static final long ONLINE_TTL_SECONDS = 90;
    private static final long ONLINE_FUTURE_TOLERANCE_SECONDS = 60;
    private static final int MAX_PARALLEL_CATALOGUE_PEERS = 4;
    private final StateStore store;
    private final String nodeId;
    private final String nodeName;
    private volatile String localEndpoint;
    private final NetworkIdentity identity;
    private final Map<String, Object> state;
    private final CatalogueTransport catalogueTransport;

    /** Narrow injectable boundary used by deterministic sync/failure tests. */
    public interface CatalogueTransport {
        Map<String, Object> getSignedJson(String baseUrl, String path, Map<String, String> headers,
                                          String trustedCaPath) throws Exception;
        Map<String, Object> postSignedJson(String baseUrl, String path, Map<String, Object> body,
                                           Map<String, String> headers, String trustedCaPath) throws Exception;
    }

    private static final CatalogueTransport DEFAULT_CATALOGUE_TRANSPORT = new CatalogueTransport() {
        @Override public Map<String, Object> getSignedJson(String baseUrl, String path,
                Map<String, String> headers, String trustedCaPath) throws Exception {
            return PeerConnector.getSignedJson(baseUrl, path, headers, trustedCaPath);
        }
        @Override public Map<String, Object> postSignedJson(String baseUrl, String path,
                Map<String, Object> body, Map<String, String> headers, String trustedCaPath) throws Exception {
            return PeerConnector.postSignedJson(baseUrl, path, body, headers, trustedCaPath);
        }
    };

    public NetworkMembershipClient(StateStore store, String nodeId, String nodeName, String localEndpoint) throws Exception {
        this(store, nodeId, nodeName, localEndpoint, DEFAULT_CATALOGUE_TRANSPORT);
    }

    NetworkMembershipClient(StateStore store, String nodeId, String nodeName, String localEndpoint,
                            CatalogueTransport catalogueTransport) throws Exception {
        if (nodeId == null || !nodeId.matches("[A-Za-z0-9._:-]{8,100}")) throw new IllegalArgumentException("Invalid Android node ID.");
        validateName(nodeName);
        validateEndpoint(localEndpoint);
        this.store = store;
        this.nodeId = nodeId;
        this.nodeName = nodeName;
        this.localEndpoint = localEndpoint;
        if (catalogueTransport == null) throw new IllegalArgumentException("Catalogue transport is required.");
        this.catalogueTransport = catalogueTransport;
        // NetworkIdentity may create and persist a new keypair. Load the shared domain only
        // after that write so the initial state cannot overwrite and discard the new identity.
        this.identity = new NetworkIdentity(store);
        this.state = store.loadDomain("network");
        ensureMap("members");
        ensureMap("pendingRequests");
        ensureMap("challenges");
        ensureMap("nonces");
        ensureMap("usedApprovals");
        persist();
    }

    public NetworkIdentity identity() { return identity; }

    /** Restores a previously joined member identity without requiring the foreground peer service to be running. */
    public static NetworkMembershipClient restore(StateStore store, String nodeId, String nodeName) throws Exception {
        Map<String, Object> saved = store.loadDomain("network");
        String endpoint = string(saved.get("localEndpoint"));
        if (endpoint.isBlank() || string(saved.get("localCertificate")).isBlank()) return null;
        return new NetworkMembershipClient(store, nodeId, nodeName, endpoint);
    }

    public synchronized Map<String, Object> status() {
        boolean joined = !string(state.get("networkId")).isEmpty();
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("joined", joined);
        result.put("nodeId", nodeId);
        result.put("nodeName", nodeName);
        result.put("networkId", string(state.get("networkId")));
        result.put("networkName", string(state.get("networkName")));
        result.put("accountName", string(state.get("accountName")));
        result.put("endpoint", localEndpoint);
        result.put("members", object(state.get("members")).values().stream()
                .filter(value -> "ACTIVE".equals(string(object(value).get("status")))).count());
        result.put("pendingRequests", object(state.get("pendingRequests")).size());
        boolean consent = Boolean.parseBoolean(string(state.get("filesystemConsent")));
        result.put("filesystemConsent", consent);
        result.put("filesystemConsentRequired", joined && !consent);
        result.put("canApproveAdmissions", canApproveAdmissions());
        return result;
    }

    /** True only when this Android device is an active member authorized to admit new devices. */
    public synchronized boolean canApproveAdmissions() {
        if (!isJoined()) return false;
        Map<String, Object> local = object(object(state.get("members")).get(nodeId));
        if (local.isEmpty() || !"ACTIVE".equals(string(local.get("status")))) return false;
        try {
            CertificateInfo own = verifyCertificate(required(state, "localCertificate"));
            if (!own.nodeId.equals(nodeId) || !own.publicKeyBase64.equals(identity.publicKeyBase64())) return false;
        } catch (Exception invalid) {
            return false;
        }
        long active = object(state.get("members")).values().stream()
                .filter(value -> "ACTIVE".equals(string(object(value).get("status")))).count();
        if (active < 1) return false;
        if (nodeId.equals(string(state.get("rootNodeId")))) return true;
        return active >= 2;
    }

    /** Records explicit owner consent for broad eligible-filesystem access. */
    public synchronized Map<String, Object> recordFilesystemConsent(boolean granted) throws Exception {
        requireNetwork();
        state.put("filesystemConsent", Boolean.toString(granted));
        state.put("filesystemConsentAt", Instant.now().toString());
        persist();
        return Map.of("filesystemConsent", granted, "filesystemConsentRequired", !granted);
    }

    /**
     * Updates this device's mutable routing endpoint after a network change.
     * The signed membership certificate is deliberately immutable; only the
     * locally observed endpoint and the local member catalogue row are changed.
     */
    public synchronized Map<String, Object> updateLocalEndpoint(String candidate) throws Exception {
        validateEndpoint(candidate);
        String normalized = candidate == null ? "" : candidate.trim();
        Map<String, Object> currentMembers = object(state.get("members"));
        Map<String, Object> currentOwn = object(currentMembers.get(nodeId));
        boolean persistedEndpointMatches = normalized.equals(string(state.get("localEndpoint")))
                && (currentOwn.isEmpty() || normalized.equals(string(currentOwn.get("endpoint"))));
        if (normalized.equals(localEndpoint) && persistedEndpointMatches) {
            return Map.of("nodeId", nodeId, "endpoint", localEndpoint, "changed", false,
                    "certificatePreserved", true);
        }

        Map<String, Object> previousState = new LinkedHashMap<String, Object>(state);
        Map<String, Object> nextState = new LinkedHashMap<String, Object>(state);
        Map<String, Object> nextMembers = new LinkedHashMap<String, Object>(currentMembers);
        Map<String, Object> own = new LinkedHashMap<String, Object>(currentOwn);
        if (!own.isEmpty()) {
            long now = Instant.now().getEpochSecond();
            own.put("endpoint", normalized);
            own.put("endpointVerified", true);
            own.put("lastSeenAt", Instant.now().toString());
            own.put("lastSeenEpoch", now);
            own.put("online", true);
            nextMembers.put(nodeId, own);
        }
        nextState.put("localEndpoint", normalized);
        nextState.put("members", nextMembers);
        state.clear();
        state.putAll(nextState);
        try {
            persist();
        } catch (Exception failure) {
            state.clear();
            state.putAll(previousState);
            throw failure;
        }
        String previous = localEndpoint;
        localEndpoint = normalized;
        return Map.of("nodeId", nodeId, "previousEndpoint", previous,
                "endpoint", normalized, "changed", true, "certificatePreserved", true);
    }

    /** Creates a network on this Android device. The verifier, never the password, is persisted. */
    public synchronized Map<String, Object> bootstrap(String networkName, String accountName, char[] password) throws Exception {
        if (!string(state.get("networkId")).isEmpty()) throw new IllegalStateException("This Android device already belongs to a PersonalCloud network.");
        validateName(networkName);
        validateAccount(accountName);
        validatePassword(password);
        byte[] salt = new byte[16]; new java.security.SecureRandom().nextBytes(salt);
        byte[] verifier = derivePassword(password, salt);
        String certificate = createRootCertificate();
        CertificateInfo root = verifyCertificate(certificate);
        state.put("networkId", root.networkId);
        state.put("networkName", networkName.trim());
        state.put("accountName", accountName);
        state.put("salt", Base64.getEncoder().encodeToString(salt));
        state.put("accountVerifier", Base64.getEncoder().encodeToString(verifier));
        state.put("rootNodeId", nodeId);
        state.put("rootCertificate", certificate);
        state.put("localCertificate", certificate);
        state.put("localEndpoint", localEndpoint);
        state.put("filesystemConsent", "false");
        saveMember(root, "ACTIVE", Instant.now().toString(), 0L);
        persist();
        java.util.Arrays.fill(verifier, (byte) 0);
        return status();
    }

    /** Starts approval-gated enrollment. The password is converted to a verifier and immediately discarded. */
    public synchronized Map<String, Object> beginJoin(String peerBaseUrl, String accountName, char[] password, String trustedCaPath) throws Exception {
        return beginJoin(peerBaseUrl, accountName, password, trustedCaPath, false);
    }

    /**
     * Starts approval-gated enrollment. Broad filesystem access stays disabled
     * unless the device owner explicitly consents during enrollment.
     */
    public synchronized Map<String, Object> beginJoin(String peerBaseUrl, String accountName, char[] password,
                                                      String trustedCaPath, boolean filesystemConsent) throws Exception {
        if (!string(state.get("networkId")).isEmpty()) throw new IllegalStateException("This Android device already belongs to a PersonalCloud network.");
        validatePassword(password);
        Map<String, Object> challenge = PeerConnector.getJson(peerBaseUrl, "/network/challenge", trustedCaPath);
        byte[] salt = Base64.getDecoder().decode(required(challenge, "salt"));
        if (salt.length != 16) throw new SecurityException("The network returned an invalid credential salt.");
        String networkId = required(challenge, "networkId");
        CertificateInfo issuer = verifyCertificate(required(challenge, "issuerCertificate"));
        String challengeIssuerEndpoint = required(challenge, "issuerEndpoint");
        validateEndpoint(challengeIssuerEndpoint);
        if (!networkId.equals(issuer.networkId)
                || !required(challenge, "issuerNodeId").equals(issuer.nodeId)) {
            throw new SecurityException("The enrollment challenge issuer identity does not match its signed certificate.");
        }
        String account = accountName == null || accountName.trim().isEmpty() ? required(challenge, "accountName") : accountName.trim();
        validateAccount(account);
        String challengeId = required(challenge, "challengeId");
        String nonce = required(challenge, "nonce");
        byte[] verifier = derivePassword(password, salt);
        String verifierText = Base64.getEncoder().encodeToString(verifier);
        String publicKey = identity.publicKeyBase64();
        String proofInput = join(networkId, account, challengeId, nonce, nodeId, nodeName, publicKey, localEndpoint);
        String proof = Base64.getEncoder().encodeToString(hmac(verifier, proofInput.getBytes(StandardCharsets.UTF_8)));
        String signaturePayload = join(networkId, nodeId, nodeName, publicKey, localEndpoint, challengeId, proof);
        String signature = Base64.getEncoder().encodeToString(identity.sign(signaturePayload.getBytes(StandardCharsets.UTF_8)));
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("networkId", networkId); request.put("accountName", account); request.put("challengeId", challengeId);
        request.put("nodeId", nodeId); request.put("nodeName", nodeName); request.put("publicKey", publicKey);
        request.put("endpoint", localEndpoint); request.put("proof", proof); request.put("signature", signature);
        Map<String, Object> submitted;
        try { submitted = PeerConnector.postJson(peerBaseUrl, "/network/enroll", request, trustedCaPath); }
        finally { java.util.Arrays.fill(verifier, (byte) 0); }
        Map<String, Object> pending = new LinkedHashMap<String, Object>();
        pending.put("requestId", required(submitted, "requestId"));
        pending.put("peerBaseUrl", normalizeBase(peerBaseUrl));
        pending.put("trustedCaPath", trustedCaPath);
        pending.put("networkId", networkId);
        pending.put("accountName", account);
        pending.put("salt", Base64.getEncoder().encodeToString(salt));
        pending.put("accountVerifier", verifierText);
        pending.put("rootCertificate", certificateRoot(required(challenge, "issuerCertificate")));
        pending.put("filesystemConsent", Boolean.toString(filesystemConsent));
        state.put("pendingJoin", pending);
        persist();
        return Map.of("requestId", pending.get("requestId"), "status", string(submitted.get("status")), "networkId", networkId);
    }

    /** Polls the stored enrollment request and installs the signed certificate only after approval. */
    public synchronized Map<String, Object> refreshJoin(String trustedCaPath) throws Exception {
        Map<String, Object> pending = object(state.get("pendingJoin"));
        if (pending.isEmpty()) throw new IllegalStateException("There is no pending Android network enrollment request.");
        String base = required(pending, "peerBaseUrl");
        String requestId = required(pending, "requestId");
        String ca = trustedCaPath == null || trustedCaPath.isEmpty() ? string(pending.get("trustedCaPath")) : trustedCaPath;
        Map<String, Object> response = PeerConnector.getJson(base, "/network/enroll/status/" + requestId, ca);
        String status = required(response, "status");
        if ("PENDING".equals(status)) return Map.of("status", "PENDING", "requestId", requestId);
        if ("REJECTED".equals(status)) {
            state.remove("pendingJoin"); persist();
            return Map.of("status", "REJECTED", "reason", string(response.get("reason")));
        }
        if (!"APPROVED".equals(status)) throw new SecurityException("The network returned an unknown enrollment status.");
        acceptApproval(response, pending);
        return status();
    }

    private void acceptApproval(Map<String, Object> response, Map<String, Object> pending) throws Exception {
        String networkId = required(response, "networkId");
        if (!networkId.equals(string(pending.get("networkId")))) throw new SecurityException("Approval belongs to a different network than the pending request.");
        if (!required(response, "accountName").equals(string(pending.get("accountName")))) throw new SecurityException("Approval belongs to a different network account.");
        String responseSalt = required(response, "salt");
        if (!MessageDigest.isEqual(responseSalt.getBytes(StandardCharsets.US_ASCII), string(pending.get("salt")).getBytes(StandardCharsets.US_ASCII))) {
            throw new SecurityException("The approved network credential salt does not match the enrollment challenge.");
        }
        String certificate = required(response, "certificate");
        CertificateInfo own = verifyCertificate(certificate);
        if (!networkId.equals(own.networkId) || !nodeId.equals(own.nodeId) || !identity.publicKeyBase64().equals(own.publicKeyBase64)) {
            throw new SecurityException("The approved membership certificate does not belong to this Android device or network.");
        }
        List<CertificateInfo> chain = certificateChain(certificate);
        if (chain.isEmpty()) throw new SecurityException("The approved membership chain is empty.");
        CertificateInfo root = chain.get(0);
        String approvedRoot = root.certificateJson;
        String challengedRoot = certificateRoot(required(pending, "rootCertificate"));
        if (!approvedRoot.equals(challengedRoot)) throw new SecurityException("The approval certificate chain is not rooted in the identity that issued the enrollment challenge.");
        Map<String, Object> members = new LinkedHashMap<String, Object>();
        Object incoming = response.get("members");
        if (!(incoming instanceof List<?>)) throw new SecurityException("The approval response omitted the member certificate bundle.");
        Map<String, String> certificateByNode = new LinkedHashMap<String, String>();
        for (CertificateInfo item : chain) certificateByNode.put(item.nodeId, item.certificateJson);
        List<Map<String, Object>> wires = new ArrayList<Map<String, Object>>();
        java.util.Set<String> revokedIncoming = new java.util.HashSet<String>();
        for (Object item : (List<?>) incoming) {
            if (!(item instanceof Map<?, ?>)) continue;
            Map<String, Object> wire = castMap(item);
            String memberCertificate = required(wire, "certificate");
            CertificateInfo info = verifyForNetwork(memberCertificate, networkId, root.nodeId);
            String known = certificateByNode.putIfAbsent(info.nodeId, memberCertificate);
            if (known != null && !known.equals(memberCertificate)) {
                throw new SecurityException("The approval bundle contains conflicting certificates for one device.");
            }
            for (CertificateInfo chained : certificateChain(memberCertificate)) {
                certificateByNode.putIfAbsent(chained.nodeId, chained.certificateJson);
            }
            if ("REVOKED".equals(string(wire.get("status")))) revokedIncoming.add(info.nodeId);
            wires.add(wire);
        }
        for (Map<String, Object> wire : wires) {
            CertificateInfo info = verifyForNetwork(required(wire, "certificate"), networkId, root.nodeId);
            for (CertificateInfo chained : certificateChain(required(wire, "certificate"))) {
                if (!chained.nodeId.equals(info.nodeId) && revokedIncoming.contains(chained.nodeId)) {
                    throw new SecurityException("The approval bundle contains a certificate chain through a revoked member.");
                }
            }
            String memberStatus = "REVOKED".equals(string(wire.get("status"))) ? "REVOKED" : "ACTIVE";
            Map<String, Object> record = memberRecord(info, memberStatus, string(wire.get("addedAt")), number(wire.get("lastSeenEpoch"), 0L));
            String revocationText = string(wire.get("revocation"));
            if ("REVOKED".equals(memberStatus) && !revocationText.isEmpty()) {
                Map<String, Object> revocation = validateRevocation(revocationText, info.nodeId, networkId,
                        root.nodeId, certificateByNode, revokedIncoming);
                record.put("revocation", Json.stringify(revocation));
            } else if (!"REVOKED".equals(memberStatus) && !revocationText.isEmpty()) {
                throw new SecurityException("The approval bundle reported an active device with a revocation record.");
            }
            members.put(info.nodeId, record);
        }
        for (CertificateInfo item : chain) {
            Object existing = members.get(item.nodeId);
            if (existing == null) members.put(item.nodeId, memberRecord(item, "ACTIVE", item.issuedAt, 0L));
            else if ("REVOKED".equals(string(object(existing).get("status")))) throw new SecurityException("The approved certificate chain passes through a revoked member.");
        }
        boolean approvalVerified = false;
        Object approvalValue = response.get("admissionApproval");
        if (approvalValue instanceof String approvalText && !approvalText.isBlank()) {
            Map<String, Object> approval = Json.object(approvalText);
            CertificateInfo approver = null;
            for (CertificateInfo item : chain) if (item.nodeId.equals(own.issuerNodeId)) approver = item;
            if (approver == null) throw new SecurityException("The admission approval issuer is not present in the certificate chain.");
            AdmissionApproval.verifyWithCertificate(approval, approver.certificateJson, networkId,
                    required(pending, "requestId"), nodeId, identity.publicKeyBase64());
            if (!own.nodeName.equals(AdmissionApproval.text(approval, "candidateNodeName"))
                    || !own.endpoint.equals(AdmissionApproval.text(approval, "candidateEndpoint"))) {
                throw new SecurityException("The admission approval is bound to a different device name or endpoint.");
            }
            String digest = hex(NetworkIdentity.sha256(approvalText.getBytes(StandardCharsets.UTF_8)));
            Map<String, Object> used = object(state.get("usedApprovals"));
            if (used.containsKey(digest)) throw new SecurityException("This admission approval has already been used.");
            Map<String, Object> usedRecord = new LinkedHashMap<String, Object>();
            usedRecord.put("usedAt", Instant.now().toString());
            usedRecord.put("requestId", required(pending, "requestId"));
            used.put(digest, usedRecord);
            approvalVerified = true;
        }
        Map<String, Object> ownExisting = object(members.get(nodeId));
        if (!ownExisting.isEmpty() && "REVOKED".equals(string(ownExisting.get("status")))) throw new SecurityException("This Android identity was revoked and cannot re-enroll.");
        members.put(nodeId, memberRecord(own, "ACTIVE", Instant.now().toString(), 0L));
        state.put("networkId", networkId);
        state.put("networkName", required(response, "networkName"));
        state.put("accountName", required(response, "accountName"));
        state.put("salt", string(pending.get("salt")));
        state.put("accountVerifier", string(pending.get("accountVerifier")));
        state.put("rootNodeId", root.nodeId);
        state.put("rootCertificate", root.certificateJson);
        state.put("localCertificate", certificate);
        state.put("localEndpoint", localEndpoint);
        state.put("filesystemConsent", Boolean.toString(Boolean.parseBoolean(string(pending.get("filesystemConsent")))));
        state.put("admissionApprovalVerified", Boolean.toString(approvalVerified));
        state.put("members", members);
        state.remove("pendingJoin");
        persist();
    }

    public synchronized Map<String, Object> createChallenge() throws Exception {
        requireNetwork();
        String id = randomToken(), nonce = randomToken();
        Map<String, Object> challenges = object(state.get("challenges"));
        purgeTransient();
        if (challenges.size() >= 1024) throw new IllegalStateException("Too many active Android enrollment challenges.");
        challenges.put(id, Map.of("nonce", nonce, "expiresEpoch", Instant.now().getEpochSecond() + 90));
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("networkId", state.get("networkId")); result.put("networkName", state.get("networkName"));
        result.put("accountName", state.get("accountName")); result.put("salt", state.get("salt"));
        result.put("challengeId", id); result.put("nonce", nonce); result.put("expiresInSeconds", 90);
        result.put("issuerNodeId", nodeId); result.put("issuerNodeName", nodeName); result.put("issuerEndpoint", localEndpoint);
        result.put("issuerCertificate", state.get("localCertificate"));
        persist(); return result;
    }

    public synchronized Map<String, Object> submitEnrollment(Map<String, Object> request) throws Exception {
        requireNetwork(); purgeTransient();
        String challengeId = required(request, "challengeId");
        Map<String, Object> challenge = object(object(state.get("challenges")).remove(challengeId));
        if (challenge.isEmpty() || number(challenge.get("expiresEpoch"), 0L) < Instant.now().getEpochSecond()) {
            persist(); throw new IllegalArgumentException("Enrollment challenge is invalid or expired.");
        }
        String networkId = required(request, "networkId"), accountName = required(request, "accountName");
        String remoteId = required(request, "nodeId"), remoteName = required(request, "nodeName");
        String publicKeyText = required(request, "publicKey"), endpoint = required(request, "endpoint");
        String proof = required(request, "proof"), signatureText = required(request, "signature");
        if (!networkId.equals(string(state.get("networkId"))) || !accountName.equals(string(state.get("accountName")))) throw new SecurityException("Network account credentials do not match.");
        if (remoteId.equals(nodeId) || !remoteId.matches("[A-Za-z0-9._:-]{8,100}")) throw new IllegalArgumentException("Invalid or duplicate device identity.");
        validateName(remoteName); validateEndpoint(endpoint);
        PublicKey candidate = NetworkIdentity.decodePublicKey(publicKeyText);
        String proofInput = join(networkId, accountName, challengeId, required(challenge, "nonce"), remoteId, remoteName, publicKeyText, endpoint);
        byte[] verifier = Base64.getDecoder().decode(required(state, "accountVerifier"));
        byte[] expectedProof = hmac(verifier, proofInput.getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedProof, Base64.getDecoder().decode(proof))) throw new SecurityException("Network password proof is invalid.");
        String signed = join(networkId, remoteId, remoteName, publicKeyText, endpoint, challengeId, proof);
        if (!NetworkIdentity.verify(candidate, signed.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(signatureText))) throw new SecurityException("Enrollment device signature is invalid.");
        Map<String, Object> existing = object(object(state.get("members")).get(remoteId));
        if (!existing.isEmpty()) throw new IllegalArgumentException("This device identity is already known to the network.");
        Map<String, Object> requests = object(state.get("pendingRequests"));
        for (Object item : requests.values()) if (remoteId.equals(string(object(item).get("nodeId"))) && "PENDING".equals(string(object(item).get("status")))) {
            persist(); return Map.of("requestId", object(item).get("requestId"), "status", "PENDING");
        }
        if (requests.size() >= 50) throw new IllegalStateException("Android network has reached its pending enrollment limit.");
        String requestId = UUID.randomUUID().toString();
        Map<String, Object> pending = new LinkedHashMap<String, Object>();
        pending.put("requestId", requestId); pending.put("nodeId", remoteId); pending.put("nodeName", remoteName);
        pending.put("publicKey", publicKeyText); pending.put("endpoint", endpoint); pending.put("status", "PENDING");
        pending.put("createdAt", Instant.now().toString()); pending.put("expiresEpoch", Instant.now().getEpochSecond() + 900);
        requests.put(requestId, pending); persist();
        return Map.of("requestId", requestId, "status", "PENDING", "expiresInSeconds", 900);
    }

    public synchronized List<Map<String, Object>> members() {
        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (Map.Entry<String, Object> entry : object(state.get("members")).entrySet()) {
            Map<String, Object> member = object(entry.getValue());
            Map<String, Object> row = new LinkedHashMap<String, Object>();
            row.put("nodeId", entry.getKey()); row.put("nodeName", member.get("name"));
            row.put("endpoint", member.get("endpoint")); row.put("status", member.get("status"));
            row.put("online", entry.getKey().equals(nodeId) || isFreshOnline(member, Instant.now().getEpochSecond()));
            row.put("addedAt", member.get("addedAt")); row.put("lastSeenAt", member.get("lastSeenAt"));
            row.put("lastSeenEpoch", number(member.get("lastSeenEpoch"), 0L));
            row.put("revokedAt", member.get("revokedAt")); result.add(row);
        }
        result.sort(Comparator.comparing(row -> string(row.get("nodeName")).toLowerCase(java.util.Locale.ROOT)));
        return result;
    }

    /** True only for a certificate-validated, non-revoked member of this network. */
    public synchronized boolean isActiveMember(String memberId) {
        if (memberId == null || memberId.isBlank()) return false;
        Map<String, Object> member = object(object(state.get("members")).get(memberId));
        return !member.isEmpty() && "ACTIVE".equals(string(member.get("status")));
    }

    public synchronized List<Map<String, Object>> pendingRequests() {
        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (Object value : object(state.get("pendingRequests")).values()) {
            Map<String, Object> pending = object(value);
            if (!"PENDING".equals(string(pending.get("status")))) continue;
            Map<String, Object> row = new LinkedHashMap<String, Object>();
            row.put("requestId", pending.get("requestId")); row.put("nodeId", pending.get("nodeId"));
            row.put("nodeName", pending.get("nodeName")); row.put("endpoint", pending.get("endpoint")); row.put("createdAt", pending.get("createdAt"));
            result.add(row);
        }
        result.sort(Comparator.comparing(row -> string(row.get("createdAt"))));
        return result;
    }

    public synchronized Map<String, Object> approve(String requestId) throws Exception {
        Map<String, Object> pending = object(object(state.get("pendingRequests")).get(requestId));
        if (pending.isEmpty() || !"PENDING".equals(string(pending.get("status")))) throw new IllegalArgumentException("Pending enrollment request not found.");
        if (number(pending.get("expiresEpoch"), 0L) < Instant.now().getEpochSecond()) throw new IllegalArgumentException("Enrollment request expired.");
        if (!canApproveAdmissions()) throw new SecurityException("This device is not an authorized active admission authority.");
        String certificate = issueCertificate(required(pending, "nodeId"), required(pending, "nodeName"), required(pending, "endpoint"), required(pending, "publicKey"));
        CertificateInfo info = verifyCertificate(certificate);
        Map<String, Object> approval = AdmissionApproval.create(required(state, "networkId"), requestId,
                required(pending, "nodeId"), required(pending, "nodeName"), required(pending, "publicKey"),
                required(pending, "endpoint"), nodeId,
                AdmissionApproval.certificateSha256(required(state, "localCertificate")),
                identity.privateKey(), AdmissionApproval.DEFAULT_TTL_SECONDS);
        saveMember(info, "ACTIVE", Instant.now().toString(), 0L);
        pending.put("status", "APPROVED"); pending.put("certificate", certificate);
        pending.put("admissionApproval", Json.stringify(approval));
        pending.put("approvedAt", Instant.now().toString());
        object(state.get("pendingRequests")).put(requestId, pending); persist();
        return enrollmentResult(requestId);
    }

    public synchronized Map<String, Object> reject(String requestId, String reason) throws Exception {
        Map<String, Object> pending = object(object(state.get("pendingRequests")).get(requestId));
        if (pending.isEmpty() || !"PENDING".equals(string(pending.get("status")))) throw new IllegalArgumentException("Pending enrollment request not found.");
        pending.put("status", "REJECTED"); pending.put("reason", safeReason(reason));
        persist(); return Map.of("requestId", requestId, "status", "REJECTED");
    }

    public synchronized Map<String, Object> enrollmentResult(String requestId) throws Exception {
        Map<String, Object> pending = object(object(state.get("pendingRequests")).get(requestId));
        if (pending.isEmpty()) throw new IllegalArgumentException("Enrollment request not found.");
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.put("requestId", requestId); result.put("status", pending.get("status"));
        if ("APPROVED".equals(string(pending.get("status")))) {
            result.put("networkId", state.get("networkId")); result.put("networkName", state.get("networkName"));
            result.put("accountName", state.get("accountName")); result.put("salt", state.get("salt"));
            result.put("certificate", pending.get("certificate"));
            if (pending.get("admissionApproval") != null) result.put("admissionApproval", pending.get("admissionApproval"));
            result.put("members", membersForWire());
        } else if ("REJECTED".equals(string(pending.get("status")))) result.put("reason", pending.get("reason"));
        return result;
    }

    public synchronized Map<String, String> createAuthHeaders(String method, String rawPath, byte[] body) throws Exception {
        requireNetwork();
        Map<String, Object> local = object(object(state.get("members")).get(nodeId));
        if (local.isEmpty() || !"ACTIVE".equals(string(local.get("status")))) {
            throw new SecurityException("This Android device's network membership is not active; signed requests are refused.");
        }
        long timestamp = Instant.now().getEpochSecond();
        String nonce = randomToken();
        String bodyHash = hex(NetworkIdentity.sha256(body == null ? new byte[0] : body));
        String canonical = method.toUpperCase(java.util.Locale.ROOT) + "\n" + rawPath + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash;
        String signature = Base64.getEncoder().encodeToString(identity.sign(canonical.getBytes(StandardCharsets.UTF_8)));
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("X-PC-Node-ID", nodeId); headers.put("X-PC-Timestamp", Long.toString(timestamp));
        headers.put("X-PC-Nonce", nonce); headers.put("X-PC-Certificate", Base64.getEncoder().encodeToString(required(state, "localCertificate").getBytes(StandardCharsets.UTF_8)));
        headers.put("X-PC-Signature", signature); headers.put("X-PC-Body-SHA256", bodyHash);
        return headers;
    }

    public synchronized boolean authenticate(String method, String rawPath, Map<String, String> headers, byte[] body) throws Exception {
        if (!isJoined()) return false;
        String remoteId = header(headers, "X-PC-Node-ID"), timestampText = header(headers, "X-PC-Timestamp");
        String nonce = header(headers, "X-PC-Nonce"), certificateText = header(headers, "X-PC-Certificate");
        String signatureText = header(headers, "X-PC-Signature");
        if (remoteId.isEmpty() || timestampText.isEmpty() || nonce.isEmpty() || certificateText.isEmpty() || signatureText.isEmpty()) return false;
        long timestamp;
        try { timestamp = Long.parseLong(timestampText); } catch (NumberFormatException invalid) { return false; }
        long now = Instant.now().getEpochSecond();
        // Compare bounds directly; Math.abs(now - timestamp) can overflow for Long.MIN_VALUE.
        if (timestamp < now - AUTH_CLOCK_SKEW_SECONDS || timestamp > now + AUTH_CLOCK_SKEW_SECONDS
                || !nonce.matches("[A-Za-z0-9_-]{20,100}")) return false;
        String certificate;
        try { certificate = new String(Base64.getDecoder().decode(certificateText), StandardCharsets.UTF_8); }
        catch (Exception invalid) { return false; }
        CertificateInfo info;
        List<CertificateInfo> chain;
        try { info = verifyCertificate(certificate); chain = certificateChain(certificate); }
        catch (Exception invalid) { return false; }
        if (!remoteId.equals(info.nodeId) || !string(state.get("networkId")).equals(info.networkId)
                || chain.isEmpty() || !string(state.get("rootNodeId")).equals(chain.get(0).nodeId)) return false;
        for (CertificateInfo item : chain) {
            Map<String, Object> known = object(object(state.get("members")).get(item.nodeId));
            if (!known.isEmpty() && "REVOKED".equals(string(known.get("status")))) return false;
            if (!known.isEmpty() && !item.certificateJson.equals(string(known.get("certificate")))) return false;
        }
        byte[] bodyHash = NetworkIdentity.sha256(body == null ? new byte[0] : body);
        String canonical = method.toUpperCase(java.util.Locale.ROOT) + "\n" + rawPath + "\n" + timestamp + "\n" + nonce + "\n" + hex(bodyHash);
        try { if (!NetworkIdentity.verify(info.publicKey, canonical.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(signatureText))) return false; }
        catch (Exception invalid) { return false; }
        Map<String, Object> nonces = object(state.get("nonces"));
        purgeTransient();
        String replayKey = remoteId + "-" + nonce;
        if (nonces.containsKey(replayKey)) return false;
        nonces.put(replayKey, timestamp + AUTH_CLOCK_SKEW_SECONDS);
        for (CertificateInfo item : chain) if (!object(state.get("members")).containsKey(item.nodeId)) saveMember(item, "ACTIVE", item.issuedAt, 0L);
        persist(); return true;
    }

    public synchronized List<Map<String, Object>> membersForWire() {
        List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
        for (Map.Entry<String, Object> entry : object(state.get("members")).entrySet()) {
            Map<String, Object> row = object(entry.getValue());
            Map<String, Object> wire = new LinkedHashMap<String, Object>();
            wire.put("nodeId", entry.getKey()); wire.put("name", row.get("name")); wire.put("endpoint", row.get("endpoint"));
            wire.put("certificate", row.get("certificate")); wire.put("status", row.get("status")); wire.put("addedAt", row.get("addedAt"));
            wire.put("lastSeenEpoch", number(row.get("lastSeenEpoch"), 0L)); wire.put("online", entry.getKey().equals(nodeId) || isFreshOnline(row, Instant.now().getEpochSecond()));
            wire.put("revokedAt", row.get("revokedAt"));
            if (row.get("revocation") != null) wire.put("revocation", row.get("revocation"));
            result.add(wire);
        }
        result.sort(Comparator.comparing(item -> string(item.get("name")).toLowerCase(java.util.Locale.ROOT)));
        return result;
    }

    public synchronized void importMembers(List<?> incoming) throws Exception {
        requireNetwork();
        String networkId = string(state.get("networkId"));
        Map<String, Object> members = object(state.get("members"));
        Map<String, String> certificateByNode = new LinkedHashMap<String, String>();
        List<Map<String, Object>> wires = new ArrayList<Map<String, Object>>();
        java.util.Set<String> revokedIncoming = new java.util.HashSet<String>();
        for (Object value : incoming) {
            if (!(value instanceof Map<?, ?>)) continue;
            Map<String, Object> wire = castMap(value);
            String certificate = string(wire.get("certificate"));
            if (certificate.isEmpty()) continue;
            CertificateInfo info = verifyForNetwork(certificate, networkId);
            String knownCertificate = certificateByNode.putIfAbsent(info.nodeId, certificate);
            if (knownCertificate != null && !knownCertificate.equals(certificate)) {
                throw new SecurityException("A catalogue contains conflicting certificates for one device.");
            }
            for (CertificateInfo chained : certificateChain(certificate)) {
                certificateByNode.putIfAbsent(chained.nodeId, chained.certificateJson);
                Map<String, Object> known = object(members.get(chained.nodeId));
                if (!known.isEmpty() && "REVOKED".equals(string(known.get("status"))) && !chained.nodeId.equals(info.nodeId)) {
                    throw new SecurityException("A received membership certificate passes through a revoked member.");
                }
            }
            if ("REVOKED".equals(string(wire.get("status")))) revokedIncoming.add(info.nodeId);
            wires.add(wire);
        }
        for (Map<String, Object> wire : wires) {
            CertificateInfo info = verifyForNetwork(required(wire, "certificate"), networkId);
            Map<String, Object> existing = object(members.get(info.nodeId));
            if (!existing.isEmpty() && !info.certificateJson.equals(string(existing.get("certificate")))) {
                throw new SecurityException("A catalogue attempted to replace a known device certificate.");
            }
            // Revocation is monotonic. A stale catalogue can never reactivate an
            // identity that is already revoked locally.
            if (!existing.isEmpty() && "REVOKED".equals(string(existing.get("status")))) continue;
            String status = "REVOKED".equals(string(wire.get("status"))) ? "REVOKED" : "ACTIVE";
            String revocationText = string(wire.get("revocation"));
            Map<String, Object> revocation = null;
            if ("REVOKED".equals(status) && !revocationText.isEmpty()) {
                revocation = validateRevocation(revocationText, info.nodeId, networkId,
                        string(state.get("rootNodeId")), certificateByNode, revokedIncoming);
            } else if (!"REVOKED".equals(status) && !revocationText.isEmpty()) {
                throw new SecurityException("A catalogue reported an active device with a revocation record.");
            }
            long now = Instant.now().getEpochSecond();
            long incomingSeen = number(wire.get("lastSeenEpoch"), 0L);
            if (incomingSeen > now + ONLINE_FUTURE_TOLERANCE_SECONDS) {
                throw new SecurityException("A member catalogue contains a heartbeat timestamp too far in the future.");
            }
            Map<String, Object> saved = memberRecord(info, status, string(wire.get("addedAt")), incomingSeen);
            long existingSeen = number(existing.get("lastSeenEpoch"), 0L);
            boolean existingDirectlyVerified = !existing.isEmpty()
                    && Boolean.TRUE.equals(existing.get("endpointVerified"))
                    && Boolean.TRUE.equals(existing.get("online"))
                    && existingSeen > 0 && existingSeen <= now + ONLINE_FUTURE_TOLERANCE_SECONDS
                    && existingSeen >= now - ONLINE_TTL_SECONDS;
            boolean incomingIsNewer = existing.isEmpty() || incomingSeen > existingSeen;
            if (!existing.isEmpty()) {
                String observedEndpoint = string(existing.get("endpoint"));
                if (!observedEndpoint.isBlank()) saved.put("endpoint", observedEndpoint);
                saved.put("endpointVerified", Boolean.TRUE.equals(existing.get("endpointVerified")));
                if (!incomingIsNewer || existingDirectlyVerified) {
                    saved.put("lastSeenAt", string(existing.get("lastSeenAt")));
                    saved.put("lastSeenEpoch", existingSeen);
                    saved.put("online", Boolean.TRUE.equals(existing.get("online")));
                    saved.put("endpointVerified", existingDirectlyVerified);
                }
            }
            if (incomingIsNewer && !existingDirectlyVerified) saved.put("online", Boolean.TRUE.equals(wire.get("online")));
            saved.put("revokedAt", string(wire.get("revokedAt")));
            if (revocation != null) saved.put("revocation", Json.stringify(revocation));
            if ("REVOKED".equals(status)) saved.put("online", false);
            members.put(info.nodeId, saved);
        }
        persist();
    }

    private Map<String, Object> validateRevocation(String revocationText, String revokedNodeId,
                                                   String networkId, String rootNodeId,
                                                   Map<String, String> certificateByNode,
                                                   java.util.Set<String> revokedIncoming) throws Exception {
        Map<String, Object> record = Json.object(revocationText);
        String revokerNodeId = MembershipRevocation.text(record, "revokerNodeId");
        if (revokerNodeId.equals(revokedNodeId)) {
            throw new SecurityException("A member cannot revoke itself through a catalogue record.");
        }
        if (revokedIncoming.contains(revokerNodeId)) {
            throw new SecurityException("A revoked member cannot issue a revocation record.");
        }
        String revokerCertificate = certificateByNode.get(revokerNodeId);
        Map<String, Object> localRevoker = object(object(state.get("members")).get(revokerNodeId));
        if (!localRevoker.isEmpty()) {
            if (!"ACTIVE".equals(string(localRevoker.get("status")))) {
                throw new SecurityException("A revocation record was issued by an inactive member.");
            }
            revokerCertificate = string(localRevoker.get("certificate"));
        }
        if (revokerCertificate == null || revokerCertificate.isBlank()) {
            throw new SecurityException("A revocation record was issued by an unknown member.");
        }
        CertificateInfo revoker = verifyForNetwork(revokerCertificate, networkId, rootNodeId);
        if (!revoker.nodeId.equals(revokerNodeId)) {
            throw new SecurityException("A revocation record issuer certificate does not match its signer.");
        }
        return MembershipRevocation.verify(record, revoker.publicKey, networkId, revokedNodeId);
    }

    /**
     * Imports a member catalogue only from the endpoint already bound to the expected member identity.
     * The overload without an ID resolves it from the signed membership records and rejects ambiguous endpoints.
     */
    public Map<String, Object> syncCatalogue(String peerBaseUrl, String trustedCaPath) throws Exception {
        String expectedNodeId = memberIdForEndpoint(peerBaseUrl);
        return syncCatalogue(peerBaseUrl, expectedNodeId, trustedCaPath);
    }

    /**
     * Performs the network round-trip without holding the membership monitor. Only local
     * state snapshots and commits are synchronized; a slow peer must not block inbound auth.
     */
    public Map<String, Object> syncCatalogue(String peerBaseUrl, String expectedNodeId,
                                              String trustedCaPath) throws Exception {
        final String networkId;
        final Map<String, String> membersHeaders;
        final Map<String, String> presenceHeaders;
        synchronized (this) {
            requireNetwork();
            if (expectedNodeId == null || expectedNodeId.isBlank() || !isActiveMember(expectedNodeId)
                    || expectedNodeId.equals(nodeId)) {
                throw new SecurityException("Catalogue synchronization target is not a different active network member.");
            }
            networkId = string(state.get("networkId"));
            membersHeaders = createAuthHeaders("GET", "/network/members", new byte[0]);
            presenceHeaders = createAuthHeaders("GET", "/network/presence", new byte[0]);
        }

        Map<String, Object> response = catalogueTransport.getSignedJson(peerBaseUrl,
                "/network/members", membersHeaders, trustedCaPath);
        if (!networkId.equals(required(response, "networkId"))) {
            throw new SecurityException("Remote catalogue belongs to a different PersonalCloud network.");
        }
        Object incoming = response.get("members");
        if (!(incoming instanceof List<?> list)) throw new SecurityException("Remote catalogue omitted its member list.");
        Map<String, Object> presence = catalogueTransport.getSignedJson(peerBaseUrl,
                "/network/presence", presenceHeaders, trustedCaPath);
        if (!Boolean.TRUE.equals(presence.get("online"))) throw new IllegalStateException("Remote member reported itself offline.");
        String remoteId = required(presence, "nodeId");
        if (!expectedNodeId.equals(remoteId)) {
            throw new SecurityException("The connected endpoint identifies as a different network member; expected "
                    + expectedNodeId + " but received " + remoteId + ".");
        }
        importMembers(list);
        recordHeartbeat(remoteId, required(presence, "endpoint"), required(presence, "nodeName"));
        return Map.of("networkId", networkId, "members", members(), "peerNodeId", remoteId,
                "peerOnline", true, "syncedAt", Instant.now().toString());
    }

    /** Performs bounded-concurrency direct catalogue/heartbeat work across active members. */
    public Map<String, Object> synchronizeOnce(String trustedCaPath) throws Exception {
        if (!isJoined()) return Map.of("attempted", 0, "online", List.of(), "offline", List.of());
        List<Map<String, Object>> snapshot = members();
        List<Map<String, Object>> targets = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> member : snapshot) {
            String remoteId = string(member.get("nodeId"));
            if (!remoteId.isBlank() && !remoteId.equals(nodeId)
                    && "ACTIVE".equals(string(member.get("status")))) targets.add(member);
        }
        if (targets.isEmpty()) return Map.of("attempted", 0, "online", List.of(), "offline", List.of(),
                "syncedAt", Instant.now().toString());

        ExecutorService workers = Executors.newFixedThreadPool(
                Math.min(MAX_PARALLEL_CATALOGUE_PEERS, targets.size()), task -> {
                    Thread thread = new Thread(task, "personalcloud-android-catalogue-peer");
                    thread.setDaemon(true);
                    return thread;
                });
        List<Future<Map<String, Object>>> futures = new ArrayList<Future<Map<String, Object>>>();
        try {
            for (Map<String, Object> member : targets) {
                futures.add(workers.submit(() -> synchronizeMember(member, trustedCaPath)));
            }
            List<String> online = new ArrayList<String>();
            List<Map<String, Object>> offline = new ArrayList<Map<String, Object>>();
            for (Future<Map<String, Object>> future : futures) {
                try {
                    Map<String, Object> result = future.get();
                    if (Boolean.TRUE.equals(result.get("online"))) online.add(string(result.get("nodeId")));
                    else offline.add(result);
                } catch (ExecutionException failure) {
                    Throwable cause = failure.getCause() == null ? failure : failure.getCause();
                    offline.add(Map.of("nodeId", "unknown", "reason", safeFailure(cause)));
                }
            }
            Collections.sort(online);
            return Map.of("attempted", targets.size(), "online", List.copyOf(online),
                    "offline", List.copyOf(offline), "syncedAt", Instant.now().toString());
        } finally {
            workers.shutdownNow();
            workers.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    private Map<String, Object> synchronizeMember(Map<String, Object> member, String trustedCaPath) {
        String remoteId = string(member.get("nodeId"));
        String endpoint = string(member.get("endpoint"));
        if (endpoint.isBlank()) {
            try { markOffline(remoteId); } catch (Exception ignored) { }
            return Map.of("nodeId", remoteId, "online", false, "reason", "No direct endpoint is registered.");
        }
        try {
            syncCatalogue(endpoint, remoteId, trustedCaPath);
            sendHeartbeat(endpoint, trustedCaPath);
            return Map.of("nodeId", remoteId, "online", true);
        } catch (Exception unreachable) {
            try { markOffline(remoteId); }
            catch (Exception persistenceFailure) { unreachable.addSuppressed(persistenceFailure); }
            return Map.of("nodeId", remoteId, "online", false, "reason", safeFailure(unreachable));
        }
    }

    private static String safeFailure(Throwable failure) {
        String message = failure.getMessage();
        String value = message == null || message.isBlank() ? failure.getClass().getSimpleName() : message;
        return value.substring(0, Math.min(200, value.length()));
    }

    private static boolean isFreshOnline(Map<String, Object> member, long nowEpoch) {
        if (!Boolean.TRUE.equals(member.get("online"))) return false;
        long lastSeen = number(member.get("lastSeenEpoch"), 0L);
        return lastSeen > 0 && lastSeen <= nowEpoch + ONLINE_FUTURE_TOLERANCE_SECONDS
                && lastSeen >= nowEpoch - ONLINE_TTL_SECONDS;
    }

    private String memberIdForEndpoint(String peerBaseUrl) throws Exception {
        String requested = normalizeBase(peerBaseUrl);
        String match = null;
        for (Map<String, Object> member : members()) {
            if (!"ACTIVE".equals(string(member.get("status")))) continue;
            String endpoint = string(member.get("endpoint"));
            if (endpoint.isBlank() || !normalizeBase(endpoint).equals(requested)) continue;
            String id = string(member.get("nodeId"));
            if (match != null && !match.equals(id)) throw new SecurityException("More than one active member advertises this endpoint.");
            match = id;
        }
        if (match == null) throw new SecurityException("The endpoint is not registered to an active member of this PersonalCloud network.");
        return match;
    }

    /** Sends this node's signed presence to another active network member. */
    public Map<String, Object> sendHeartbeat(String peerBaseUrl, String trustedCaPath) throws Exception {
        final Map<String, Object> body = new LinkedHashMap<String, Object>();
        final Map<String, String> headers;
        final String path = "/network/heartbeat";
        synchronized (this) {
            requireNetwork();
            body.put("nodeId", nodeId); body.put("nodeName", nodeName); body.put("endpoint", localEndpoint);
            byte[] payload = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
            headers = createAuthHeaders("POST", path, payload);
        }
        return catalogueTransport.postSignedJson(peerBaseUrl, path, body, headers, trustedCaPath);
    }

    public synchronized void recordHeartbeat(String remoteId, String endpoint, String remoteName) throws Exception {
        Map<String, Object> member = object(object(state.get("members")).get(remoteId));
        if (member.isEmpty() || "REVOKED".equals(string(member.get("status")))) throw new SecurityException("Heartbeat sender is not an active member.");
        validateEndpoint(endpoint);
        CertificateInfo info = verifyCertificate(required(member, "certificate"));
        if (!info.nodeName.equals(remoteName)) throw new SecurityException("Heartbeat name does not match the signed membership certificate.");
        member.put("endpoint", endpoint);
        member.put("endpointVerified", true);
        member.put("online", true);
        member.put("lastSeenAt", Instant.now().toString());
        member.put("lastSeenEpoch", Instant.now().getEpochSecond());
        object(state.get("members")).put(remoteId, member); persist();
    }

    public synchronized void markOffline(String remoteId) throws Exception {
        Map<String, Object> member = object(object(state.get("members")).get(remoteId));
        if (member.isEmpty() || remoteId.equals(nodeId) || "REVOKED".equals(string(member.get("status")))) return;
        member.put("online", false); member.put("endpointVerified", false);
        object(state.get("members")).put(remoteId, member); persist();
    }

    public synchronized void revokeMember(String remoteId) throws Exception {
        requireNetwork();
        Map<String, Object> local = object(object(state.get("members")).get(nodeId));
        if (local.isEmpty() || !"ACTIVE".equals(string(local.get("status")))) {
            throw new SecurityException("Only an active member can revoke a network device.");
        }
        if (remoteId.equals(nodeId) || remoteId.equals(string(state.get("rootNodeId")))) throw new IllegalArgumentException("The local device and network root cannot be revoked here.");
        Map<String, Object> member = object(object(state.get("members")).get(remoteId));
        if (member.isEmpty()) throw new IllegalArgumentException("Network member not found.");
        Map<String, Object> revocation = MembershipRevocation.create(required(state, "networkId"), remoteId,
                nodeId, "Revoked by an active network member.", identity.privateKey());
        member.put("status", "REVOKED"); member.put("online", false);
        member.put("revokedAt", MembershipRevocation.text(revocation, "revokedAt"));
        member.put("revocation", Json.stringify(revocation));
        object(state.get("members")).put(remoteId, member); persist();
    }

    private String createRootCertificate() throws Exception {
        String networkId = hex(NetworkIdentity.sha256(identity.publicKey().getEncoded()));
        return signCertificate(certificatePayload(networkId, nodeId, nodeName, localEndpoint,
                identity.publicKeyBase64(), nodeId, "", Instant.now().toString()));
    }
    private String issueCertificate(String remoteId, String remoteName, String endpoint, String publicKey) throws Exception {
        CertificateInfo issuer = verifyCertificate(required(state, "localCertificate"));
        Map<String, Object> payload = certificatePayload(issuer.networkId, remoteId, remoteName, endpoint,
                publicKey, nodeId, Base64.getEncoder().encodeToString(issuer.certificateJson.getBytes(StandardCharsets.UTF_8)), Instant.now().toString());
        return signCertificate(payload);
    }
    private String signCertificate(Map<String, Object> payload) throws Exception {
        Map<String, Object> certificate = new LinkedHashMap<String, Object>(payload);
        certificate.put("signature", Base64.getEncoder().encodeToString(identity.sign(Json.stringify(payload).getBytes(StandardCharsets.UTF_8))));
        return Json.stringify(certificate);
    }
    private static Map<String, Object> certificatePayload(String networkId, String id, String name, String endpoint,
                                                          String publicKey, String issuerId, String issuerCertificate, String issuedAt) {
        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("networkId", networkId); payload.put("nodeId", id); payload.put("nodeName", name);
        payload.put("endpoint", endpoint); payload.put("publicKey", publicKey); payload.put("issuerNodeId", issuerId);
        payload.put("issuerCertificate", issuerCertificate); payload.put("issuedAt", issuedAt); return payload;
    }

    private static CertificateInfo verifyCertificate(String json) throws Exception { return verifyCertificate(json, 0); }
    private static CertificateInfo verifyCertificate(String json, int depth) throws Exception {
        if (depth > 32) throw new SecurityException("Membership certificate chain is too deep.");
        Map<String, Object> certificate = Json.object(json);
        String networkId = required(certificate, "networkId"), id = required(certificate, "nodeId");
        String name = required(certificate, "nodeName"), endpoint = required(certificate, "endpoint");
        String publicKeyText = required(certificate, "publicKey"), issuerId = required(certificate, "issuerNodeId");
        String issuerCertificate = string(certificate.get("issuerCertificate")), issuedAt = required(certificate, "issuedAt");
        String signatureText = required(certificate, "signature"); validateName(name); validateEndpoint(endpoint);
        PublicKey publicKey = NetworkIdentity.decodePublicKey(publicKeyText);
        Map<String, Object> payload = certificatePayload(networkId, id, name, endpoint, publicKeyText, issuerId, issuerCertificate, issuedAt);
        byte[] signed = Base64.getDecoder().decode(signatureText);
        if (signed.length != 64) throw new SecurityException("Membership certificate signature has an invalid length.");
        Instant issued;
        try { issued = Instant.parse(issuedAt); }
        catch (java.time.format.DateTimeParseException invalid) { throw new SecurityException("Membership certificate has an invalid issue time."); }
        if (issued.isAfter(Instant.now().plusSeconds(120))) throw new SecurityException("Membership certificate was issued in the future.");
        if (issuerCertificate.isEmpty()) {
            if (!id.equals(issuerId)) throw new SecurityException("Network root certificate must be self-issued.");
            String expectedNetworkId = hex(NetworkIdentity.sha256(publicKey.getEncoded()));
            if (!MessageDigest.isEqual(networkId.getBytes(StandardCharsets.US_ASCII), expectedNetworkId.getBytes(StandardCharsets.US_ASCII))) throw new SecurityException("Network root fingerprint does not match its public key.");
            if (!NetworkIdentity.verify(publicKey, Json.stringify(payload).getBytes(StandardCharsets.UTF_8), signed)) throw new SecurityException("Network root signature is invalid.");
        } else {
            if (id.equals(issuerId)) throw new SecurityException("A non-root membership certificate cannot be self-issued.");
            String parentJson = new String(Base64.getDecoder().decode(issuerCertificate), StandardCharsets.UTF_8);
            CertificateInfo parent = verifyCertificate(parentJson, depth + 1);
            if (!networkId.equals(parent.networkId) || !issuerId.equals(parent.nodeId)) throw new SecurityException("Membership issuer does not match the parent certificate.");
            if (issued.isBefore(Instant.parse(parent.issuedAt))) throw new SecurityException("Membership certificate predates its issuer certificate.");
            if (!NetworkIdentity.verify(parent.publicKey, Json.stringify(payload).getBytes(StandardCharsets.UTF_8), signed)) throw new SecurityException("Membership certificate signature is invalid.");
        }
        return new CertificateInfo(networkId, id, name, endpoint, publicKey, publicKeyText, issuerId, issuerCertificate, issuedAt, json);
    }

    /** Verifies a certificate and requires it to belong to the expected network and root. */
    private CertificateInfo verifyForNetwork(String json, String networkId) throws Exception {
        return verifyForNetwork(json, networkId, string(state.get("rootNodeId")));
    }

    private CertificateInfo verifyForNetwork(String json, String networkId, String rootNodeId) throws Exception {
        CertificateInfo info = verifyCertificate(json);
        if (!networkId.equals(info.networkId)) throw new SecurityException("Membership certificate belongs to a different network.");
        List<CertificateInfo> chain = certificateChain(json);
        if (chain.isEmpty() || rootNodeId == null || rootNodeId.isEmpty()
                || !rootNodeId.equals(chain.get(0).nodeId)) {
            throw new SecurityException("Membership certificate is not rooted in the expected network identity.");
        }
        return info;
    }
    private static List<CertificateInfo> certificateChain(String certificate) throws Exception {
        List<CertificateInfo> chain = new ArrayList<CertificateInfo>(); String current = certificate;
        java.util.Set<String> seen = new java.util.HashSet<String>();
        while (true) {
            CertificateInfo info = verifyCertificate(current);
            if (!seen.add(info.nodeId)) throw new SecurityException("Membership certificate chain contains a duplicate device identity.");
            chain.add(info);
            if (info.issuerCertificate.isEmpty()) break;
            current = new String(Base64.getDecoder().decode(info.issuerCertificate), StandardCharsets.UTF_8);
            if (chain.size() > 32) throw new SecurityException("Membership chain is too deep.");
        }
        Collections.reverse(chain); return chain;
    }

    private void saveMember(CertificateInfo info, String status, String addedAt, long lastSeen) {
        Map<String, Object> member = memberRecord(info, status, addedAt, lastSeen);
        member.put("online", info.nodeId.equals(nodeId));
        member.put("endpointVerified", info.nodeId.equals(nodeId));
        object(state.get("members")).put(info.nodeId, member);
    }
    private static Map<String, Object> memberRecord(CertificateInfo info, String status, String addedAt, long lastSeen) {
        Map<String, Object> row = new LinkedHashMap<String, Object>(); row.put("name", info.nodeName);
        row.put("endpoint", info.endpoint); row.put("publicKey", info.publicKeyBase64); row.put("certificate", info.certificateJson);
        row.put("status", status); row.put("addedAt", addedAt.isEmpty() ? info.issuedAt : addedAt);
        row.put("lastSeenAt", ""); row.put("lastSeenEpoch", lastSeen); row.put("online", false);
        row.put("endpointVerified", false);
        row.put("issuerNodeId", info.issuerNodeId); row.put("revokedAt", ""); return row;
    }
    private Map<String, Object> requireNetwork() { if (!isJoined()) throw new IllegalStateException("Android node has not joined a PersonalCloud network."); return state; }
    private synchronized boolean isJoined() { return !string(state.get("networkId")).isEmpty() && !string(state.get("localCertificate")).isEmpty(); }
    private void ensureMap(String key) { if (!(state.get(key) instanceof Map<?, ?>)) state.put(key, new LinkedHashMap<String, Object>()); }
    private void persist() throws Exception { store.saveDomain("network", state); }
    private static String certificateRoot(String certificate) throws Exception {
        CertificateInfo current = verifyCertificate(certificate);
        while (!current.issuerCertificate.isEmpty()) {
            current = verifyCertificate(new String(Base64.getDecoder().decode(current.issuerCertificate), StandardCharsets.UTF_8));
        }
        return current.certificateJson;
    }
    private void purgeTransient() {
        long now = Instant.now().getEpochSecond();
        object(state.get("challenges")).entrySet().removeIf(entry -> number(object(entry.getValue()).get("expiresEpoch"), 0L) < now);
        object(state.get("nonces")).entrySet().removeIf(entry -> number(entry.getValue(), 0L) < now);
    }

    private static byte[] derivePassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }
    private static void validatePassword(char[] password) {
        if (password == null || password.length < 12 || password.length > 256) throw new IllegalArgumentException("Network password must contain 12–256 characters.");
        boolean letter = false, digit = false;
        for (char c : password) { if (Character.isLetter(c)) letter = true; if (Character.isDigit(c)) digit = true; if (Character.isISOControl(c)) throw new IllegalArgumentException("Network password cannot contain control characters."); }
        if (!letter || !digit) throw new IllegalArgumentException("Network password must contain at least one letter and one number.");
    }
    private static byte[] hmac(byte[] key, byte[] payload) throws Exception { Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256")); return mac.doFinal(payload); }
    private static String join(String... parts) { return String.join("\n", parts); }
    private static String randomToken() { byte[] b = new byte[32]; new java.security.SecureRandom().nextBytes(b); return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    private static String hex(byte[] bytes) { StringBuilder result = new StringBuilder(); for (byte value : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255)); return result.toString(); }
    private static String safeReason(String reason) { String clean = reason == null ? "Rejected by a network member." : reason.replaceAll("[\\p{Cntrl}]", " ").trim(); return clean.isEmpty() ? "Rejected by a network member." : clean.substring(0, Math.min(200, clean.length())); }
    private static void validateName(String value) { if (value == null || value.isBlank() || value.length() > 80 || value.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Device/network name must contain 1–80 printable characters."); }
    private static void validateAccount(String value) { if (value == null || !value.matches("[A-Za-z0-9._-]{3,64}")) throw new IllegalArgumentException("Network account must use 3–64 letters, numbers, dot, underscore or hyphen characters."); }
    private static void validateEndpoint(String value) throws Exception {
        URI uri = URI.create(value);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getPort() < 1 || uri.getPort() > 65535) throw new SecurityException("Invalid device endpoint.");
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !("http".equalsIgnoreCase(uri.getScheme()) && InetAddress.getByName(uri.getHost()).isLoopbackAddress())) throw new SecurityException("Non-loopback PersonalCloud endpoints require HTTPS.");
    }
    private static String normalizeBase(String value) { if (value == null) throw new IllegalArgumentException("Peer URL is required."); String result = value.trim().replaceAll("/+$", ""); if (!(result.startsWith("https://") || result.startsWith("http://127.0.0.1") || result.startsWith("http://localhost"))) throw new SecurityException("Network peer URL must use HTTPS except for loopback testing."); return result; }
    private static String required(Map<String, ?> map, String key) { String value = string(map.get(key)); if (value.isEmpty()) throw new IllegalArgumentException("Network response omitted '" + key + "'."); return value; }
    private static String string(Object value) { return value instanceof String text ? text : ""; }
    private static long number(Object value, long fallback) { return value instanceof Number n ? n.longValue() : fallback; }
    private static Map<String, Object> object(Object value) { if (value instanceof Map<?, ?> map) return castMap(map); return new LinkedHashMap<String, Object>(); }
    @SuppressWarnings("unchecked") private static Map<String, Object> castMap(Object value) { return (Map<String, Object>) value; }
    private static String header(Map<String, String> headers, String name) { for (Map.Entry<String, String> entry : headers.entrySet()) if (entry.getKey().equalsIgnoreCase(name)) return entry.getValue(); return ""; }

    private static final class CertificateInfo {
        final String networkId, nodeId, nodeName, endpoint, publicKeyBase64, issuerNodeId, issuerCertificate, issuedAt, certificateJson;
        final PublicKey publicKey;
        CertificateInfo(String n, String i, String name, String ep, PublicKey key, String keyText, String issuer, String parent, String date, String json) {
            networkId=n; nodeId=i; nodeName=name; endpoint=ep; publicKey=key; publicKeyBase64=keyText; issuerNodeId=issuer; issuerCertificate=parent; issuedAt=date; certificateJson=json;
        }
    }
}
