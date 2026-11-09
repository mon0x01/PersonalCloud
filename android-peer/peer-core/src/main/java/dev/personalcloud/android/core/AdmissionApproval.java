package dev.personalcloud.android.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Signed admission approval issued by an authorized active member.
 *
 * <p>Mirrors the desktop record so both peer cores produce and verify the same
 * canonical bytes. The approval binds one enrollment request to the candidate
 * device and to the exact certificate that issued its membership certificate.</p>
 */
public final class AdmissionApproval {
    public static final String VERSION = "personalcloud-admission-approval/1";
    public static final long DEFAULT_TTL_SECONDS = 15 * 60;
    public static final long MAX_TTL_SECONDS = 60 * 60;
    private static final long CLOCK_SKEW_SECONDS = 120;

    private AdmissionApproval() { }

    public static Map<String, Object> build(String networkId, String requestId,
                                            String candidateNodeId, String candidateNodeName,
                                            String candidatePublicKey, String candidateEndpoint,
                                            String approverNodeId, String approverCertificateSha256,
                                            long ttlSeconds) {
        Instant issued = Instant.now();
        long ttl = ttlSeconds <= 0 ? DEFAULT_TTL_SECONDS : Math.min(ttlSeconds, MAX_TTL_SECONDS);
        Map<String, Object> approval = new LinkedHashMap<String, Object>();
        approval.put("approvalVersion", VERSION);
        approval.put("networkId", requireText(networkId, "Network ID"));
        approval.put("requestId", canonicalUuid(requestId));
        approval.put("candidateNodeId", requireText(candidateNodeId, "Candidate node ID"));
        approval.put("candidateNodeName", requireText(candidateNodeName, "Candidate node name"));
        approval.put("candidatePublicKey", requireText(candidatePublicKey, "Candidate public key"));
        approval.put("candidateEndpoint", requireText(candidateEndpoint, "Candidate endpoint"));
        approval.put("approverNodeId", requireText(approverNodeId, "Approver node ID"));
        approval.put("approverCertificateSha256", requireHash(approverCertificateSha256));
        approval.put("issuedAt", issued.toString());
        approval.put("expiresAt", issued.plusSeconds(ttl).toString());
        return approval;
    }

    public static Map<String, Object> create(String networkId, String requestId,
                                             String candidateNodeId, String candidateNodeName,
                                             String candidatePublicKey, String candidateEndpoint,
                                             String approverNodeId, String approverCertificateSha256,
                                             PrivateKey approverKey, long ttlSeconds) throws Exception {
        return sign(build(networkId, requestId, candidateNodeId, candidateNodeName,
                candidatePublicKey, candidateEndpoint, approverNodeId,
                approverCertificateSha256, ttlSeconds), approverKey);
    }

    public static Map<String, Object> sign(Map<String, Object> approval, PrivateKey approverKey) throws Exception {
        validateStructure(approval);
        java.security.Signature signer = java.security.Signature.getInstance("Ed25519");
        signer.initSign(approverKey);
        signer.update(canonical(approval));
        Map<String, Object> signed = new LinkedHashMap<String, Object>(approval);
        signed.put("signature", Base64.getEncoder().encodeToString(signer.sign()));
        return signed;
    }

    public static Map<String, Object> verify(Map<String, Object> approval, PublicKey approverKey,
                                             String expectedNetworkId, String expectedRequestId,
                                             String expectedCandidateNodeId,
                                             String expectedCandidatePublicKey) throws Exception {
        validateStructure(approval);
        if (!expectedNetworkId.equals(text(approval, "networkId"))
                || !canonicalUuid(expectedRequestId).equals(text(approval, "requestId"))
                || !expectedCandidateNodeId.equals(text(approval, "candidateNodeId"))
                || !expectedCandidatePublicKey.equals(text(approval, "candidatePublicKey"))) {
            throw new SecurityException("The admission approval is bound to a different network, request or device.");
        }
        byte[] signature;
        try { signature = Base64.getDecoder().decode(text(approval, "signature")); }
        catch (IllegalArgumentException invalid) { throw new SecurityException("The admission approval signature is not valid base64."); }
        if (signature.length != 64 || !NetworkIdentity.verify(approverKey, canonical(approval), signature)) {
            throw new SecurityException("The admission approval signature is invalid.");
        }
        Instant now = Instant.now();
        Instant issuedAt = Instant.parse(text(approval, "issuedAt"));
        Instant expiresAt = Instant.parse(text(approval, "expiresAt"));
        if (issuedAt.isAfter(now.plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new SecurityException("The admission approval was issued in the future.");
        }
        if (!expiresAt.isAfter(issuedAt) || expiresAt.isAfter(issuedAt.plusSeconds(MAX_TTL_SECONDS))) {
            throw new SecurityException("The admission approval has an invalid lifetime.");
        }
        if (!now.isBefore(expiresAt)) throw new SecurityException("The admission approval has expired.");
        if (Duration.between(issuedAt, now).toSeconds() > MAX_TTL_SECONDS + CLOCK_SKEW_SECONDS) {
            throw new SecurityException("The admission approval is too old.");
        }
        return approval;
    }

    public static Map<String, Object> verifyWithCertificate(Map<String, Object> approval,
                                                            String approverCertificateJson,
                                                            String expectedNetworkId,
                                                            String expectedRequestId,
                                                            String expectedCandidateNodeId,
                                                            String expectedCandidatePublicKey) throws Exception {
        Map<String, Object> approver = Json.object(approverCertificateJson);
        if (!requireText(string(approver.get("nodeId")), "Approver node ID").equals(text(approval, "approverNodeId"))) {
            throw new SecurityException("The admission approval was issued by a different certificate holder.");
        }
        if (!certificateSha256(approverCertificateJson).equals(text(approval, "approverCertificateSha256"))) {
            throw new SecurityException("The admission approval is bound to a different approver certificate.");
        }
        PublicKey key = NetworkIdentity.decodePublicKey(requireText(string(approver.get("publicKey")), "Approver public key"));
        return verify(approval, key, expectedNetworkId, expectedRequestId,
                expectedCandidateNodeId, expectedCandidatePublicKey);
    }

    public static String certificateSha256(String certificateJson) {
        try {
            return hex(MessageDigest.getInstance("SHA-256")
                    .digest(requireText(certificateJson, "Certificate").getBytes(StandardCharsets.UTF_8)));
        } catch (SecurityException invalid) {
            throw invalid;
        } catch (Exception failure) {
            throw new IllegalStateException("Unable to hash the membership certificate.", failure);
        }
    }

    public static String text(Map<String, Object> map, String key) {
        String value = string(map.get(key));
        if (value.isBlank()) throw new SecurityException("Admission approval is missing '" + key + "'.");
        return value;
    }

    private static void validateStructure(Map<String, Object> approval) {
        if (approval == null) throw new SecurityException("An admission approval is required.");
        if (!VERSION.equals(approval.get("approvalVersion"))) throw new SecurityException("Unsupported admission approval version.");
        canonicalUuid(text(approval, "requestId"));
        requireText(text(approval, "networkId"), "Network ID");
        requireText(text(approval, "candidateNodeId"), "Candidate node ID");
        requireText(text(approval, "candidateNodeName"), "Candidate node name");
        requireText(text(approval, "candidatePublicKey"), "Candidate public key");
        requireText(text(approval, "candidateEndpoint"), "Candidate endpoint");
        requireText(text(approval, "approverNodeId"), "Approver node ID");
        requireHash(text(approval, "approverCertificateSha256"));
        Instant.parse(text(approval, "issuedAt"));
        Instant.parse(text(approval, "expiresAt"));
    }

    private static byte[] canonical(Map<String, Object> approval) {
        Map<String, Object> body = new LinkedHashMap<String, Object>(approval);
        body.remove("signature");
        return Json.stringify(body).getBytes(StandardCharsets.UTF_8);
    }

    private static String canonicalUuid(String value) {
        try {
            String canonical = UUID.fromString(requireText(value, "Request ID")).toString();
            if (!canonical.equalsIgnoreCase(value)) throw new SecurityException("Admission approval request ID must be a canonical UUID.");
            return canonical;
        } catch (IllegalArgumentException invalid) {
            throw new SecurityException("Admission approval request ID must be a canonical UUID.", invalid);
        }
    }

    private static String requireHash(String value) {
        String hash = requireText(value, "Approver certificate SHA-256").toLowerCase(java.util.Locale.ROOT);
        if (!hash.matches("[a-f0-9]{64}")) throw new SecurityException("A valid approver certificate SHA-256 digest is required.");
        return hash;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new SecurityException(label + " is required.");
        return value;
    }

    private static String string(Object value) { return value instanceof String text ? text : ""; }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte value : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }
}
