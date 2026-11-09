package dev.personalcloud.android.core;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Signed, attributable revocation of one network member. Revocation is
 * monotonic: a revoked identity can never be reactivated by a stale catalogue.
 */
public final class MembershipRevocation {
    public static final String VERSION = "personalcloud-membership-revocation/1";
    private static final long CLOCK_SKEW_SECONDS = 120;

    private MembershipRevocation() { }

    public static Map<String, Object> build(String networkId, String revokedNodeId,
                                            String revokerNodeId, String reason, Instant revokedAt) {
        Map<String, Object> record = new LinkedHashMap<String, Object>();
        record.put("revocationVersion", VERSION);
        record.put("networkId", requireText(networkId, "Network ID"));
        record.put("revokedNodeId", requireText(revokedNodeId, "Revoked node ID"));
        record.put("revokerNodeId", requireText(revokerNodeId, "Revoker node ID"));
        record.put("revokedAt", (revokedAt == null ? Instant.now() : revokedAt).toString());
        record.put("reason", safeReason(reason));
        return record;
    }

    public static Map<String, Object> create(String networkId, String revokedNodeId,
                                             String revokerNodeId, String reason,
                                             PrivateKey revokerKey) throws Exception {
        return sign(build(networkId, revokedNodeId, revokerNodeId, reason, Instant.now()), revokerKey);
    }

    public static Map<String, Object> sign(Map<String, Object> record, PrivateKey revokerKey) throws Exception {
        validateStructure(record);
        java.security.Signature signer = java.security.Signature.getInstance("Ed25519");
        signer.initSign(revokerKey);
        signer.update(canonical(record));
        Map<String, Object> signed = new LinkedHashMap<String, Object>(record);
        signed.put("signature", Base64.getEncoder().encodeToString(signer.sign()));
        return signed;
    }

    public static Map<String, Object> verify(Map<String, Object> record, PublicKey revokerKey,
                                             String expectedNetworkId, String expectedRevokedNodeId) throws Exception {
        validateStructure(record);
        if (!expectedNetworkId.equals(text(record, "networkId"))
                || !expectedRevokedNodeId.equals(text(record, "revokedNodeId"))) {
            throw new SecurityException("The revocation record is bound to a different network or member.");
        }
        byte[] signature;
        try { signature = Base64.getDecoder().decode(text(record, "signature")); }
        catch (IllegalArgumentException invalid) { throw new SecurityException("The revocation signature is not valid base64."); }
        if (signature.length != 64 || !NetworkIdentity.verify(revokerKey, canonical(record), signature)) {
            throw new SecurityException("The revocation signature is invalid.");
        }
        Instant revokedAt = Instant.parse(text(record, "revokedAt"));
        if (revokedAt.isAfter(Instant.now().plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new SecurityException("The revocation timestamp is in the future.");
        }
        return record;
    }

    public static Instant revokedAt(Map<String, Object> record) {
        return Instant.parse(text(record, "revokedAt"));
    }

    public static String text(Map<String, Object> map, String key) {
        String value = string(map.get(key));
        if (value.isBlank()) throw new SecurityException("Revocation record is missing '" + key + "'.");
        return value;
    }

    private static void validateStructure(Map<String, Object> record) {
        if (record == null) throw new SecurityException("A revocation record is required.");
        if (!VERSION.equals(record.get("revocationVersion"))) throw new SecurityException("Unsupported revocation record version.");
        requireText(text(record, "networkId"), "Network ID");
        requireText(text(record, "revokedNodeId"), "Revoked node ID");
        requireText(text(record, "revokerNodeId"), "Revoker node ID");
        Instant.parse(text(record, "revokedAt"));
        Object reason = record.get("reason");
        if (reason != null && !(reason instanceof String)) throw new SecurityException("Revocation reason must be text.");
    }

    private static byte[] canonical(Map<String, Object> record) {
        Map<String, Object> body = new LinkedHashMap<String, Object>(record);
        body.remove("signature");
        return Json.stringify(body).getBytes(StandardCharsets.UTF_8);
    }

    private static String safeReason(String value) {
        if (value == null) return "";
        String reason = value.strip();
        if (reason.length() > 240 || reason.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Revocation reason must contain at most 240 printable characters.");
        }
        return reason;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new SecurityException(label + " is required.");
        return value;
    }

    private static String string(Object value) { return value instanceof String text ? text : ""; }
}
