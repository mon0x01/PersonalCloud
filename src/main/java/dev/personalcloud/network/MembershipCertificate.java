package dev.personalcloud.network;

import dev.personalcloud.net.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A small signed certificate chain rooted in the first device's Ed25519 public key. */
public final class MembershipCertificate {
    private static final int MAX_CHAIN_DEPTH = 32;
    private static final long CLOCK_SKEW_SECONDS = 120;
    private MembershipCertificate() { }

    public static String createRoot(String nodeId, String nodeName, String endpoint, String publicKey,
                                    PrivateKey privateKey) throws Exception {
        String networkId = fingerprint(Base64.getDecoder().decode(publicKey));
        Map<String, Object> payload = payload(networkId, nodeId, nodeName, endpoint, publicKey,
                nodeId, "", java.time.Instant.now().toString());
        return sign(payload, privateKey);
    }

    public static String issue(String networkId, String nodeId, String nodeName, String endpoint,
                               String publicKey, String issuerCertificate, PrivateKey issuerKey) throws Exception {
        CertificateInfo issuer = verify(issuerCertificate);
        if (!networkId.equals(issuer.networkId())) throw new SecurityException("Issuer belongs to a different PersonalCloud network.");
        Map<String, Object> payload = payload(networkId, nodeId, nodeName, endpoint, publicKey,
                issuer.nodeId(), Base64.getEncoder().encodeToString(issuerCertificate.getBytes(StandardCharsets.UTF_8)),
                java.time.Instant.now().toString());
        return sign(payload, issuerKey);
    }

    public static CertificateInfo verify(String certificateJson) throws Exception {
        return verify(certificateJson, 0);
    }

    private static CertificateInfo verify(String certificateJson, int depth) throws Exception {
        if (depth > MAX_CHAIN_DEPTH) throw new SecurityException("Membership certificate chain is too deep.");
        Map<String, Object> cert = Json.object(certificateJson);
        String networkId = required(cert, "networkId");
        String nodeId = required(cert, "nodeId");
        String nodeName = required(cert, "nodeName");
        String endpoint = required(cert, "endpoint");
        String publicKeyText = required(cert, "publicKey");
        String issuerNodeId = required(cert, "issuerNodeId");
        String issuerCertificateEncoded = optional(cert, "issuerCertificate");
        String issuedAt = required(cert, "issuedAt");
        String signatureText = required(cert, "signature");
        PublicKey publicKey = DeviceIdentity.decodePublicKey(publicKeyText);
        Map<String, Object> payload = payload(networkId, nodeId, nodeName, endpoint, publicKeyText,
                issuerNodeId, issuerCertificateEncoded, issuedAt);
        byte[] signature = Base64.getDecoder().decode(signatureText);
        if (signature.length != 64) throw new SecurityException("Invalid membership certificate signature length.");
        java.time.Instant issuedInstant;
        try { issuedInstant = java.time.Instant.parse(issuedAt); }
        catch (java.time.format.DateTimeParseException invalid) {
            throw new SecurityException("Membership certificate has an invalid issue time.");
        }
        if (issuedInstant.isAfter(java.time.Instant.now().plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new SecurityException("Membership certificate was issued in the future.");
        }

        if (issuerCertificateEncoded.isBlank()) {
            if (!nodeId.equals(issuerNodeId)) throw new SecurityException("The network root certificate must be self-issued.");
            String actualNetworkId = fingerprint(publicKey.getEncoded());
            if (!MessageDigest.isEqual(networkId.getBytes(StandardCharsets.US_ASCII), actualNetworkId.getBytes(StandardCharsets.US_ASCII))) {
                throw new SecurityException("The network root fingerprint does not match its public key.");
            }
            if (!DeviceIdentity.verify(publicKey, canonical(payload), signature)) {
                throw new SecurityException("The network root certificate signature is invalid.");
            }
        } else {
            if (nodeId.equals(issuerNodeId)) {
                throw new SecurityException("A non-root membership certificate cannot be self-issued.");
            }
            String issuerJson = new String(Base64.getDecoder().decode(issuerCertificateEncoded), StandardCharsets.UTF_8);
            CertificateInfo issuer = verify(issuerJson, depth + 1);
            if (!issuer.networkId().equals(networkId) || !issuer.nodeId().equals(issuerNodeId)) {
                throw new SecurityException("Membership certificate issuer does not match its parent certificate.");
            }
            if (issuedInstant.isBefore(java.time.Instant.parse(issuer.issuedAt()))) {
                throw new SecurityException("Membership certificate predates its issuer certificate.");
            }
            if (!DeviceIdentity.verify(issuer.publicKey(), canonical(payload), signature)) {
                throw new SecurityException("Membership certificate signature is invalid.");
            }
        }
        validateEndpoint(endpoint);
        return new CertificateInfo(networkId, nodeId, nodeName, endpoint, publicKey, publicKeyText,
                issuerNodeId, issuerCertificateEncoded, issuedAt, certificateJson);
    }

    /** Verifies a certificate and requires it to belong to the expected network and root. */
    public static CertificateInfo verifyForNetwork(String certificateJson, String networkId,
                                                   String rootNodeId) throws Exception {
        CertificateInfo info = verify(certificateJson);
        if (!info.networkId().equals(networkId)) {
            throw new SecurityException("Membership certificate belongs to a different network.");
        }
        List<CertificateInfo> chain = chain(certificateJson);
        if (chain.isEmpty() || !chain.getFirst().nodeId().equals(rootNodeId)) {
            throw new SecurityException("Membership certificate is not rooted in the expected network identity.");
        }
        return info;
    }

    public static List<CertificateInfo> chain(String certificateJson) throws Exception {
        List<CertificateInfo> result = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        String current = certificateJson;
        while (true) {
            CertificateInfo info = verify(current);
            if (!seen.add(info.nodeId())) {
                throw new SecurityException("Membership certificate chain contains a duplicate device identity.");
            }
            result.add(info);
            if (info.issuerCertificate().isBlank()) break;
            current = new String(Base64.getDecoder().decode(info.issuerCertificate()), StandardCharsets.UTF_8);
            if (result.size() > MAX_CHAIN_DEPTH) throw new SecurityException("Membership certificate chain is too deep.");
        }
        java.util.Collections.reverse(result);
        return List.copyOf(result);
    }

    public static String fingerprint(byte[] publicKeyBytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKeyBytes));
    }

    private static Map<String, Object> payload(String networkId, String nodeId, String nodeName,
                                                String endpoint, String publicKey, String issuerNodeId,
                                                String issuerCertificate, String issuedAt) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("networkId", networkId);
        map.put("nodeId", nodeId);
        map.put("nodeName", safeName(nodeName));
        map.put("endpoint", endpoint);
        map.put("publicKey", publicKey);
        map.put("issuerNodeId", issuerNodeId);
        map.put("issuerCertificate", issuerCertificate == null ? "" : issuerCertificate);
        map.put("issuedAt", issuedAt);
        return map;
    }

    private static String sign(Map<String, Object> payload, PrivateKey key) throws Exception {
        byte[] signature = signBytes(key, canonical(payload));
        Map<String, Object> certificate = new LinkedHashMap<>(payload);
        certificate.put("signature", Base64.getEncoder().encodeToString(signature));
        return Json.stringify(certificate);
    }

    private static byte[] signBytes(PrivateKey key, byte[] payload) throws Exception {
        java.security.Signature signer = java.security.Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(payload);
        return signer.sign();
    }

    private static byte[] canonical(Map<String, Object> payload) {
        return Json.stringify(payload).getBytes(StandardCharsets.UTF_8);
    }

    private static String required(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) throw new SecurityException("Membership certificate is missing '" + key + "'.");
        return text;
    }
    private static String optional(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value instanceof String text ? text : "";
    }
    private static String safeName(String value) {
        if (value == null || value.isBlank() || value.length() > 80 || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Device name must contain 1–80 printable characters.");
        }
        return value;
    }
    private static void validateEndpoint(String value) throws Exception {
        java.net.URI uri = java.net.URI.create(value);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new SecurityException("Membership certificate contains an invalid peer endpoint.");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !("http".equalsIgnoreCase(uri.getScheme()) &&
                java.net.InetAddress.getByName(uri.getHost()).isLoopbackAddress())) {
            throw new SecurityException("Non-loopback PersonalCloud endpoints must use HTTPS.");
        }
    }

    public record CertificateInfo(String networkId, String nodeId, String nodeName, String endpoint,
                                  PublicKey publicKey, String publicKeyEncoded, String issuerNodeId,
                                  String issuerCertificate, String issuedAt, String certificateJson) { }
}
