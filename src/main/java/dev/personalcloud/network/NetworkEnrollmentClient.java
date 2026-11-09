package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.net.Json;
import dev.personalcloud.net.RemotePeerClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Performs a password-proved, approval-gated enrollment against an existing network member. */
public final class NetworkEnrollmentClient {
    private final HttpClient client;

    public NetworkEnrollmentClient() throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NEVER);
        String truststore = System.getenv("PERSONALCLOUD_TLS_TRUSTSTORE");
        String password = System.getenv("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD");
        if (truststore != null && !truststore.isBlank()) {
            if (password == null || password.isBlank()) throw new IllegalArgumentException("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD is required with the configured truststore.");
            java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
            try (var input = java.nio.file.Files.newInputStream(java.nio.file.Path.of(truststore))) {
                store.load(input, password.toCharArray());
            }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            managers.init(store);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, managers.getTrustManagers(), null);
            builder.sslContext(ssl);
        }
        client = builder.build();
    }

    public Map<String, Object> join(String baseUrl, String accountName, char[] password,
                                    AppConfig config, DeviceIdentity identity,
                                    NetworkMembershipService membership) throws Exception {
        return join(baseUrl, accountName, password, config, identity, membership, false);
    }

    /**
     * Joins a network. Broad filesystem access is only enabled when the owner
     * explicitly consents; the default is no access.
     */
    public Map<String, Object> join(String baseUrl, String accountName, char[] password,
                                    AppConfig config, DeviceIdentity identity,
                                    NetworkMembershipService membership,
                                    boolean filesystemConsent) throws Exception {
        String base = RemotePeerClient.normalizeBaseUrl(baseUrl);
        Map<String, Object> challenge = getJson(base + "/network/challenge");
        String saltText = text(challenge, "salt");
        byte[] salt = Base64.getDecoder().decode(saltText);
        if (salt.length != 16) throw new SecurityException("The network returned an invalid credential salt.");
        String networkId = text(challenge, "networkId");
        String account = accountName == null || accountName.isBlank() ? text(challenge, "accountName") : accountName;
        String challengeId = text(challenge, "challengeId");
        String nonce = text(challenge, "nonce");
        String endpoint = membership.localEndpointForProtocol();
        String publicKey = identity.publicKeyBase64();
        byte[] verifier = NetworkMembershipService.derivePasswordForEnrollment(password, salt);
        String proof = NetworkMembershipService.enrollmentProof(verifier, networkId, account, challengeId,
                nonce, config.nodeId(), config.nodeName(), publicKey, endpoint);
        byte[] signedPayload = NetworkMembershipService.enrollmentSignaturePayload(networkId, config.nodeId(),
                config.nodeName(), publicKey, endpoint, challengeId, proof);
        String signature = Base64.getEncoder().encodeToString(identity.sign(signedPayload));
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("networkId", networkId);
        request.put("accountName", account);
        request.put("challengeId", challengeId);
        request.put("nodeId", config.nodeId());
        request.put("nodeName", config.nodeName());
        request.put("publicKey", publicKey);
        request.put("endpoint", endpoint);
        request.put("proof", proof);
        request.put("signature", signature);
        Map<String, Object> submitted = postJson(base + "/network/enroll", request);
        String requestId = text(submitted, "requestId");

        long timeoutSeconds = Long.parseLong(System.getenv().getOrDefault("PERSONALCLOUD_ENROLLMENT_TIMEOUT_SECONDS", "900"));
        long deadline = System.nanoTime() + Duration.ofSeconds(Math.max(10, Math.min(timeoutSeconds, 1800))).toNanos();
        while (System.nanoTime() < deadline) {
            Thread.sleep(2000);
            Map<String, Object> result = getJson(base + "/network/enroll/status/" + requestId);
            String status = text(result, "status");
            if ("REJECTED".equals(status)) throw new SecurityException("Network enrollment was rejected: " + result.getOrDefault("reason", "No reason provided."));
            if ("APPROVED".equals(status)) {
                Map<String, Object> accepted = new LinkedHashMap<>(result);
                accepted.put("salt", saltText);
                return membership.acceptApproval(accepted, password, filesystemConsent);
            }
            if (!"PENDING".equals(status)) throw new IllegalStateException("The network returned an unknown enrollment status: " + status);
        }
        throw new java.net.SocketTimeoutException("Enrollment is still pending. The request remains available for approval; run 'network status' and 'network join-status' later.");
    }

    private Map<String, Object> getJson(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(12))
                .header("Accept", "application/json").GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> data = Json.object(response.body());
        if (response.statusCode() != 200) throw new IllegalArgumentException(message(data, "Network request failed with HTTP " + response.statusCode()));
        return data;
    }

    private Map<String, Object> postJson(String url, Map<String, Object> body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json; charset=UTF-8")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.stringify(body), StandardCharsets.UTF_8)).build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> data = Json.object(response.body());
        if (response.statusCode() != 200) throw new IllegalArgumentException(message(data, "Network enrollment failed with HTTP " + response.statusCode()));
        return data;
    }

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) throw new IllegalArgumentException("The network response omitted '" + key + "'.");
        return text;
    }
    private static String message(Map<String, Object> data, String fallback) {
        Object error = data.get("error");
        return error == null ? fallback : String.valueOf(error);
    }
}
