package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.StateStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class NetworkMembershipServiceTest {
    public static void main(String[] args) throws Exception {
        Path temporary = Files.createTempDirectory("personalcloud-network-membership-test-");
        Path rootData = temporary.resolve("root-data");
        Path rootStorage = temporary.resolve("root-storage");
        Path joiningData = temporary.resolve("joining-data");
        Path joiningStorage = temporary.resolve("joining-storage");
        Files.createDirectories(rootData);
        Files.createDirectories(rootStorage);
        Files.createDirectories(joiningData);
        Files.createDirectories(joiningStorage);

        AppConfig rootConfig = config("root-node-0001", "Root Device", rootData, rootStorage, 18781);
        AppConfig joiningConfig = config("joining-node-01", "Joining Device", joiningData, joiningStorage, 18782);
        StateStore rootStore = new StateStore(rootData);
        NetworkMembershipService root = new NetworkMembershipService(rootStore, rootConfig);
        NetworkMembershipService joining = new NetworkMembershipService(new StateStore(joiningData), joiningConfig);
        char[] password = "Correct-Horse-2026".toCharArray();

        Map<String, Object> initial = root.bootstrap("Mon Personal Network", "mon", password);
        check(Boolean.TRUE.equals(initial.get("joined")), "bootstrap must create the root membership");
        check(root.members().size() == 1, "bootstrap must register the root device");
        String networkId = String.valueOf(initial.get("networkId"));

        Map<String, Object> challenge = root.createChallenge();
        byte[] salt = Base64.getDecoder().decode(String.valueOf(challenge.get("salt")));
        byte[] verifier = NetworkMembershipService.derivePasswordForEnrollment(password, salt);
        String nodeId = joiningConfig.nodeId();
        String nodeName = joiningConfig.nodeName();
        String publicKey = joining.identity().publicKeyBase64();
        String endpoint = "http://127.0.0.1:18782";
        String challengeId = String.valueOf(challenge.get("challengeId"));
        String proof = NetworkMembershipService.enrollmentProof(verifier, networkId, "mon", challengeId,
                String.valueOf(challenge.get("nonce")), nodeId, nodeName, publicKey, endpoint);
        byte[] requestSignaturePayload = NetworkMembershipService.enrollmentSignaturePayload(networkId, nodeId,
                nodeName, publicKey, endpoint, challengeId, proof);
        String signature = Base64.getEncoder().encodeToString(joining.identity().sign(requestSignaturePayload));
        Map<String, Object> enrollment = new LinkedHashMap<>();
        enrollment.put("networkId", networkId);
        enrollment.put("accountName", "mon");
        enrollment.put("challengeId", challengeId);
        enrollment.put("nodeId", nodeId);
        enrollment.put("nodeName", nodeName);
        enrollment.put("publicKey", publicKey);
        enrollment.put("endpoint", endpoint);
        enrollment.put("proof", proof);
        enrollment.put("signature", signature);
        Map<String, Object> submitted = root.submitEnrollment(enrollment);
        check("PENDING".equals(submitted.get("status")), "valid credentials must create a pending request, not auto-enroll");
        String requestId = String.valueOf(submitted.get("requestId"));
        check(root.pendingRequests().size() == 1, "pending request must be visible for member approval");

        Map<String, Object> approved = root.approve(requestId);
        check("APPROVED".equals(approved.get("status")), "an existing member must be able to approve enrollment");
        check(root.members().size() == 2, "approver must register the new member");
        check(approved.get("members") instanceof List<?>, "approval bundle must include the known member certificates");

        Map<String, Object> accepted = joining.acceptApproval(approved, password);
        check(Boolean.TRUE.equals(accepted.get("joined")), "joining device must persist its approved membership");
        check(networkId.equals(accepted.get("networkId")), "joining device must join the same private network");
        check(joining.members().size() == 2, "joining device must import the member catalogue and certificate chain");
        check(MembershipCertificate.verify(String.valueOf(approved.get("certificate"))).nodeId().equals(nodeId),
                "issued membership certificate must identify the applicant");

        Map<String, String> headers = joining.createAuthHeaders("GET", "/network/members", new byte[0]);
        Map<String, List<String>> multiHeaders = new LinkedHashMap<>();
        headers.forEach((key, value) -> multiHeaders.put(key, List.of(value)));
        check(root.authenticate("GET", "/network/members", multiHeaders, new byte[0]),
                "an active member must authenticate with its device-specific signature");
        check(!root.authenticate("GET", "/network/members", multiHeaders, new byte[0]),
                "replaying a signed request nonce must be rejected");

        Map<String, String> overflowHeaders = joining.createAuthHeaders("GET", "/network/members", new byte[0]);
        String extremeTimestamp = Long.toString(Long.MIN_VALUE);
        String emptyBodyHash = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[0]));
        String overflowCanonical = "GET\n/network/members\n" + extremeTimestamp + "\n"
                + overflowHeaders.get("X-PC-Nonce") + "\n" + emptyBodyHash;
        overflowHeaders.put("X-PC-Timestamp", extremeTimestamp);
        overflowHeaders.put("X-PC-Signature", Base64.getEncoder().encodeToString(
                joining.identity().sign(overflowCanonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        Map<String, List<String>> overflowMultiHeaders = new LinkedHashMap<>();
        overflowHeaders.forEach((key, value) -> overflowMultiHeaders.put(key, List.of(value)));
        check(!root.authenticate("GET", "/network/members", overflowMultiHeaders, new byte[0]),
                "a correctly signed request with an overflowed extreme timestamp must be rejected");

        String tampered = String.valueOf(approved.get("certificate")).replace("Joining Device", "Attacker Device");
        boolean tamperRejected = false;
        try { MembershipCertificate.verify(tampered); }
        catch (SecurityException expected) { tamperRejected = true; }
        check(tamperRejected, "tampered member certificate must fail signature verification");

        // Online is a lease derived from a recent direct heartbeat, not a permanent
        // persisted boolean that survives a crashed or disconnected peer forever.
        root.recordHeartbeat(nodeId, endpoint, nodeName);
        Map<String, String> staleMember = rootStore.getRecord("member", nodeId);
        staleMember.put("online", "true");
        staleMember.put("lastSeenEpoch", Long.toString(System.currentTimeMillis() / 1000L - 180L));
        rootStore.putRecord("member", nodeId, staleMember);
        check(!memberOnline(root.members(), nodeId),
                "a stale heartbeat must make an otherwise active member appear offline");
        check(!memberOnline(root.membersForWire(), nodeId),
                "stale online state must not be propagated to other network members");

        root.revokeMember(nodeId);
        Map<String, String> afterRevoke = joining.createAuthHeaders("GET", "/network/members", new byte[0]);
        Map<String, List<String>> revokeHeaders = new LinkedHashMap<>();
        afterRevoke.forEach((key, value) -> revokeHeaders.put(key, List.of(value)));
        check(!root.authenticate("GET", "/network/members", revokeHeaders, new byte[0]),
                "a locally revoked member must no longer authenticate");

        NetworkMembershipService restored = new NetworkMembershipService(new StateStore(joiningData), joiningConfig);
        check(Boolean.TRUE.equals(restored.status().get("joined")), "network membership must survive node restart");
        check(restored.identity().publicKeyBase64().equals(publicKey), "per-device signing identity must survive node restart");

        // A node may restart on a different LAN address. Its signed membership
        // certificate is immutable, but the node's own endpoint metadata must
        // follow the listener actually configured for this process.
        Path syntheticTlsIdentity = rootData.resolve("synthetic-server-identity.p12");
        Files.writeString(syntheticTlsIdentity, "test-only-placeholder");
        AppConfig movedRootConfig = new AppConfig(rootConfig.nodeName(), rootConfig.nodeId(),
                "192.0.2.44", rootConfig.port(), rootData, rootStorage,
                syntheticTlsIdentity, "test-only-password", rootConfig.maxFileBytes());
        NetworkMembershipService movedRoot = new NetworkMembershipService(new StateStore(rootData), movedRootConfig);
        String rootCertificateBefore = new StateStore(rootData).getRecord("network", "active").get("localCertificate");
        String remoteEndpointBefore = new StateStore(rootData).getRecord("member", nodeId).get("endpoint");
        Map<String, Object> reconciliation = movedRoot.reconcileLocalEndpoint();
        String expectedMovedEndpoint = "https://192.0.2.44:" + rootConfig.port();
        check(expectedMovedEndpoint.equals(reconciliation.get("endpoint"))
                        && Boolean.TRUE.equals(reconciliation.get("updated")),
                "the local member endpoint must follow the configured listener after an address change");
        Map<String, String> movedLocalMember = new StateStore(rootData).getRecord("member", rootConfig.nodeId());
        check(expectedMovedEndpoint.equals(movedLocalMember.get("endpoint"))
                        && "true".equals(movedLocalMember.get("endpointVerified")),
                "the reconciled self endpoint must be marked as locally verified");
        check(rootCertificateBefore.equals(new StateStore(rootData).getRecord("network", "active").get("localCertificate"))
                        && rootCertificateBefore.equals(movedLocalMember.get("certificate")),
                "endpoint reconciliation must not rotate or rewrite the signed device certificate");
        check(remoteEndpointBefore.equals(new StateStore(rootData).getRecord("member", nodeId).get("endpoint")),
                "local endpoint reconciliation must never rewrite another member's endpoint");
        String endpointUpdatedAt = movedLocalMember.get("endpointUpdatedAt");
        Map<String, Object> repeatedReconciliation = movedRoot.reconcileLocalEndpoint();
        check(Boolean.FALSE.equals(repeatedReconciliation.get("updated"))
                        && endpointUpdatedAt.equals(new StateStore(rootData).getRecord("member", rootConfig.nodeId()).get("endpointUpdatedAt")),
                "reconciling an unchanged endpoint must be idempotent");

        java.util.Arrays.fill(password, '\0');
        System.out.println("PASS: network bootstrap, password-proved enrollment, explicit approval, Ed25519 certificate chains, member import, signed request authentication, replay rejection, tamper rejection, revocation, restart persistence and local endpoint reconciliation.");
    }

    private static boolean memberOnline(List<Map<String, Object>> members, String nodeId) {
        for (Map<String, Object> member : members) {
            if (nodeId.equals(member.get("nodeId"))) return Boolean.TRUE.equals(member.get("online"));
        }
        return false;
    }

    private static AppConfig config(String nodeId, String nodeName, Path data, Path storage, int port) {
        return new AppConfig(nodeName, nodeId, "127.0.0.1", port, data, storage, null, "", 1024L * 1024 * 1024);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
