package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.net.Json;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * M5 delegated-admission, approval-attribution, revocation-propagation and
 * consent integration coverage for the desktop membership service.
 */
public final class DelegatedAdmissionIntegrationTest {
    private static final char[] PASSWORD = "Correct-Horse-2026".toCharArray();

    public static void main(String[] args) throws Exception {
        Path temporary = Files.createTempDirectory("personalcloud-delegated-admission-");
        Node root = node(temporary, "root-node-0001", "Root Device", 18801);
        Node b = node(temporary, "member-b-00001", "Member B", 18802);
        Node c = node(temporary, "member-c-00001", "Member C", 18803);
        Node d = node(temporary, "member-d-00001", "Member D", 18804);
        Node e = node(temporary, "member-e-00001", "Member E", 18805);
        Node f = node(temporary, "member-f-00001", "Member F", 18806);
        Node g = node(temporary, "member-g-00001", "Member G", 18807);

        Map<String, Object> initial = root.service.bootstrap("Delegated Network", "mon", PASSWORD);
        String networkId = String.valueOf(initial.get("networkId"));
        check(root.service.members().size() == 1, "bootstrap must create the root trust anchor");

        // First additional device: the founder admits it.
        String bRequest = submit(root.service, b);
        Map<String, Object> bApproved = root.service.approve(bRequest);
        check("APPROVED".equals(bApproved.get("status")), "the founder must admit the first additional device");
        Map<String, Object> bAccepted = b.service.acceptApproval(bApproved, PASSWORD, false);
        check(Boolean.TRUE.equals(bAccepted.get("joined")), "the first additional device must join");
        check(Boolean.FALSE.equals(b.service.status().get("filesystemConsent")),
                "a new device must not receive broad filesystem access silently");
        check(Boolean.TRUE.equals(b.service.status().get("filesystemConsentRequired")),
                "a new device must be told that owner consent is still required");

        // Second additional device while the founder is still the only approver
        // with two active members.
        String cRequest = submit(root.service, c);
        Map<String, Object> cApproved = root.service.approve(cRequest);
        Map<String, Object> cAccepted = c.service.acceptApproval(cApproved, PASSWORD, true);
        check(Boolean.TRUE.equals(cAccepted.get("joined")), "the second additional device must join");
        check(Boolean.TRUE.equals(c.service.status().get("filesystemConsent")),
                "new-device consent must be persisted when explicitly granted");
        check(root.service.members().size() == 3, "root must catalogue all three active devices");

        // Post-threshold admission by a non-root active member, without majority.
        String dRequest = submit(b.service, d);
        Map<String, Object> dApproved = b.service.approve(dRequest);
        Map<String, Object> dApproval = Json.object(text(dApproved, "admissionApproval"));
        check(b.config.nodeId().equals(dApproval.get("approverNodeId")),
                "a post-threshold approval must be attributable to the approving active member");
        check(AdmissionApproval.certificateSha256(
                        MembershipCertificate.chain(text(dApproved, "certificate")).stream()
                                .filter(item -> item.nodeId().equals(b.config.nodeId()))
                                .findFirst().orElseThrow().certificateJson())
                        .equals(dApproval.get("approverCertificateSha256")),
                "the approval must bind the exact approver certificate");
        Map<String, Object> dAccepted = d.service.acceptApproval(dApproved, PASSWORD, false);
        check(Boolean.TRUE.equals(dAccepted.get("joined")), "a non-root active member must admit a device independently");
        check("true".equals(d.store.getRecord("network", "active").get("admissionApprovalVerified")),
                "the joining device must record that it verified the signed approval");

        // Another active member must be able to admit the next device on its own.
        String eRequest = submit(c.service, e);
        Map<String, Object> eApproved = c.service.approve(eRequest);
        Map<String, Object> eApproval = Json.object(text(eApproved, "admissionApproval"));
        check(c.config.nodeId().equals(eApproval.get("approverNodeId")),
                "any active member must be able to approve independently");
        Map<String, Object> eAccepted = e.service.acceptApproval(eApproved, PASSWORD, false);
        check(Boolean.TRUE.equals(eAccepted.get("joined")), "the second independent approver must succeed");

        // Inactive and revoked local members must not approve new devices.
        String fRequest = submit(c.service, f);
        Map<String, String> cMember = c.store.getRecord("member", c.config.nodeId());
        cMember.put("status", "INACTIVE");
        c.store.putRecord("member", c.config.nodeId(), cMember);
        check(expectsSecurity(() -> c.service.approve(fRequest)),
                "an inactive member must not approve admissions");
        cMember.put("status", "REVOKED");
        c.store.putRecord("member", c.config.nodeId(), cMember);
        check(expectsSecurity(() -> c.service.approve(fRequest)),
                "a revoked member must not approve admissions");
        cMember.put("status", "ACTIVE");
        c.store.putRecord("member", c.config.nodeId(), cMember);
        check(Boolean.TRUE.equals(c.service.status().get("canApproveAdmissions")),
                "a restored active member must regain admission authority");

        // Forged, altered, expired and replayed approval records must be rejected.
        MembershipCertificate.CertificateInfo eCertificate =
                MembershipCertificate.verify(text(eApproved, "certificate"));
        MembershipCertificate.CertificateInfo approverCertificate =
                MembershipCertificate.chain(text(eApproved, "certificate")).stream()
                        .filter(item -> item.nodeId().equals(c.config.nodeId()))
                        .findFirst().orElseThrow();
        String ePublicKey = e.service.identity().publicKeyBase64();

        Map<String, Object> body = new LinkedHashMap<>(eApproval);
        body.remove("signature");
        Map<String, Object> forged = AdmissionApproval.sign(body, d.service.identity().privateKey());
        check(expectsSecurity(() -> AdmissionApproval.verifyWithCertificate(forged,
                        approverCertificate.certificateJson(), networkId, eRequest,
                        eCertificate.nodeId(), ePublicKey)),
                "an approval signed by a different device must be rejected");

        Map<String, Object> altered = new LinkedHashMap<>(eApproval);
        altered.put("candidateNodeName", "Altered Device");
        check(expectsSecurity(() -> AdmissionApproval.verifyWithCertificate(altered,
                        approverCertificate.certificateJson(), networkId, eRequest,
                        eCertificate.nodeId(), ePublicKey)),
                "an altered approval must be rejected");

        Map<String, Object> expiredBody = new LinkedHashMap<>(eApproval);
        expiredBody.remove("signature");
        expiredBody.put("issuedAt", Instant.now().minusSeconds(3600).toString());
        expiredBody.put("expiresAt", Instant.now().minusSeconds(60).toString());
        Map<String, Object> expired = AdmissionApproval.sign(expiredBody, c.service.identity().privateKey());
        check(expectsSecurity(() -> AdmissionApproval.verifyWithCertificate(expired,
                        approverCertificate.certificateJson(), networkId, eRequest,
                        eCertificate.nodeId(), ePublicKey)),
                "an expired approval must be rejected");

        String gRequest = submit(root.service, g);
        Map<String, Object> gApproved = root.service.approve(gRequest);
        String gApprovalText = text(gApproved, "admissionApproval");
        String gDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(gApprovalText.getBytes(StandardCharsets.UTF_8)));
        g.store.putRecord("admissionApprovalUse", gDigest,
                Map.of("usedAt", Instant.now().toString(), "requestId", gRequest));
        check(expectsSecurity(() -> g.service.acceptApproval(gApproved, PASSWORD, false)),
                "a replayed admission approval must be rejected");

        // Invalid certificate chains must be rejected even when individually signed.
        check(expectsSecurity(() -> MembershipCertificate.verifyForNetwork(
                        text(eApproved, "certificate"), "different-network", root.config.nodeId())),
                "a certificate for a different network must be rejected");
        String foreignRoot = MembershipCertificate.createRoot(d.config.nodeId(), d.config.nodeName(),
                d.service.localEndpointForProtocol(), d.service.identity().publicKeyBase64(),
                d.service.identity().privateKey());
        check(expectsSecurity(() -> MembershipCertificate.verifyForNetwork(foreignRoot, networkId,
                        root.config.nodeId())),
                "a chain rooted outside the network trust anchor must be rejected");
        Map<String, Object> eCertificateMap = Json.object(text(eApproved, "certificate"));
        eCertificateMap.put("issuerCertificate", Base64.getEncoder().encodeToString(
                b.store.getRecord("network", "active").get("rootCertificate").getBytes(StandardCharsets.UTF_8)));
        check(expectsSecurity(() -> MembershipCertificate.verify(Json.stringify(eCertificateMap))),
                "a chain with a substituted parent must be rejected");

        // Signed revocation must propagate and must not be reversed by stale catalogues.
        List<Map<String, Object>> staleCatalogue = root.service.membersForWire();
        root.service.revokeMember(b.config.nodeId());
        Map<String, Object> revokedRow = row(root.service.membersForWire(), b.config.nodeId());
        check("REVOKED".equals(revokedRow.get("status")), "revocation must mark the member revoked");
        Map<String, Object> revocationRecord = Json.object(text(revokedRow, "revocation"));
        PublicKey rootKey = MembershipCertificate.verify(
                root.store.getRecord("network", "active").get("rootCertificate")).publicKey();
        MembershipRevocation.verify(revocationRecord, rootKey, networkId, b.config.nodeId());
        check(root.config.nodeId().equals(revocationRecord.get("revokerNodeId")),
                "revocation must be attributable to the issuing active member");

        // Tampered revocation records are rejected on a peer that has not yet
        // applied the revocation.
        Map<String, Object> tamperedRow = new LinkedHashMap<>(revokedRow);
        Map<String, Object> tamperedRecord = new LinkedHashMap<>(revocationRecord);
        tamperedRecord.put("signature", Base64.getEncoder().encodeToString(new byte[64]));
        tamperedRow.put("revocation", Json.stringify(tamperedRecord));
        check(expectsSecurity(() -> d.service.importMembers(List.of(tamperedRow))),
                "an invalid signed revocation must be rejected");

        d.service.importMembers(root.service.membersForWire());
        check("REVOKED".equals(row(d.service.members(), b.config.nodeId()).get("status")),
                "revocation must propagate to other active members");
        Map<String, List<String>> revokedHeaders = signedHeaders(b.service, "GET", "/network/members");
        check(!d.service.authenticate("GET", "/network/members", revokedHeaders, new byte[0]),
                "a revoked member must not authenticate on a peer that applied the revocation");

        d.service.importMembers(staleCatalogue);
        check("REVOKED".equals(row(d.service.members(), b.config.nodeId()).get("status")),
                "a stale catalogue must never reactivate a revoked member");

        // A revoked member may still act locally on stale state, but peers must
        // reject any new certificate chain that passes through the revoked identity.
        String fRequestForRevokedApprover = submit(b.service, f);
        Map<String, Object> fApprovedByRevoked = b.service.approve(fRequestForRevokedApprover);
        check("APPROVED".equals(fApprovedByRevoked.get("status")),
                "the stale revoked member may still issue an approval locally");
        check(expectsSecurity(() -> root.service.importMembers(b.service.membersForWire())),
                "a certificate chain issued through a revoked member must be rejected");

        // Existing devices upgrade their consent explicitly; it is never silent.
        check(Boolean.FALSE.equals(d.service.status().get("filesystemConsent")),
                "existing-device consent must remain opt-in after an upgrade");
        d.service.recordFilesystemConsent(true);
        check(Boolean.TRUE.equals(d.service.status().get("filesystemConsent"))
                        && Boolean.FALSE.equals(d.service.status().get("filesystemConsentRequired")),
                "an existing device must be able to grant consent explicitly");
        d.service.recordFilesystemConsent(false);
        check(Boolean.TRUE.equals(d.service.status().get("filesystemConsentRequired")),
                "consent revocation must restore the consent-required state");

        java.util.Arrays.fill(PASSWORD, '\0');
        System.out.println("PASS: first/second/post-threshold delegated admission, independent active-member approval, signed approval attribution, forged/altered/expired/replayed approval rejection, invalid chain rejection, signed revocation propagation, stale-catalogue conflict handling, inactive/revoked approver rejection and explicit new/existing device consent.");
    }

    private static Node node(Path temporary, String nodeId, String nodeName, int port) throws Exception {
        Path data = Files.createDirectories(temporary.resolve(nodeId + "-data"));
        Path storage = Files.createDirectories(temporary.resolve(nodeId + "-storage"));
        AppConfig config = new AppConfig(nodeName, nodeId, "127.0.0.1", port, data, storage, null, "",
                1024L * 1024 * 1024);
        StateStore store = new StateStore(data);
        return new Node(config, store, new NetworkMembershipService(store, config));
    }

    private static String submit(NetworkMembershipService host, Node joiner) throws Exception {
        Map<String, Object> challenge = host.createChallenge();
        String networkId = text(challenge, "networkId");
        String account = text(challenge, "accountName");
        String challengeId = text(challenge, "challengeId");
        String nonce = text(challenge, "nonce");
        String saltText = text(challenge, "salt");
        byte[] salt = Base64.getDecoder().decode(saltText);
        byte[] verifier = NetworkMembershipService.derivePasswordForEnrollment(PASSWORD, salt);
        String nodeId = joiner.config.nodeId();
        String nodeName = joiner.config.nodeName();
        String publicKey = joiner.service.identity().publicKeyBase64();
        String endpoint = joiner.service.localEndpointForProtocol();
        String proof = NetworkMembershipService.enrollmentProof(verifier, networkId, account, challengeId,
                nonce, nodeId, nodeName, publicKey, endpoint);
        byte[] signaturePayload = NetworkMembershipService.enrollmentSignaturePayload(networkId, nodeId,
                nodeName, publicKey, endpoint, challengeId, proof);
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("networkId", networkId);
        request.put("accountName", account);
        request.put("challengeId", challengeId);
        request.put("nodeId", nodeId);
        request.put("nodeName", nodeName);
        request.put("publicKey", publicKey);
        request.put("endpoint", endpoint);
        request.put("proof", proof);
        request.put("signature", Base64.getEncoder().encodeToString(joiner.service.identity().sign(signaturePayload)));
        Map<String, Object> submitted = host.submitEnrollment(request);
        return text(submitted, "requestId");
    }

    private static Map<String, List<String>> signedHeaders(NetworkMembershipService service,
                                                           String method, String path) throws Exception {
        Map<String, String> headers = service.createAuthHeaders(method, path, new byte[0]);
        Map<String, List<String>> result = new LinkedHashMap<>();
        headers.forEach((key, value) -> result.put(key, List.of(value)));
        return result;
    }

    private static Map<String, Object> row(List<Map<String, Object>> rows, String nodeId) {
        for (Map<String, Object> item : rows) if (nodeId.equals(item.get("nodeId"))) return item;
        throw new AssertionError("Expected catalogue row for " + nodeId);
    }

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new AssertionError("Expected text field '" + key + "'");
        }
        return text;
    }

    private static boolean expectsSecurity(ThrowingAction action) throws Exception {
        try {
            action.run();
            return false;
        } catch (SecurityException expected) {
            return true;
        }
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }

    private record Node(AppConfig config, StateStore store, NetworkMembershipService service) { }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
