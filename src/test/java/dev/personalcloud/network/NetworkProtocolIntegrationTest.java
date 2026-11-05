package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.protocol.PeerProtocolServer;
import dev.personalcloud.net.Json;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public final class NetworkProtocolIntegrationTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-network-protocol-test-");
        PeerProtocolServer server = null;
        FileService files = null;
        char[] password = "Correct-Horse-2026".toCharArray();
        try {
            Path rootData = Files.createDirectory(workspace.resolve("root-data"));
            Path rootStorage = Files.createDirectory(workspace.resolve("root-storage"));
            Path candidateData = Files.createDirectory(workspace.resolve("candidate-data"));
            Path candidateStorage = Files.createDirectory(workspace.resolve("candidate-storage"));
            int rootPort = freePort();
            int candidatePort = freePort();
            AppConfig rootConfig = config("protocol-root-0001", "Protocol Root", rootData, rootStorage, rootPort);
            AppConfig candidateConfig = config("protocol-candidate-01", "Protocol Candidate", candidateData, candidateStorage, candidatePort);
            StateStore rootState = new StateStore(rootData);
            files = new FileService(rootStorage);
            PeerService peers = new PeerService(rootState, rootConfig);
            VersionService versions = new VersionService(rootData, files);
            GrantService grants = new GrantService(rootState, files, peers, versions, rootConfig.maxFileBytes());
            NetworkMembershipService rootMembership = new NetworkMembershipService(rootState, rootConfig);
            rootMembership.bootstrap("Protocol Test Network", "tester", password);
            server = new PeerProtocolServer(rootConfig, files, peers, grants, new AuditLog(rootData), rootMembership);
            server.start();

            StateStore candidateState = new StateStore(candidateData);
            NetworkMembershipService candidateMembership = new NetworkMembershipService(candidateState, candidateConfig);
            NetworkEnrollmentClient enrollmentClient = new NetworkEnrollmentClient();
            String rootUrl = "http://127.0.0.1:" + rootPort;
            final Throwable[] joinFailure = {null};
            Thread joinThread = new Thread(() -> {
                try {
                    enrollmentClient.join(rootUrl, "tester", password, candidateConfig,
                            candidateMembership.identity(), candidateMembership);
                } catch (Throwable failure) { joinFailure[0] = failure; }
            }, "network-enrollment-test");
            joinThread.start();

            long approvalDeadline = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
            while (rootMembership.pendingRequests().isEmpty() && System.nanoTime() < approvalDeadline) Thread.sleep(25);
            check(!rootMembership.pendingRequests().isEmpty(), "candidate must submit a network enrollment request over HTTP");
            Map<String, Object> pending = rootMembership.pendingRequests().getFirst();
            rootMembership.approve(String.valueOf(pending.get("requestId")));
            joinThread.join(8_000);
            check(!joinThread.isAlive(), "candidate enrollment should complete after approval");
            if (joinFailure[0] != null) throw new AssertionError("candidate enrollment failed", joinFailure[0]);
            check(Boolean.TRUE.equals(candidateMembership.status().get("joined")), "candidate must receive and persist its approval certificate");

            NetworkPeerClient peerClient = new NetworkPeerClient();
            Map<String, Object> remotePresence = peerClient.getJson(rootUrl, "/network/presence", candidateMembership);
            check("protocol-root-0001".equals(remotePresence.get("nodeId")), "signed member request must read remote peer presence");
            Map<String, Object> remoteMembers = peerClient.getJson(rootUrl, "/network/members", candidateMembership);
            Object members = remoteMembers.get("members");
            check(members instanceof List<?> list && list.size() == 2, "network catalogue endpoint must return the two approved devices");

            Map<String, Object> heartbeat = Map.of("nodeId", candidateConfig.nodeId(), "nodeName", candidateConfig.nodeName(),
                    "endpoint", "http://127.0.0.1:" + candidatePort, "sentAt", java.time.Instant.now().toString());
            Map<String, Object> heartbeatResponse = peerClient.postJson(rootUrl, "/network/heartbeat", heartbeat, candidateMembership);
            check(Boolean.TRUE.equals(heartbeatResponse.get("ok")), "signed member heartbeat must be accepted");
            check(rootMembership.members().stream().anyMatch(row -> candidateConfig.nodeId().equals(row.get("nodeId")) && Boolean.TRUE.equals(row.get("online"))),
                    "accepted heartbeat must update the member's online state");

            String stableTransferId = java.util.UUID.randomUUID().toString();
            String emptyHash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(new byte[0]));
            Map<String,Object> transferRequest = Map.of("transferId", stableTransferId, "path", "retries/empty.bin",
                    "size", 0, "sha256", emptyHash);
            Map<String,Object> firstSession = peerClient.postJson(rootUrl, "/network/transfers", transferRequest, candidateMembership);
            Map<String,Object> retriedSession = peerClient.postJson(rootUrl, "/network/transfers", transferRequest, candidateMembership);
            check(stableTransferId.equals(firstSession.get("transferId")) && stableTransferId.equals(retriedSession.get("transferId")),
                    "repeated signed create requests must reopen the same sender-generated session");
            Map<String,Object> sessionStatus = peerClient.getJson(rootUrl, "/network/transfers/" + stableTransferId, candidateMembership);
            check("READY_TO_COMMIT".equals(sessionStatus.get("state")), "idempotent zero-byte session remains commit-ready");
            try {
                peerClient.postJson(rootUrl, "/network/transfers", Map.of("transferId", stableTransferId,
                        "path", "retries/different.bin", "size", 0, "sha256", emptyHash), candidateMembership);
                throw new AssertionError("A stable transfer ID must not be rebound to different metadata.");
            } catch (java.io.IOException expected) { }
            peerClient.deleteJson(rootUrl, "/network/transfers/" + stableTransferId, candidateMembership);

            System.out.println("PASS: HTTP enrollment challenge, password proof, pending request, explicit approval, certificate delivery, signed member APIs, catalogue response, heartbeat and idempotent sender-generated transfer sessions.");
        } finally {
            Arrays.fill(password, '\0');
            if (server != null) server.close();
            if (files != null) files.close();
        }
    }

    private static AppConfig config(String nodeId, String nodeName, Path data, Path storage, int port) {
        return new AppConfig(nodeName, nodeId, "127.0.0.1", port, data, storage, null, "", 1024L * 1024 * 1024);
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) { return socket.getLocalPort(); }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
