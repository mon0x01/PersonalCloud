package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.policy.FilesystemPolicyService;
import dev.personalcloud.policy.PolicyMode;
import dev.personalcloud.policy.ProtectionApprovalService;
import dev.personalcloud.protocol.PeerProtocolServer;
import dev.personalcloud.storage.EligibleStorageService;
import dev.personalcloud.storage.ManagedStorageService;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.storage.ReferenceVersionService;
import dev.personalcloud.transfer.ResumableTransferManager;
import dev.personalcloud.transfer.TransferTicketService;

import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

/**
 * Three independent nodes: X owns the source, Y owns the destination and Z
 * coordinates. X streams chunks directly to Y. Z only exchanges signed
 * metadata and never receives, stages or relays file bytes.
 */
public final class CoordinatedTransferIntegrationTest {
    private static final int CHUNK = ResumableTransferManager.DEFAULT_CHUNK_BYTES;

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-coordinated-");
        List<Node> nodes = new ArrayList<>();
        try {
            char[] password = "Correct-Horse-2026".toCharArray();
            Node x = new Node(workspace, "coordinated-source-0001", "Coordinated Source", "source");
            Node y = new Node(workspace, "coordinated-destination-01", "Coordinated Destination", "destination");
            Node z = new Node(workspace, "coordinated-coordinator-01", "Coordinated Coordinator", "coordinator");
            nodes.add(x);
            nodes.add(y);
            nodes.add(z);

            x.membership.bootstrap("Coordinated Test Network", "tester", password);
            x.server.start();
            join(x, y, password);
            join(x, z, password);
            // Y enrolled before Z, so it must learn the coordinator certificate before
            // it can verify the coordinator's signed ticket.
            y.membership.importMembers(x.membership.membersForWire());
            y.server.start();
            z.server.start();

            NetworkPeerClient client = new NetworkPeerClient();
            String xRoot = rootId(x);
            String yRoot = rootId(y);
            TransferTicketService zTickets = new TransferTicketService(new StateStore(z.data), z.membership);
            CoordinatedTransferService coordinator = new CoordinatedTransferService(z.config, z.membership,
                    z.filesystem, zTickets, new NetworkPeerClient(), new StateStore(z.data));

            // 1. Direct COPY: X -> Y, source retained, Z never stores bytes.
            byte[] copyPayload = "coordinated-copy-marker-7f3a19".getBytes(StandardCharsets.UTF_8);
            Path xCopy = x.eligible.resolve("copy-source.txt");
            Files.write(xCopy, copyPayload);
            Map<String, Object> copyMetadata = sourceMetadata(client, x, xRoot, "copy-source.txt", z);
            Map<String, Object> copy = coordinator.coordinate(x.config.nodeId(), xRoot, "copy-source.txt",
                    y.config.nodeId(), yRoot, "copy-destination.txt", "COPY", false, "", "", 600);
            check("COPIED".equals(copy.get("state")), "COPY must complete with a COPIED result");
            check(Boolean.TRUE.equals(copy.get("sourceRetained")), "COPY must retain the source");
            check(Boolean.FALSE.equals(copy.get("sourceDeleted")), "COPY must not delete the source");
            check(Files.exists(xCopy), "COPY must leave the source file in place");
            check(Arrays.equals(Files.readAllBytes(y.eligible.resolve("copy-destination.txt")), copyPayload),
                    "destination must contain the exact source bytes");
            String copyTransferId = TransferTicketService.text(copy, "transferId");
            assertCoordinatorHoldsNoBytes(z, copyTransferId, copyPayload);
            // A destination re-authorization after a lost commit response must
            // accept the already-published identical bytes without a new approval.
            Map<String, Object> reauthorized = y.filesystem.authorizeCoordinatedWrite(z.config.nodeId(), yRoot,
                    "copy-destination.txt", false, "", TransferTicketService.text(copy, "ticketId"),
                    number(copyMetadata.get("size")), TransferTicketService.text(copyMetadata, "sha256"));
            check(Boolean.TRUE.equals(reauthorized.get("authorized")),
                    "destination re-authorization must be idempotent for identical committed bytes");
            Map<String, Object> copyStatus = coordinator.status(TransferTicketService.text(copy, "requestId"));
            check("COPIED".equals(copyStatus.get("state")), "coordinator status must report the terminal state");
            check(copyStatus.get("result") instanceof Map<?, ?>, "coordinator status must retain the metadata-only result");
            check(!copyStatus.containsKey("content") && !copyStatus.containsKey("bytes"),
                    "coordinator status must never expose file contents");

            // 2. Safe MOVE: destination commits and is verified before source deletion.
            byte[] movePayload = "coordinated-move-marker-c41d".getBytes(StandardCharsets.UTF_8);
            Path xMove = x.eligible.resolve("move-source.txt");
            Files.write(xMove, movePayload);
            Map<String, Object> moveMetadata = sourceMetadata(client, x, xRoot, "move-source.txt", z);
            Map<String, Object> move = coordinator.coordinate(x.config.nodeId(), xRoot, "move-source.txt",
                    y.config.nodeId(), yRoot, "move-destination.txt", "MOVE", false, "", "", 600);
            check("MOVED".equals(move.get("state")), "MOVE must complete with a MOVED result");
            check(Boolean.TRUE.equals(move.get("sourceDeleted")), "MOVE must delete the source after commit");
            check(Boolean.FALSE.equals(move.get("sourceRetained")), "MOVE must not claim to retain the source");
            check(!Files.exists(xMove), "MOVE must remove the source file");
            check(Arrays.equals(Files.readAllBytes(y.eligible.resolve("move-destination.txt")), movePayload),
                    "MOVE destination must contain the exact source bytes");
            assertCoordinatorHoldsNoBytes(z, TransferTicketService.text(move, "transferId"), movePayload);
            // Replaying the deletion leg after a crash must converge instead of
            // reporting a false failure or deleting anything else.
            Map<String, Object> repeatedDeletion = x.filesystem.deleteCoordinatedSource(z.config.nodeId(), xRoot,
                    "move-source.txt", TransferTicketService.text(move, "ticketId"),
                    number(moveMetadata.get("size")), TransferTicketService.text(moveMetadata, "sha256"),
                    TransferTicketService.text(moveMetadata, "version"));
            check(Boolean.TRUE.equals(repeatedDeletion.get("alreadyAbsent")),
                    "replaying a completed source deletion must be idempotent");
            Map<String, Object> moveRetry = coordinator.retry(TransferTicketService.text(move, "requestId"));
            check("MOVED".equals(moveRetry.get("state")),
                    "retrying a terminal coordinated MOVE must return the stored result");

            // 3. Protected source MOVE requires an independent owner approval at X.
            byte[] protectedPayload = "protected-move-payload".getBytes(StandardCharsets.UTF_8);
            Path xProtected = x.eligible.resolve("protected-move.txt");
            Files.write(xProtected, protectedPayload);
            x.policy.set(xRoot, "protected-move.txt", PolicyMode.PROTECTED);
            expectFailure(() -> coordinator.coordinate(x.config.nodeId(), xRoot, "protected-move.txt",
                            y.config.nodeId(), yRoot, "protected-move-destination.txt", "MOVE", false,
                            "", "", 600),
                    "a protected source MOVE must fail without an owner approval");
            check(Files.exists(xProtected), "a rejected protected MOVE must leave the source intact");
            check(!Files.exists(y.eligible.resolve("protected-move-destination.txt")),
                    "a rejected protected MOVE must not create the destination");
            Map<String, Object> sourceApproval = client.requestFilesystemApproval(x.url(), xRoot,
                    "protected-move.txt", "MOVE", 120, z.membership);
            String sourceApprovalId = TransferTicketService.text(sourceApproval, "approvalId");
            x.approvals.approve(sourceApprovalId);
            Map<String, Object> approvedMove = coordinator.coordinate(x.config.nodeId(), xRoot,
                    "protected-move.txt", y.config.nodeId(), yRoot, "protected-move-destination.txt",
                    "MOVE", false, sourceApprovalId, "", 600);
            check("MOVED".equals(approvedMove.get("state")),
                    "an approved protected source MOVE must complete");
            check(!Files.exists(xProtected) && Arrays.equals(
                            Files.readAllBytes(y.eligible.resolve("protected-move-destination.txt")),
                            protectedPayload),
                    "an approved protected MOVE must publish and then remove the source");

            // 4. Protected destination overwrite requires an independent approval at Y.
            Path yProtected = y.eligible.resolve("protected-destination.txt");
            Files.writeString(yProtected, "old destination payload");
            y.policy.set(yRoot, "protected-destination.txt", PolicyMode.PROTECTED);
            expectFailure(() -> coordinator.coordinate(x.config.nodeId(), xRoot, "copy-source.txt",
                            y.config.nodeId(), yRoot, "protected-destination.txt", "COPY", true,
                            "", "", 600),
                    "a protected destination overwrite must fail without an owner approval");
            check(Files.readString(yProtected).equals("old destination payload"),
                    "a rejected protected overwrite must leave the destination intact");
            Map<String, Object> destinationApproval = client.requestFilesystemApproval(y.url(), yRoot,
                    "protected-destination.txt", "WRITE", 120, z.membership);
            String destinationApprovalId = TransferTicketService.text(destinationApproval, "approvalId");
            y.approvals.approve(destinationApprovalId);
            Map<String, Object> approvedCopy = coordinator.coordinate(x.config.nodeId(), xRoot,
                    "copy-source.txt", y.config.nodeId(), yRoot, "protected-destination.txt",
                    "COPY", true, "", destinationApprovalId, 600);
            check("COPIED".equals(approvedCopy.get("state")),
                    "an approved protected destination overwrite must complete");
            check(Arrays.equals(Files.readAllBytes(yProtected), copyPayload),
                    "an approved protected overwrite must publish the exact bytes");

            // 5. Destination failure: an existing destination without overwrite is never replaced.
            Path yExisting = y.eligible.resolve("existing-destination.txt");
            Files.writeString(yExisting, "existing bytes");
            expectFailure(() -> coordinator.coordinate(x.config.nodeId(), xRoot, "copy-source.txt",
                            y.config.nodeId(), yRoot, "existing-destination.txt", "COPY", false,
                            "", "", 600),
                    "a no-overwrite transfer to an existing destination must fail");
            check(Files.readString(yExisting).equals("existing bytes"),
                    "a rejected no-overwrite transfer must leave the destination intact");
            check(Files.exists(xCopy), "a failed destination must leave the source intact");

            // 6. Invalid, expired, replayed and mis-bound tickets fail closed.
            Map<String, Object> metadata = sourceMetadata(client, x, xRoot, "copy-source.txt", z);
            long size = number(metadata.get("size"));
            String sha256 = TransferTicketService.text(metadata, "sha256");
            String version = TransferTicketService.text(metadata, "version");

            Map<String, Object> tampered = buildTicket(z, x, y, xRoot, "copy-source.txt", yRoot,
                    "tampered-destination.txt", "COPY", false, size, sha256, version, "", "", 600);
            String tamperedSignature = zTickets.sign(tampered);
            tampered.put("destinationPath", "attacker-destination.txt");
            expectFailure(() -> client.executeCoordinatedTransfer(x.url(), tampered, tamperedSignature, z.membership),
                    "a ticket whose signed body was modified must be rejected");

            Map<String, Object> expired = buildTicket(z, x, y, xRoot, "copy-source.txt", yRoot,
                    "expired-destination.txt", "COPY", false, size, sha256, version, "", "", 600);
            expired.put("issuedAt", Instant.now().minusSeconds(7200).toString());
            expired.put("expiresAt", Instant.now().minusSeconds(3600).toString());
            String expiredSignature = zTickets.sign(expired);
            expectFailure(() -> client.executeCoordinatedTransfer(x.url(), expired, expiredSignature, z.membership),
                    "an expired ticket must be rejected");

            Map<String, Object> wrongSource = TransferTicketService.build(UUID.randomUUID().toString(),
                    UUID.randomUUID().toString(), UUID.randomUUID().toString(), z.config.nodeId(),
                    y.config.nodeId(), x.config.nodeId(), xRoot, "copy-source.txt", yRoot,
                    "wrong-source-destination.txt", "COPY", false, size, sha256, version, "", "", 600);
            String wrongSourceSignature = zTickets.sign(wrongSource);
            expectFailure(() -> client.executeCoordinatedTransfer(x.url(), wrongSource, wrongSourceSignature,
                            z.membership),
                    "a ticket bound to a different source device must be rejected");

            Map<String, Object> wrongDestination = buildTicket(z, x, y, xRoot, "copy-source.txt", yRoot,
                    "wrong-destination.txt", "COPY", false, size, sha256, version, "", "", 600);
            String wrongDestinationSignature = zTickets.sign(wrongDestination);
            expectFailure(() -> client.createCoordinatedTransfer(x.url(),
                            TransferTicketService.text(wrongDestination, "transferId"), wrongDestination,
                            wrongDestinationSignature, x.membership),
                    "a destination route must reject a ticket bound to another destination");

            Map<String, Object> wrongHash = buildTicket(z, x, y, xRoot, "copy-source.txt", yRoot,
                    "wrong-hash-destination.txt", "COPY", false, size, "0".repeat(64), version, "", "", 600);
            String wrongHashSignature = zTickets.sign(wrongHash);
            expectFailure(() -> client.executeCoordinatedTransfer(x.url(), wrongHash, wrongHashSignature,
                            z.membership),
                    "a ticket with the wrong digest must be rejected");

            Map<String, Object> wrongPath = buildTicket(z, x, y, xRoot, "missing-source.txt", yRoot,
                    "wrong-path-destination.txt", "COPY", false, size, sha256, version, "", "", 600);
            String wrongPathSignature = zTickets.sign(wrongPath);
            expectFailure(() -> client.executeCoordinatedTransfer(x.url(), wrongPath, wrongPathSignature,
                            z.membership),
                    "a ticket with a missing source path must be rejected");

            // Replay: a ticket already claimed for one transfer cannot be rebound to another.
            byte[] replayPayload = "replay-payload".getBytes(StandardCharsets.UTF_8);
            Files.write(x.eligible.resolve("replay-source.txt"), replayPayload);
            Map<String, Object> replayMetadata = sourceMetadata(client, x, xRoot, "replay-source.txt", z);
            Map<String, Object> replayTicket = buildTicket(z, x, y, xRoot, "replay-source.txt", yRoot,
                    "replay-destination.txt", "COPY", false, number(replayMetadata.get("size")),
                    TransferTicketService.text(replayMetadata, "sha256"),
                    TransferTicketService.text(replayMetadata, "version"), "", "", 600);
            String replaySignature = zTickets.sign(replayTicket);
            Map<String, Object> replayResult = client.executeCoordinatedTransfer(x.url(), replayTicket,
                    replaySignature, z.membership);
            check("COPIED".equals(replayResult.get("state")), "the first execution of a ticket must succeed");
            Map<String, Object> idempotentRetry = client.executeCoordinatedTransfer(x.url(), replayTicket,
                    replaySignature, z.membership);
            check("COPIED".equals(idempotentRetry.get("state"))
                            && TransferTicketService.text(replayResult, "transferId")
                            .equals(TransferTicketService.text(idempotentRetry, "transferId")),
                    "retrying the same ticket and transfer identity must be idempotent");
            Map<String, Object> rebound = TransferTicketService.build(
                    TransferTicketService.text(replayTicket, "ticketId"), UUID.randomUUID().toString(),
                    UUID.randomUUID().toString(), z.config.nodeId(), x.config.nodeId(), y.config.nodeId(),
                    xRoot, "replay-source.txt", yRoot, "rebound-destination.txt", "COPY", false,
                    number(replayMetadata.get("size")), TransferTicketService.text(replayMetadata, "sha256"),
                    TransferTicketService.text(replayMetadata, "version"), "", "", 600);
            String reboundSignature = zTickets.sign(rebound);
            expectFailure(() -> client.executeCoordinatedTransfer(x.url(), rebound, reboundSignature,
                            z.membership),
                    "a replayed ticket bound to a different transfer identity must be rejected");
            check(!Files.exists(y.eligible.resolve("rebound-destination.txt")),
                    "a rejected replay must not create a destination file");

            // 7. Source mutation after ticket issuance is detected before transfer.
            Path mutated = x.eligible.resolve("mutating-source.txt");
            Files.writeString(mutated, "version one");
            CoordinatedTransferService.Prepared prepared = coordinator.prepare(x.config.nodeId(), xRoot,
                    "mutating-source.txt", y.config.nodeId(), yRoot, "mutated-destination.txt",
                    "COPY", false, "", "", 600);
            Files.writeString(mutated, "version two changed after the ticket was signed");
            expectFailure(() -> coordinator.retry(prepared.requestId()),
                    "a source changed after ticket issuance must be rejected");
            check(Files.exists(mutated), "a rejected source mutation must leave the source intact");
            check(!Files.exists(y.eligible.resolve("mutated-destination.txt")),
                    "a rejected source mutation must not create the destination");

            // 8. Interruption recovery: seed one verified chunk and resume the same ticket.
            byte[] large = new byte[CHUNK + 128 * 1024];
            new Random(20261108L).nextBytes(large);
            byte[] largeMarker = "partial-resume-marker-91be".getBytes(StandardCharsets.UTF_8);
            System.arraycopy(largeMarker, 0, large, 0, largeMarker.length);
            System.arraycopy(largeMarker, 0, large, large.length - largeMarker.length, largeMarker.length);
            Files.write(x.eligible.resolve("large-source.bin"), large);
            CoordinatedTransferService.Prepared resumable = coordinator.prepare(x.config.nodeId(), xRoot,
                    "large-source.bin", y.config.nodeId(), yRoot, "large-destination.bin",
                    "COPY", false, "", "", 600);
            client.createCoordinatedTransfer(y.url(), resumable.transferId(), resumable.ticket(),
                    resumable.signature(), x.membership);
            client.sendTransferChunk(y.url(), resumable.transferId(), 0,
                    Arrays.copyOfRange(large, 0, CHUNK), x.membership);
            Map<String, Object> partial = client.transferStatus(y.url(), resumable.transferId(), x.membership);
            check(((List<?>) partial.get("receivedChunks")).size() == 1
                            && number(partial.get("chunkCount")) == 2,
                    "a partially seeded session must retain exactly the verified chunk");
            check(!Files.exists(y.eligible.resolve("large-destination.bin")),
                    "a partial transfer must not publish the destination");
            Map<String, Object> resumed = coordinator.retry(resumable.requestId());
            check("COPIED".equals(resumed.get("state")), "a resumed coordinated transfer must complete");
            check(Arrays.equals(Files.readAllBytes(y.eligible.resolve("large-destination.bin")), large),
                    "a resumed transfer must publish the exact original bytes");
            Map<String, Object> committed = client.transferStatus(y.url(), resumable.transferId(), x.membership);
            check("COMMITTED".equals(committed.get("state")), "the resumed session must be committed");
            assertCoordinatorHoldsNoBytes(z, resumable.transferId(), largeMarker);

            // 9. Revocation: a revoked destination or coordinator is rejected on both sides.
            byte[] revokedPayload = "revoked-destination-payload".getBytes(StandardCharsets.UTF_8);
            Files.write(x.eligible.resolve("revoked-destination.txt"), revokedPayload);
            x.membership.revokeMember(y.config.nodeId());
            expectFailure(() -> coordinator.coordinate(x.config.nodeId(), xRoot, "revoked-destination.txt",
                            y.config.nodeId(), yRoot, "revoked-destination-out.txt", "COPY", false,
                            "", "", 600),
                    "a revoked destination must be rejected by the source");
            check(Files.exists(x.eligible.resolve("revoked-destination.txt")),
                    "a rejected transfer to a revoked destination must retain the source");
            check(!Files.exists(y.eligible.resolve("revoked-destination-out.txt")),
                    "a rejected transfer to a revoked destination must not create the destination");

            x.membership.revokeMember(z.config.nodeId());
            expectFailure(() -> client.coordinatedMetadata(x.url(), "source", xRoot, "copy-source.txt",
                            z.membership),
                    "a revoked coordinator must not read source metadata");
            expectFailure(() -> coordinator.coordinate(x.config.nodeId(), xRoot, "copy-source.txt",
                            y.config.nodeId(), yRoot, "revoked-coordinator-out.txt", "COPY", false,
                            "", "", 600),
                    "a revoked coordinator must not execute transfers");

            y.membership.revokeMember(z.config.nodeId());
            expectFailure(() -> client.coordinatedMetadata(y.url(), "destination", yRoot,
                            "revoked-coordinator-destination.txt", z.membership),
                    "a revoked coordinator must not read destination metadata");

            check(listCount(z.eligible) == 0, "the coordinator must never store transferred files");
        } finally {
            for (int index = nodes.size() - 1; index >= 0; index--) nodes.get(index).close();
            deleteTree(workspace);
        }
        System.out.println("PASS: three-peer coordinated COPY/MOVE with direct X-to-Y bytes, "
                + "coordinator metadata-only isolation, signed ticket binding and expiry, replay and "
                + "identity rejection, source mutation detection, protected approvals, destination "
                + "failure safety, interruption recovery and member revocation.");
    }

    private static void join(Node root, Node joining, char[] password) throws Exception {
        final Throwable[] failure = {null};
        Thread thread = new Thread(() -> {
            try {
                new NetworkEnrollmentClient().join(root.url(), "tester", password, joining.config,
                        joining.membership.identity(), joining.membership);
            } catch (Throwable problem) {
                failure[0] = problem;
            }
        }, "coordinated-enrollment-" + joining.config.nodeId());
        thread.start();
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (root.membership.pendingRequests().isEmpty() && System.nanoTime() < deadline) Thread.sleep(20);
        check(!root.membership.pendingRequests().isEmpty(),
                "an enrolling node must request membership before coordinated transfers");
        root.membership.approve(String.valueOf(root.membership.pendingRequests().getFirst().get("requestId")));
        thread.join(12_000);
        check(!thread.isAlive(), "membership enrollment must finish after approval");
        if (failure[0] != null) throw new AssertionError("membership enrollment failed", failure[0]);
    }

    private static Map<String, Object> sourceMetadata(NetworkPeerClient client, Node source, String rootId,
                                                       String path, Node coordinator) throws Exception {
        return client.coordinatedMetadata(source.url(), "source", rootId, path, coordinator.membership);
    }

    private static Map<String, Object> buildTicket(Node coordinator, Node source, Node destination,
                                                   String sourceRoot, String sourcePath, String destinationRoot,
                                                   String destinationPath, String operation, boolean overwrite,
                                                   long size, String sha256, String version,
                                                   String sourceApprovalId, String destinationApprovalId,
                                                   long ttlSeconds) {
        return TransferTicketService.build(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), coordinator.config.nodeId(), source.config.nodeId(),
                destination.config.nodeId(), sourceRoot, sourcePath, destinationRoot, destinationPath,
                operation, overwrite, size, sha256, version, sourceApprovalId, destinationApprovalId,
                ttlSeconds);
    }

    private static void assertCoordinatorHoldsNoBytes(Node coordinator, String transferId, byte[] marker)
            throws Exception {
        check(!Files.exists(coordinator.data.resolve("transfer-sessions").resolve(transferId)),
                "the coordinator must never create a transfer session for another pair");
        check(!containsBytes(coordinator.data, marker),
                "the coordinator data directory must never contain transferred file bytes");
        check(!containsBytes(coordinator.eligible, marker),
                "the coordinator eligible storage must never contain transferred file bytes");
    }

    private static boolean containsBytes(Path root, byte[] needle) throws Exception {
        if (!Files.exists(root)) return false;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                if (Files.size(path) > 8L * 1024 * 1024) continue;
                byte[] content = Files.readAllBytes(path);
                if (indexOf(content, needle) >= 0) return true;
            }
        }
        return false;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) return -1;
        outer:
        for (int start = 0; start <= haystack.length - needle.length; start++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[start + offset] != needle[offset]) continue outer;
            }
            return start;
        }
        return -1;
    }

    private static String rootId(Node node) {
        return String.valueOf(node.filesystem.rootsForOwner().get(0).get("rootId"));
    }

    private static long listCount(Path directory) throws Exception {
        if (!Files.isDirectory(directory)) return 0;
        try (var entries = Files.list(directory)) {
            return entries.count();
        }
    }

    private static long number(Object value) {
        if (!(value instanceof Number number)) throw new IllegalArgumentException("Expected a numeric value.");
        return number.longValue();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (java.io.IOException | SecurityException | IllegalArgumentException expected) {
            // Expected: unsafe or unauthorized operations fail closed.
        }
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                }
            });
        }
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static final class Node implements AutoCloseable {
        final AppConfig config;
        final Path data;
        final Path eligible;
        final StateStore state;
        final NetworkMembershipService membership;
        final FilesystemPolicyService policy;
        final ProtectionApprovalService approvals;
        final EligibleStorageService filesystem;
        final FileService files;
        final PeerProtocolServer server;

        Node(Path workspace, String nodeId, String nodeName, String label) throws Exception {
            this.data = Files.createDirectory(workspace.resolve(label + "-data"));
            Path storage = Files.createDirectory(workspace.resolve(label + "-storage"));
            this.eligible = Files.createDirectory(workspace.resolve(label + "-files"));
            int port = freePort();
            this.config = new AppConfig(nodeName, nodeId, "127.0.0.1", port, data, storage, null, "",
                    1024L * 1024 * 1024);
            this.state = new StateStore(data);
            this.files = new FileService(storage);
            PeerService peers = new PeerService(state, config);
            VersionService versions = new VersionService(data, files);
            GrantService grants = new GrantService(state, files, peers, versions, config.maxFileBytes());
            this.membership = new NetworkMembershipService(state, config);
            ReferenceStorageService references = new ReferenceStorageService(state, data, storage);
            this.policy = new FilesystemPolicyService(state);
            this.approvals = new ProtectionApprovalService();
            this.filesystem = new EligibleStorageService(config, state, policy, approvals, List.of(eligible));
            this.filesystem.grantConsent();
            this.server = new PeerProtocolServer(config, files, peers, grants, new AuditLog(data), membership,
                    references, new ReferenceGrantService(state, references, membership),
                    new ReferenceVersionService(data, references), new ManagedStorageService(state, config),
                    policy, approvals, filesystem);
        }

        String url() {
            return "http://127.0.0.1:" + config.port();
        }

        @Override
        public void close() {
            try {
                server.close();
            } catch (Exception ignored) {
            }
            try {
                files.close();
            } catch (Exception ignored) {
            }
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
