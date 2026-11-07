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

import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Authenticated direct filesystem routes over two independently running nodes. */
public final class EligibleStorageIntegrationTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-filesystem-integration-");
        PeerProtocolServer rootServer = null;
        PeerProtocolServer destinationServer = null;
        FileService rootFiles = null;
        FileService destinationFiles = null;
        char[] password = "Correct-Horse-2026".toCharArray();
        try {
            Path rootData = Files.createDirectory(workspace.resolve("root-data"));
            Path rootStorage = Files.createDirectory(workspace.resolve("root-storage"));
            Path destinationData = Files.createDirectory(workspace.resolve("destination-data"));
            Path destinationStorage = Files.createDirectory(workspace.resolve("destination-storage"));
            Path eligible = Files.createDirectory(workspace.resolve("destination-files"));
            Path documents = Files.createDirectory(eligible.resolve("Documents"));
            Path protectedDirectory = Files.createDirectory(eligible.resolve("Protected"));
            Path privateDirectory = Files.createDirectory(eligible.resolve("Private"));
            byte[] original = "original remote file".getBytes(StandardCharsets.UTF_8);
            Files.write(documents.resolve("report.txt"), original);
            Files.write(protectedDirectory.resolve("plan.txt"), "protected plan".getBytes(StandardCharsets.UTF_8));
            Files.write(privateDirectory.resolve("keys.txt"), "private keys".getBytes(StandardCharsets.UTF_8));

            int rootPort = freePort();
            int destinationPort = freePort();
            AppConfig rootConfig = config("filesystem-root-node-0001", "Filesystem Root", rootData, rootStorage, rootPort);
            AppConfig destinationConfig = config("filesystem-destination-01", "Filesystem Destination", destinationData, destinationStorage, destinationPort);
            StateStore rootState = new StateStore(rootData);
            rootFiles = new FileService(rootStorage);
            PeerService rootPeers = new PeerService(rootState, rootConfig);
            VersionService rootVersions = new VersionService(rootData, rootFiles);
            GrantService rootLegacyGrants = new GrantService(rootState, rootFiles, rootPeers, rootVersions, rootConfig.maxFileBytes());
            NetworkMembershipService rootMembership = new NetworkMembershipService(rootState, rootConfig);
            rootMembership.bootstrap("Filesystem Test", "tester", password);
            ReferenceStorageService rootReferences = new ReferenceStorageService(rootState, rootData, rootStorage);
            rootServer = new PeerProtocolServer(rootConfig, rootFiles, rootPeers, rootLegacyGrants,
                    new AuditLog(rootData), rootMembership, rootReferences,
                    new ReferenceGrantService(rootState, rootReferences, rootMembership),
                    new ReferenceVersionService(rootData, rootReferences),
                    new ManagedStorageService(rootState, rootConfig));
            rootServer.start();

            StateStore destinationState = new StateStore(destinationData);
            NetworkMembershipService destinationMembership = new NetworkMembershipService(destinationState, destinationConfig);
            String rootUrl = "http://127.0.0.1:" + rootPort;
            final Throwable[] joinFailure = {null};
            Thread joinThread = new Thread(() -> {
                try { new NetworkEnrollmentClient().join(rootUrl, "tester", password, destinationConfig,
                        destinationMembership.identity(), destinationMembership); }
                catch (Throwable failure) { joinFailure[0] = failure; }
            }, "filesystem-enrollment-test");
            joinThread.start();
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
            while (rootMembership.pendingRequests().isEmpty() && System.nanoTime() < deadline) Thread.sleep(20);
            check(!rootMembership.pendingRequests().isEmpty(), "destination must request membership before filesystem access");
            rootMembership.approve(String.valueOf(rootMembership.pendingRequests().getFirst().get("requestId")));
            joinThread.join(8_000);
            check(!joinThread.isAlive(), "destination enrollment must finish after approval");
            if (joinFailure[0] != null) throw new AssertionError("destination enrollment failed", joinFailure[0]);

            destinationFiles = new FileService(destinationStorage);
            PeerService destinationPeers = new PeerService(destinationState, destinationConfig);
            VersionService destinationVersions = new VersionService(destinationData, destinationFiles);
            GrantService destinationLegacyGrants = new GrantService(destinationState, destinationFiles, destinationPeers,
                    destinationVersions, destinationConfig.maxFileBytes());
            ReferenceStorageService destinationReferences = new ReferenceStorageService(destinationState, destinationData, destinationStorage);
            FilesystemPolicyService destinationPolicy = new FilesystemPolicyService(destinationState);
            ProtectionApprovalService destinationApprovals = new ProtectionApprovalService();
            EligibleStorageService destinationFilesystem = new EligibleStorageService(destinationConfig, destinationState,
                    destinationPolicy, destinationApprovals, List.of(eligible));
            destinationFilesystem.grantConsent();
            destinationServer = new PeerProtocolServer(destinationConfig, destinationFiles, destinationPeers,
                    destinationLegacyGrants, new AuditLog(destinationData), destinationMembership, destinationReferences,
                    new ReferenceGrantService(destinationState, destinationReferences, destinationMembership),
                    new ReferenceVersionService(destinationData, destinationReferences),
                    new ManagedStorageService(destinationState, destinationConfig), destinationPolicy,
                    destinationApprovals, destinationFilesystem);
            destinationServer.start();
            String destinationUrl = "http://127.0.0.1:" + destinationPort;
            NetworkPeerClient client = new NetworkPeerClient();
            String rootId = String.valueOf(destinationFilesystem.rootsForOwner().get(0).get("rootId"));

            Map<String, Object> roots = client.listFilesystemRoots(destinationUrl, rootMembership);
            check(roots.get("roots") instanceof List<?> rootRows && rootRows.size() == 1,
                    "an active member must discover consented eligible roots");
            @SuppressWarnings("unchecked") Map<String, Object> rootRow = (Map<String, Object>) ((List<?>) roots.get("roots")).get(0);
            check(rootId.equals(rootRow.get("rootId")) && !rootRow.containsKey("path"),
                    "remote root metadata must not disclose the absolute host path");

            Map<String, Object> listing = client.browseFilesystem(destinationUrl, rootId, "", rootMembership);
            check(listing.get("entries") instanceof List<?> entries && entries.size() == 3,
                    "default access must list eligible directories");
            Map<String, Object> stat = client.statFilesystem(destinationUrl, rootId, "Documents/report.txt", rootMembership);
            check(((Number) stat.get("size")).longValue() == original.length, "remote stat must report the original file size");
            Path downloaded = workspace.resolve("downloaded.bin");
            NetworkPeerClient.RemoteDownloadResult result = client.downloadFilesystemFile(destinationUrl, rootId,
                    "Documents/report.txt", downloaded, rootMembership, destinationConfig.maxFileBytes());
            check(result.sizeBytes() == original.length && Arrays.equals(Files.readAllBytes(downloaded), original),
                    "remote download must preserve the original bytes");
            NetworkPeerClient.RemoteRangeResult range = client.readRemoteFilesystemRange(destinationUrl, rootId,
                    "Documents/report.txt", 2, 5, rootMembership);
            check(Arrays.equals(range.bytes(), Arrays.copyOfRange(original, 2, 7)),
                    "remote range read must return the exact requested bytes");
            check(range.totalSize() == original.length, "remote range read must report the total file size");
            NetworkPeerClient.RemoteRangeResult tail = client.readRemoteFilesystemRange(destinationUrl, rootId,
                    "Documents/report.txt", original.length - 3, 10, rootMembership);
            check(tail.bytes().length == 3 && Arrays.equals(tail.bytes(),
                            Arrays.copyOfRange(original, original.length - 3, original.length)),
                    "remote range read must clamp a range that extends past the end of the file");
            expectFailure(() -> client.readRemoteFilesystemRange(destinationUrl, rootId,
                            "Documents/report.txt", -1, 4, rootMembership),
                    "negative remote range offsets must be rejected");
            expectFailure(() -> client.readRemoteFilesystemRange(destinationUrl, rootId,
                            "Documents/report.txt", 0, 8 * 1024 * 1024 + 1, rootMembership),
                    "oversized remote range reads must be rejected");

            Path upload = workspace.resolve("upload.txt");
            byte[] uploadBytes = "direct write from another member".getBytes(StandardCharsets.UTF_8);
            Files.write(upload, uploadBytes);
            client.uploadFilesystemFile(destinationUrl, rootId, "Documents/upload.txt", upload, false, "",
                    rootMembership, destinationConfig.maxFileBytes());
            check(Arrays.equals(Files.readAllBytes(documents.resolve("upload.txt")), uploadBytes),
                    "remote write must publish exact bytes to the owner's original path");

            destinationPolicy.set(rootId, "Protected", PolicyMode.PROTECTED);
            NetworkPeerClient.RemoteRangeResult protectedRange = client.readRemoteFilesystemRange(destinationUrl,
                    rootId, "Protected/plan.txt", 0, 4, rootMembership);
            check(new String(protectedRange.bytes(), StandardCharsets.UTF_8).equals("prot"),
                    "protected files must remain readable through bounded range reads");
            boolean approvalRequired = false;
            try {
                client.uploadFilesystemFile(destinationUrl, rootId, "Protected/plan.txt", upload, true, "",
                        rootMembership, destinationConfig.maxFileBytes());
            } catch (java.io.IOException expected) {
                approvalRequired = true;
            }
            check(approvalRequired, "protected overwrite must fail without an owner approval");
            Map<String, Object> approval = client.requestFilesystemApproval(destinationUrl, rootId,
                    "Protected/plan.txt", "WRITE", 60, rootMembership);
            String approvalId = String.valueOf(approval.get("approvalId"));
            destinationApprovals.approve(approvalId);
            client.uploadFilesystemFile(destinationUrl, rootId, "Protected/plan.txt", upload, true, approvalId,
                    rootMembership, destinationConfig.maxFileBytes());
            check(Arrays.equals(Files.readAllBytes(protectedDirectory.resolve("plan.txt")), uploadBytes),
                    "an approved protected overwrite must publish the new bytes");

            Path moveSource = documents.resolve("move-source.txt");
            Path moveDestination = documents.resolve("move-destination.txt");
            Files.writeString(moveSource, "move source payload");
            Files.writeString(moveDestination, "old destination payload");
            destinationPolicy.set(rootId, "Documents/move-source.txt", PolicyMode.PROTECTED);
            destinationPolicy.set(rootId, "Documents/move-destination.txt", PolicyMode.PROTECTED);
            expectFailure(() -> client.moveFilesystemEntry(destinationUrl, rootId, "Documents/move-source.txt",
                            "Documents/move-destination.txt", true, "", "", rootMembership),
                    "a protected source and destination move must require both approvals");
            Map<String, Object> moveSourceApproval = client.requestFilesystemApproval(destinationUrl, rootId,
                    "Documents/move-source.txt", "MOVE", 60, rootMembership);
            String moveSourceApprovalId = String.valueOf(moveSourceApproval.get("approvalId"));
            Map<String, Object> moveDestinationApproval = client.requestFilesystemApproval(destinationUrl, rootId,
                    "Documents/move-destination.txt", "WRITE", 60, rootMembership);
            String moveDestinationApprovalId = String.valueOf(moveDestinationApproval.get("approvalId"));
            destinationApprovals.approve(moveSourceApprovalId);
            destinationApprovals.approve(moveDestinationApprovalId);
            client.moveFilesystemEntry(destinationUrl, rootId, "Documents/move-source.txt",
                    "Documents/move-destination.txt", true, moveSourceApprovalId, moveDestinationApprovalId,
                    rootMembership);
            check(!Files.exists(moveSource) && Files.readString(moveDestination).equals("move source payload"),
                    "a move with both approvals must replace the protected destination");

            destinationPolicy.set(rootId, "Private", PolicyMode.PRIVATE);
            Map<String, Object> hidden = client.browseFilesystem(destinationUrl, rootId, "", rootMembership);
            check(((List<?>) hidden.get("entries")).stream().noneMatch(row -> row instanceof Map<?, ?> map
                    && "Private".equals(map.get("name"))), "private directories must be hidden from remote catalogues");
            boolean privateDenied = false;
            try { client.statFilesystem(destinationUrl, rootId, "Private/keys.txt", rootMembership); }
            catch (java.io.IOException expected) { privateDenied = true; }
            check(privateDenied, "private files must be denied at the source");

            Map<String, Object> deleteApproval = client.requestFilesystemApproval(destinationUrl, rootId,
                    "Protected/plan.txt", "DELETE", 60, rootMembership);
            String deleteApprovalId = String.valueOf(deleteApproval.get("approvalId"));
            destinationApprovals.approve(deleteApprovalId);
            client.deleteFilesystemEntry(destinationUrl, rootId, "Protected/plan.txt", false, deleteApprovalId,
                    rootMembership);
            check(!Files.exists(protectedDirectory.resolve("plan.txt")),
                    "an approved remote delete must remove the original file");

            destinationFilesystem.revokeConsent();
            boolean consentDenied = false;
            try { client.listFilesystemRoots(destinationUrl, rootMembership); }
            catch (java.io.IOException expected) { consentDenied = true; }
            check(consentDenied, "revoking consent must disable remote filesystem access immediately");
        } finally {
            if (rootServer != null) rootServer.close();
            if (destinationServer != null) destinationServer.close();
            if (rootFiles != null) rootFiles.close();
            if (destinationFiles != null) destinationFiles.close();
            try (var paths = Files.walk(workspace)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: authenticated direct filesystem roots, browse/stat/download/write, private/protected enforcement, owner approvals and consent revocation.");
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

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (java.io.IOException | SecurityException | IllegalArgumentException expected) {
            // Expected: unsafe or unauthorized operations fail closed.
        }
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
