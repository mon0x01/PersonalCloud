package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.control.LocalControlClient;
import dev.personalcloud.control.LocalControlServer;
import dev.personalcloud.policy.FilesystemPolicyService;
import dev.personalcloud.policy.PolicyMode;
import dev.personalcloud.policy.ProtectionApprovalService;
import dev.personalcloud.protocol.PeerProtocolServer;
import dev.personalcloud.storage.EligibleStorageService;
import dev.personalcloud.storage.ManagedStorageService;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.storage.ReferenceVersionService;
import dev.personalcloud.storage.ReferenceFileSystemModel;
import dev.personalcloud.storage.WritableVirtualFilesystem;

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
        LocalControlServer rootControl = null;
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

            // The native-adapter plane must use the same owner-side authorization:
            // local control commands drive signed remote operations, never local disk.
            Path rootEligible = Files.createDirectory(workspace.resolve("root-eligible"));
            DeviceCatalogueService rootCatalogue = new DeviceCatalogueService(rootConfig, rootMembership);
            ReferenceGrantService rootGrantService = new ReferenceGrantService(rootState, rootReferences, rootMembership);
            ReferenceVersionService rootVersionService = new ReferenceVersionService(rootData, rootReferences);
            ManagedStorageService rootManaged = new ManagedStorageService(rootState, rootConfig);
            FilesystemPolicyService rootPolicy = new FilesystemPolicyService(rootState);
            ProtectionApprovalService rootApprovals = new ProtectionApprovalService();
            EligibleStorageService rootFilesystem = new EligibleStorageService(rootConfig, rootState,
                    rootPolicy, rootApprovals, List.of(rootEligible));
            rootControl = new LocalControlServer(rootData, rootConfig.nodeId(), rootConfig.nodeName(),
                    rootReferences, rootConfig, rootPeers, rootLegacyGrants, rootMembership, rootCatalogue,
                    rootGrantService, rootVersionService, rootManaged, rootPolicy, rootApprovals, rootFilesystem);
            rootControl.start();
            LocalControlClient control = new LocalControlClient(rootControl.socketPath());
            WritableVirtualFilesystem nativeFilesystem =
                    new WritableVirtualFilesystem(new ReferenceFileSystemModel(control), control);

            check(nativeFilesystem.list("/").equals(List.of("Devices")),
                    "native adapter must expose the Devices root");
            check(nativeFilesystem.list("/Devices").contains("Filesystem Destination"),
                    "native adapter must expose the remote device");
            check(nativeFilesystem.list("/Devices/Filesystem Destination").contains("Filesystem"),
                    "native adapter must expose the writable eligible-storage subtree");
            List<String> nativeRoots = nativeFilesystem.list("/Devices/Filesystem Destination/Filesystem");
            check(nativeRoots.size() == 1, "native adapter must list exactly one consented eligible root");
            String nativeRoot = "/Devices/Filesystem Destination/Filesystem/" + nativeRoots.get(0);
            check(nativeFilesystem.attributes(nativeRoot).directory(), "eligible root must be a directory");
            check(nativeFilesystem.list(nativeRoot).contains("Documents"),
                    "native adapter must browse the owner's actual eligible directory");
            check(nativeFilesystem.exists(nativeRoot + "/Documents/report.txt"),
                    "native adapter must report an existing owner file");
            check(!nativeFilesystem.exists(nativeRoot + "/Documents/missing.txt"),
                    "native adapter must report a missing owner file honestly");
            expectFailure(() -> nativeFilesystem.attributes(nativeRoot + "/Documents/missing.txt"),
                    "native stat must report a missing owner file as not found");
            expectFailure(() -> nativeFilesystem.list(nativeRoot + "/missing-directory"),
                    "native browse must report a missing owner directory as not found");

            nativeFilesystem.createDirectory(nativeRoot + "/Native");
            check(Files.isDirectory(eligible.resolve("Native")),
                    "native mkdir must create the directory on the owner's filesystem");
            Path nativeStaging = nativeFilesystem.createStaging();
            Files.writeString(nativeStaging, "native write payload", StandardCharsets.UTF_8);
            nativeFilesystem.upload(nativeRoot + "/Native/native.txt", nativeStaging, false);
            nativeFilesystem.deleteStaging(nativeStaging);
            check(Files.readString(eligible.resolve("Native/native.txt"), StandardCharsets.UTF_8)
                            .equals("native write payload"),
                    "native write-back must publish exact bytes to the owner's original path");
            check(new String(nativeFilesystem.read(nativeRoot + "/Native/native.txt", 7, 5),
                    StandardCharsets.UTF_8).equals("write"),
                    "native adapter must perform bounded remote range reads");
            nativeFilesystem.move(nativeRoot + "/Native/native.txt", nativeRoot + "/Native/renamed.txt");
            check(Files.exists(eligible.resolve("Native/renamed.txt"))
                            && !Files.exists(eligible.resolve("Native/native.txt")),
                    "native rename must move the owner's original file");
            nativeFilesystem.delete(nativeRoot + "/Native/renamed.txt", false);
            check(!Files.exists(eligible.resolve("Native/renamed.txt")),
                    "native delete must remove the owner's original file");
            nativeFilesystem.delete(nativeRoot + "/Native", false);
            check(!Files.exists(eligible.resolve("Native")),
                    "native rmdir must remove the owner's empty directory");

            nativeFilesystem.createDirectory(nativeRoot + "/Native");
            // Conflicting no-overwrite commits must never replace or partially corrupt a file.
            Path conflictStaging = nativeFilesystem.createStaging();
            Files.writeString(conflictStaging, "first writer", StandardCharsets.UTF_8);
            nativeFilesystem.upload(nativeRoot + "/Native/conflict.txt", conflictStaging, false);
            Files.writeString(conflictStaging, "second writer", StandardCharsets.UTF_8);
            expectFailure(() -> nativeFilesystem.upload(nativeRoot + "/Native/conflict.txt", conflictStaging, false),
                    "native no-overwrite commit must reject a conflicting existing file");
            check(Files.readString(eligible.resolve("Native/conflict.txt"), StandardCharsets.UTF_8)
                            .equals("first writer"),
                    "a rejected conflicting write must leave the original bytes intact");

            // Two concurrent no-overwrite commits: exactly one wins and the result is never mixed.
            Path concurrentA = nativeFilesystem.createStaging();
            Path concurrentB = nativeFilesystem.createStaging();
            Files.writeString(concurrentA, "concurrent A payload", StandardCharsets.UTF_8);
            Files.writeString(concurrentB, "concurrent B payload", StandardCharsets.UTF_8);
            java.util.concurrent.atomic.AtomicInteger successfulCommits = new java.util.concurrent.atomic.AtomicInteger();
            Thread writerA = new Thread(() -> {
                try { nativeFilesystem.upload(nativeRoot + "/Native/concurrent.txt", concurrentA, false);
                    successfulCommits.incrementAndGet(); } catch (Exception ignored) { }
            });
            Thread writerB = new Thread(() -> {
                try { nativeFilesystem.upload(nativeRoot + "/Native/concurrent.txt", concurrentB, false);
                    successfulCommits.incrementAndGet(); } catch (Exception ignored) { }
            });
            writerA.start(); writerB.start(); writerA.join(10_000); writerB.join(10_000);
            check(successfulCommits.get() == 1, "exactly one concurrent no-overwrite commit must succeed");
            String concurrent = Files.readString(eligible.resolve("Native/concurrent.txt"), StandardCharsets.UTF_8);
            check(concurrent.equals("concurrent A payload") || concurrent.equals("concurrent B payload"),
                    "concurrent writes must never publish mixed or partial content");
            nativeFilesystem.deleteStaging(conflictStaging);
            nativeFilesystem.deleteStaging(concurrentA);
            nativeFilesystem.deleteStaging(concurrentB);
            nativeFilesystem.delete(nativeRoot + "/Native/conflict.txt", false);
            nativeFilesystem.delete(nativeRoot + "/Native/concurrent.txt", false);

            // Traversal and symlink escape attempts must fail closed.
            expectFailure(() -> nativeFilesystem.createDirectory(nativeRoot + "/../Escape"),
                    "native paths must reject parent-directory traversal");
            Path outside = Files.createDirectory(workspace.resolve("outside-eligible"));
            Files.writeString(outside.resolve("secret.txt"), "outside secret", StandardCharsets.UTF_8);
            Files.createSymbolicLink(eligible.resolve("outside-link"), outside);
            expectFailure(() -> nativeFilesystem.list(nativeRoot + "/outside-link"),
                    "native browsing must not follow symlinks outside eligible storage");
            Path symlinkStaging = nativeFilesystem.createStaging();
            Files.writeString(symlinkStaging, "escape", StandardCharsets.UTF_8);
            expectFailure(() -> nativeFilesystem.upload(nativeRoot + "/outside-link/secret.txt",
                            symlinkStaging, true),
                    "native writes must not follow symlinks outside eligible storage");
            check(Files.readString(outside.resolve("secret.txt"), StandardCharsets.UTF_8)
                            .equals("outside secret"),
                    "a rejected symlink escape must leave the outside file intact");
            nativeFilesystem.deleteStaging(symlinkStaging);
            Files.delete(eligible.resolve("outside-link"));
            nativeFilesystem.delete(nativeRoot + "/Native", false);

            destinationPolicy.set(rootId, "Documents/report.txt", PolicyMode.PROTECTED);
            Path protectedStaging = nativeFilesystem.createStaging();
            Files.writeString(protectedStaging, "blocked overwrite", StandardCharsets.UTF_8);
            expectFailure(() -> nativeFilesystem.upload(nativeRoot + "/Documents/report.txt",
                            protectedStaging, true),
                    "native writes must not bypass PROTECTED owner approval");
            nativeFilesystem.deleteStaging(protectedStaging);
            check(Files.readString(documents.resolve("report.txt"), StandardCharsets.UTF_8)
                            .equals("original remote file"),
                    "a blocked protected overwrite must leave the original bytes intact");
            destinationPolicy.remove(rootId, "Documents/report.txt");

            destinationPolicy.set(rootId, "Private", PolicyMode.PRIVATE);
            expectFailure(() -> nativeFilesystem.list(nativeRoot + "/Private"),
                    "native browsing must not expose PRIVATE directories");
            destinationPolicy.remove(rootId, "Private");

            destinationFilesystem.revokeConsent();
            expectFailure(() -> nativeFilesystem.list(nativeRoot),
                    "native operations must fail immediately after consent revocation");
            Path revokedStaging = nativeFilesystem.createStaging();
            Files.writeString(revokedStaging, "revoked write", StandardCharsets.UTF_8);
            expectFailure(() -> nativeFilesystem.upload(nativeRoot + "/Documents/revoked.txt", revokedStaging, false),
                    "native writes must fail after consent revocation");
            check(!Files.exists(documents.resolve("revoked.txt")),
                    "a revoked native write must not create the owner file");
            nativeFilesystem.deleteStaging(revokedStaging);
            destinationFilesystem.grantConsent();
            check(nativeFilesystem.list(nativeRoot).contains("Documents"),
                    "native operations must resume only after explicit consent is restored");

            destinationFilesystem.revokeConsent();
            boolean consentDenied = false;
            try { client.listFilesystemRoots(destinationUrl, rootMembership); }
            catch (java.io.IOException expected) { consentDenied = true; }
            check(consentDenied, "revoking consent must disable remote filesystem access immediately");
        } finally {
            if (rootControl != null) rootControl.close();
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
        System.out.println("PASS: authenticated direct filesystem roots, browse/stat/download/write, private/protected enforcement, owner approvals, consent revocation, and native-adapter concurrency, no-overwrite, traversal and symlink protections.");
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
