package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.protocol.PeerProtocolServer;
import dev.personalcloud.storage.ManagedStorageService;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.storage.ReferenceVersionService;

import java.net.ServerSocket;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Verifies direct whole-file placement between two independently running Java nodes. */
public final class ManagedStorageIntegrationTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-managed-storage-test-");
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
            Path source = workspace.resolve("source-report.bin");
            byte[] payload = new byte[2 * 1024 * 1024 + 137];
            new java.security.SecureRandom().nextBytes(payload);
            Files.write(source, payload);
            Path downloadDirectory = Files.createDirectory(workspace.resolve("downloads"));

            int rootPort = freePort();
            int destinationPort = freePort();
            AppConfig rootConfig = config("managed-root-node-0001", "Managed Root", rootData, rootStorage, rootPort);
            AppConfig destinationConfig = config("managed-destination-01", "Managed Destination", destinationData, destinationStorage, destinationPort);
            StateStore rootState = new StateStore(rootData);
            rootFiles = new FileService(rootStorage);
            PeerService rootPeers = new PeerService(rootState, rootConfig);
            VersionService rootVersions = new VersionService(rootData, rootFiles);
            GrantService rootLegacyGrants = new GrantService(rootState, rootFiles, rootPeers, rootVersions, rootConfig.maxFileBytes());
            NetworkMembershipService rootMembership = new NetworkMembershipService(rootState, rootConfig);
            rootMembership.bootstrap("Managed Storage Test", "tester", password);
            ReferenceStorageService rootReferences = new ReferenceStorageService(rootState, rootData, rootStorage);
            rootServer = server(rootConfig, rootState, rootFiles, rootPeers, rootLegacyGrants, rootMembership, rootReferences);
            rootServer.start();

            StateStore destinationState = new StateStore(destinationData);
            NetworkMembershipService destinationMembership = new NetworkMembershipService(destinationState, destinationConfig);
            String rootUrl = "http://127.0.0.1:" + rootPort;
            final Throwable[] joinFailure = {null};
            Thread joinThread = new Thread(() -> {
                try { new NetworkEnrollmentClient().join(rootUrl, "tester", password, destinationConfig,
                        destinationMembership.identity(), destinationMembership); }
                catch (Throwable failure) { joinFailure[0] = failure; }
            }, "managed-storage-enrollment-test");
            joinThread.start();
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
            while (rootMembership.pendingRequests().isEmpty() && System.nanoTime() < deadline) Thread.sleep(20);
            check(!rootMembership.pendingRequests().isEmpty(), "destination must request network membership before accepting managed storage");
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
            destinationServer = server(destinationConfig, destinationState, destinationFiles, destinationPeers,
                    destinationLegacyGrants, destinationMembership, destinationReferences);
            destinationServer.start();
            String destinationUrl = "http://127.0.0.1:" + destinationPort;
            NetworkPeerClient client = new NetworkPeerClient();

            Map<String, Object> placed = client.uploadManagedFile(destinationUrl, "backups/2026/source-report.bin", source,
                    rootMembership, rootConfig.maxFileBytes());
            String fileId = String.valueOf(placed.get("fileId"));
            check(!fileId.isBlank() && "backups/2026/source-report.bin".equals(placed.get("path")),
                    "destination must commit a complete file under its selected relative managed-storage path");
            Path physical = destinationStorage.resolve("backups/2026/source-report.bin");
            check(Files.mismatch(source, physical) == -1, "destination must store exact source bytes without transformation");

            Map<String, Object> remoteFiles = client.listManagedFiles(destinationUrl, rootMembership);
            check(remoteFiles.get("files") instanceof List<?> list && list.size() == 1,
                    "network members must see whole files in the destination node's managed-storage catalogue");
            Map<String, Object> destinationView = client.listManagedFiles(destinationUrl, destinationMembership);
            check(destinationView.get("files") instanceof List<?> destinationRows && destinationRows.size() == 1,
                    "the destination node and other authenticated network members must see managed files stored on it");
            Map<String, Object> destinationStat = client.statManagedFile(destinationUrl, fileId, destinationMembership);
            check(((Number) destinationStat.get("size")).longValue() == payload.length,
                    "a different active member must be able to stat a network-managed file");
            Map<String, Object> remoteStat = client.statManagedFile(destinationUrl, fileId, rootMembership);
            check(((Number) remoteStat.get("size")).longValue() == payload.length,
                    "managed-file stat must report the exact whole-file size");

            Path downloaded = downloadDirectory.resolve("round-trip.bin");
            NetworkPeerClient.RemoteDownloadResult result = client.downloadManagedFile(destinationUrl, fileId, downloaded,
                    rootMembership, rootConfig.maxFileBytes());
            check(result.sizeBytes() == payload.length && Files.mismatch(source, downloaded) == -1,
                    "remote managed-file download must preserve all bytes");
            check(result.sha256().equals(String.valueOf(placed.get("sha256"))),
                    "remote download checksum must match the placement receipt");

            boolean overwriteBlocked = false;
            try { client.uploadManagedFile(destinationUrl, "backups/2026/source-report.bin", source,
                    rootMembership, rootConfig.maxFileBytes()); }
            catch (Exception expected) { overwriteBlocked = true; }
            check(overwriteBlocked && Files.mismatch(source, physical) == -1,
                    "placing another file at an occupied destination must not overwrite existing data");

            boolean traversalBlocked = false;
            try { client.uploadManagedFile(destinationUrl, "../outside.bin", source, rootMembership, rootConfig.maxFileBytes()); }
            catch (Exception expected) { traversalBlocked = true; }
            check(traversalBlocked && !Files.exists(destinationStorage.getParent().resolve("outside.bin")),
                    "managed storage must reject traversal outside its configured root");

            Path destinationDownload = downloadDirectory.resolve("destination-member-round-trip.bin");
            NetworkPeerClient.RemoteDownloadResult destinationResult = client.downloadManagedFile(destinationUrl, fileId,
                    destinationDownload, destinationMembership, destinationConfig.maxFileBytes());
            check(destinationResult.sizeBytes() == payload.length && Files.mismatch(source, destinationDownload) == -1,
                    "a different active network member must download the same managed file with integrity verification");

            Map<String, Object> deleted = client.deleteManagedFile(destinationUrl, fileId, destinationMembership);
            check(Boolean.TRUE.equals(deleted.get("deleted")) && !Files.exists(physical),
                    "an authenticated network member must be able to delete a managed file on its destination node");
            check(((List<?>) client.listManagedFiles(destinationUrl, rootMembership).get("files")).isEmpty(),
                    "deleted managed files must disappear from every member's catalogue");

            // A retry after a crash between managed publication and transfer-journal cleanup must be idempotent.
            ManagedStorageService destinationManaged = new ManagedStorageService(destinationState, destinationConfig);
            String stableTransferId = "00000000-0000-4000-8000-000000000001";
            Map<String,Object> firstCommit = destinationManaged.receiveTransfer(stableTransferId,
                    rootConfig.nodeId(), "recovery/retry.bin", new ByteArrayInputStream(payload), payload.length,
                    String.valueOf(placed.get("sha256")));
            Map<String,Object> retryCommit = destinationManaged.receiveTransfer(stableTransferId,
                    rootConfig.nodeId(), "recovery/retry.bin", new ByteArrayInputStream(payload), payload.length,
                    String.valueOf(placed.get("sha256")));
            check(firstCommit.get("fileId").equals(retryCommit.get("fileId"))
                            && Files.mismatch(source, destinationStorage.resolve("recovery/retry.bin")) == -1,
                    "repeating a committed transfer ID must return the original file without overwriting or duplicating it");
            destinationManaged.deleteForMember(rootConfig.nodeId(), String.valueOf(firstCommit.get("fileId")));

            System.out.println("PASS: direct authenticated whole-file placement, network-wide managed catalogue, cross-member stat/download/delete, destination-owned storage, SHA-256 integrity, overwrite/traversal rejection.");
        } finally {
            Arrays.fill(password, '\0');
            if (rootServer != null) rootServer.close();
            if (destinationServer != null) destinationServer.close();
            if (rootFiles != null) rootFiles.close();
            if (destinationFiles != null) destinationFiles.close();
        }
    }

    private static PeerProtocolServer server(AppConfig config, StateStore state, FileService files, PeerService peers,
                                             GrantService grants, NetworkMembershipService membership,
                                             ReferenceStorageService references) throws Exception {
        ReferenceGrantService referenceGrants = new ReferenceGrantService(state, references, membership);
        ReferenceVersionService referenceVersions = new ReferenceVersionService(config.dataDirectory(), references);
        ManagedStorageService managed = new ManagedStorageService(state, config);
        return new PeerProtocolServer(config, files, peers, grants, new AuditLog(config.dataDirectory()), membership,
                references, referenceGrants, referenceVersions, managed);
    }

    private static AppConfig config(String nodeId, String nodeName, Path data, Path storage, int port) {
        return new AppConfig(nodeName, nodeId, "127.0.0.1", port, data, storage, null, "", 1024L * 1024 * 1024);
    }
    private static int freePort() throws Exception { try (ServerSocket socket = new ServerSocket(0)) { return socket.getLocalPort(); } }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
