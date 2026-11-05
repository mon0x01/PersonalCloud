package dev.personalcloud.network;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.AuditLog;
import dev.personalcloud.core.FileService;
import dev.personalcloud.core.GrantService;
import dev.personalcloud.core.PeerService;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.core.VersionService;
import dev.personalcloud.protocol.PeerProtocolServer;
import dev.personalcloud.storage.ReferenceGrantService;
import dev.personalcloud.storage.ReferenceRoot;
import dev.personalcloud.storage.ReferenceStorageService;
import dev.personalcloud.storage.ReferenceVersionService;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** End-to-end tests for member-authorized remote reference listing, browsing, search, download and deletion. */
public final class RemoteReferenceIntegrationTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-remote-reference-test-");
        PeerProtocolServer server = null;
        FileService files = null;
        char[] password = "Correct-Horse-2026".toCharArray();
        try {
            Path rootData = Files.createDirectory(workspace.resolve("root-data"));
            Path rootStorage = Files.createDirectory(workspace.resolve("root-storage"));
            Path rootReference = Files.createDirectory(workspace.resolve("root-reference"));
            Path candidateData = Files.createDirectory(workspace.resolve("candidate-data"));
            Path candidateStorage = Files.createDirectory(workspace.resolve("candidate-storage"));
            Path downloadDirectory = Files.createDirectory(workspace.resolve("downloads"));
            Path docs = Files.createDirectory(rootReference.resolve("docs"));
            byte[] readme = "PersonalCloud remote reference integrity test\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Files.write(docs.resolve("readme.txt"), readme);
            byte[] recoverable = "recoverable before delete".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Files.write(docs.resolve("delete-me.txt"), recoverable);
            Files.write(workspace.resolve("expected-delete-me.txt"), recoverable);

            int rootPort = freePort();
            int candidatePort = freePort();
            AppConfig rootConfig = config("remote-root-node-0001", "Remote Root", rootData, rootStorage, rootPort);
            AppConfig candidateConfig = config("remote-candidate-01", "Remote Candidate", candidateData, candidateStorage, candidatePort);
            StateStore rootState = new StateStore(rootData);
            files = new FileService(rootStorage);
            PeerService peers = new PeerService(rootState, rootConfig);
            VersionService versions = new VersionService(rootData, files);
            GrantService legacyGrants = new GrantService(rootState, files, peers, versions, rootConfig.maxFileBytes());
            NetworkMembershipService rootMembership = new NetworkMembershipService(rootState, rootConfig);
            rootMembership.bootstrap("Remote Reference Test", "tester", password);
            ReferenceStorageService references = new ReferenceStorageService(rootState, rootData, rootStorage);
            ReferenceRoot root = references.register("Documents", rootReference);
            ReferenceGrantService referenceGrants = new ReferenceGrantService(rootState, references, rootMembership);
            ReferenceVersionService referenceVersions = new ReferenceVersionService(rootData, references);
            server = new PeerProtocolServer(rootConfig, files, peers, legacyGrants, new AuditLog(rootData),
                    rootMembership, references, referenceGrants, referenceVersions);
            server.start();

            NetworkMembershipService candidateMembership = new NetworkMembershipService(new StateStore(candidateData), candidateConfig);
            String rootUrl = "http://127.0.0.1:" + rootPort;
            final Throwable[] joinFailure = {null};
            Thread joinThread = new Thread(() -> {
                try { new NetworkEnrollmentClient().join(rootUrl, "tester", password, candidateConfig,
                        candidateMembership.identity(), candidateMembership); }
                catch (Throwable failure) { joinFailure[0] = failure; }
            }, "remote-reference-enrollment-test");
            joinThread.start();
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
            while (rootMembership.pendingRequests().isEmpty() && System.nanoTime() < deadline) Thread.sleep(20);
            check(!rootMembership.pendingRequests().isEmpty(), "candidate must request network membership");
            String requestId = String.valueOf(rootMembership.pendingRequests().getFirst().get("requestId"));
            rootMembership.approve(requestId);
            joinThread.join(8_000);
            check(!joinThread.isAlive(), "candidate must finish enrollment after owner approval");
            if (joinFailure[0] != null) throw new AssertionError("candidate enrollment failed", joinFailure[0]);

            String candidateId = candidateConfig.nodeId();
            Map<String, Object> downloadGrant = referenceGrants.create(candidateId, root.id(), "", "DOWNLOAD");
            String downloadGrantId = String.valueOf(downloadGrant.get("grantId"));
            NetworkPeerClient remote = new NetworkPeerClient();

            Map<String, Object> shared = remote.listRemoteReferences(rootUrl, candidateMembership);
            check(shared.get("references") instanceof List<?> rows && rows.size() == 1,
                    "member must see its explicitly shared reference root");
            Map<String, Object> listing = remote.browseRemoteReference(rootUrl, downloadGrantId, "docs", candidateMembership);
            check(listing.get("entries") instanceof List<?> entries && entries.size() == 2,
                    "folder grant must permit browsing nested files");
            Map<String, Object> search = remote.searchRemoteReferences(rootUrl, "readme", 20, candidateMembership);
            check(search.get("results") instanceof List<?> results && results.size() == 1,
                    "network search must return only matching explicitly granted references");
            Map<String, Object> folderGrant = referenceGrants.create(candidateId, root.id(), "docs", "DOWNLOAD");
            String folderGrantId = String.valueOf(folderGrant.get("grantId"));
            Map<String, Object> folderListing = remote.browseRemoteReference(rootUrl, folderGrantId, "", candidateMembership);
            check(folderListing.get("entries") instanceof List<?> folderEntries
                            && folderEntries.stream().anyMatch(row -> row instanceof Map<?, ?> item && "readme.txt".equals(item.get("path"))),
                    "subfolder grants must return paths relative to the granted folder, not the storage root");
            Map<String, Object> folderStat = remote.statRemoteReference(rootUrl, folderGrantId, "readme.txt", candidateMembership);
            check("FILE".equals(folderStat.get("kind")), "subfolder grant paths must work for subsequent stat requests");
            NetworkPeerClient.RemoteRangeResult folderRange = remote.readRemoteReferenceRange(rootUrl, folderGrantId,
                    "readme.txt", 0, 8, candidateMembership);
            check(Arrays.equals(folderRange.bytes(), Arrays.copyOfRange(readme, 0, 8)),
                    "subfolder grant paths must work for subsequent random-access reads");
            Map<String, Object> scopedSearch = remote.searchRemoteReferences(rootUrl, "readme", 20, candidateMembership);
            check(scopedSearch.get("results") instanceof List<?> scopedResults && scopedResults.stream()
                            .filter(row -> row instanceof Map<?, ?> item && folderGrantId.equals(item.get("grantId")))
                            .anyMatch(row -> row instanceof Map<?, ?> item && "readme.txt".equals(item.get("path"))),
                    "search results for subfolder grants must use grant-relative paths");
            Map<String, Object> stat = remote.statRemoteReference(rootUrl, downloadGrantId, "docs/readme.txt", candidateMembership);
            check("FILE".equals(stat.get("kind")) && ((Number) stat.get("size")).longValue() == readme.length,
                    "remote stat must return file type and accurate size");
            NetworkPeerClient.RemoteRangeResult remoteRange = remote.readRemoteReferenceRange(rootUrl, downloadGrantId,
                    "docs/readme.txt", 5, 17, candidateMembership);
            check(remoteRange.totalSize() == readme.length && Arrays.equals(remoteRange.bytes(), Arrays.copyOfRange(readme, 5, 22)),
                    "authenticated remote random-access reads must return exactly the requested byte range");
            check(remote.readRemoteReferenceRange(rootUrl, downloadGrantId, "docs/readme.txt",
                    readme.length + 3L, 64, candidateMembership).bytes().length == 0,
                    "remote random-access reads beyond EOF must return an empty range");

            Path downloaded = downloadDirectory.resolve("readme.txt");
            NetworkPeerClient.RemoteDownloadResult download = remote.downloadRemoteReference(rootUrl, downloadGrantId,
                    "docs/readme.txt", downloaded, candidateMembership, 1024 * 1024);
            check(download.sizeBytes() == readme.length && Files.mismatch(downloaded, docs.resolve("readme.txt")) == -1,
                    "remote download must preserve file bytes");
            check(download.sha256().matches("[a-f0-9]{64}"), "remote download must return a verified SHA-256 digest");

            boolean traversalRejected = false;
            try { remote.browseRemoteReference(rootUrl, downloadGrantId, "../", candidateMembership); }
            catch (Exception expected) { traversalRejected = true; }
            check(traversalRejected, "remote reference browsing must reject path traversal");

            boolean unauthorizedDeleteRejected = false;
            try { remote.deleteRemoteReference(rootUrl, downloadGrantId, "docs/readme.txt", candidateMembership); }
            catch (Exception expected) { unauthorizedDeleteRejected = true; }
            check(unauthorizedDeleteRejected && Files.exists(docs.resolve("readme.txt")),
                    "DOWNLOAD-only grant must not permit deletion");

            Map<String, Object> deleteGrant = referenceGrants.create(candidateId, root.id(), "docs/delete-me.txt", "DOWNLOAD+DELETE");
            String deleteGrantId = String.valueOf(deleteGrant.get("grantId"));
            Map<String, Object> deleted = remote.deleteRemoteReference(rootUrl, deleteGrantId, "", candidateMembership);
            check(Boolean.TRUE.equals(deleted.get("deleted")) && !Files.exists(docs.resolve("delete-me.txt")),
                    "DOWNLOAD+DELETE must snapshot and then delete the selected file");
            List<Map<String, Object>> snapshots = referenceVersions.list();
            check(snapshots.size() == 1 && String.valueOf(snapshots.getFirst().get("path")).equals("docs/delete-me.txt"),
                    "owner must retain a recovery snapshot before remote deletion");
            String snapshotId = String.valueOf(snapshots.getFirst().get("snapshotId"));
            Map<String, Object> restored = referenceVersions.restore(snapshotId);
            check(Boolean.TRUE.equals(restored.get("restored")) &&
                    Files.mismatch(docs.resolve("delete-me.txt"), workspace.resolve("expected-delete-me.txt")) == -1,
                    "owner must be able to restore a deleted reference file from its verified snapshot");
            boolean overwriteBlocked = false;
            try { referenceVersions.restore(snapshotId); }
            catch (IllegalStateException expected) { overwriteBlocked = true; }
            check(overwriteBlocked, "snapshot restore must never overwrite a path that already exists");

            System.out.println("PASS: authenticated remote references, member-scoped listing, folder browsing, network search, stat, SHA-256-verified download, authenticated random-access range reads, traversal rejection, DOWNLOAD-only deletion denial, DOWNLOAD+DELETE recovery snapshot and no-overwrite restore.");
        } finally {
            Arrays.fill(password, '\0');
            if (server != null) server.close();
            if (files != null) files.close();
        }
    }

    private static AppConfig config(String nodeId, String nodeName, Path data, Path storage, int port) {
        return new AppConfig(nodeName, nodeId, "127.0.0.1", port, data, storage, null, "", 1024L * 1024 * 1024);
    }
    private static int freePort() throws Exception { try (ServerSocket socket = new ServerSocket(0)) { return socket.getLocalPort(); } }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}
