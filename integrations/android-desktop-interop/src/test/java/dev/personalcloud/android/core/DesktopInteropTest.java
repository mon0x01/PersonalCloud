package dev.personalcloud.android.core;

import dev.personalcloud.control.LocalControlClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HexFormat;
import java.security.MessageDigest;

/** Physical-protocol contract test using the headless desktop node and its Java local-control API. */
public final class DesktopInteropTest {
    public static void main(String[] args) throws Exception {
        Path jar = Path.of(args[0]);
        Path desktopP12 = Path.of(args[1]);
        Path androidP12 = Path.of(args[2]);
        Path desktopCertificate = Path.of(args[3]);
        Path androidTruststore = Path.of(args[4]);
        String desktopPassword = args[5];
        String androidPassword = args[6];
        String trustPassword = args[7];

        Path workspace = Files.createTempDirectory("personalcloud-desktop-android-v2-");
        Path desktopData = Files.createDirectory(workspace.resolve("desktop-data"));
        Path desktopStorage = Files.createDirectory(workspace.resolve("desktop-storage"));
        Path desktopReferences = Files.createDirectory(workspace.resolve("desktop-references"));
        Path androidStorage = Files.createDirectory(workspace.resolve("android-storage"));
        Path desktopEligible = Files.createDirectory(workspace.resolve("desktop-eligible"));
        Path desktopEligibleDocs = Files.createDirectory(desktopEligible.resolve("Documents"));
        Path desktopEligibleProtected = Files.createDirectory(desktopEligible.resolve("Protected"));
        Files.writeString(desktopEligibleDocs.resolve("report.txt"), "desktop eligible original",
                StandardCharsets.UTF_8);
        Files.writeString(desktopEligibleProtected.resolve("plan.txt"), "desktop protected original",
                StandardCharsets.UTF_8);
        Path desktopLog = workspace.resolve("desktop.log");
        Files.writeString(desktopStorage.resolve("desktop-owned.txt"), "Original file owned by desktop node", StandardCharsets.UTF_8);
        Files.writeString(desktopReferences.resolve("desktop-owned.txt"), "Referenced desktop file for Android", StandardCharsets.UTF_8);
        Files.writeString(desktopReferences.resolve("desktop-network-delete.txt"), "Android-authorized remote deletion", StandardCharsets.UTF_8);
        Files.writeString(androidStorage.resolve("android-view.txt"), "Original file owned by Android node", StandardCharsets.UTF_8);
        Files.writeString(androidStorage.resolve("android-modify.txt"), "Disposable Android DELETE test", StandardCharsets.UTF_8);
        Files.writeString(androidStorage.resolve("android-network-read.txt"), "Network-member reference content from Android", StandardCharsets.UTF_8);
        Files.writeString(androidStorage.resolve("android-network-delete.txt"), "Network-member delete with recovery snapshot", StandardCharsets.UTF_8);
        Path androidDocs = Files.createDirectory(androidStorage.resolve("android-docs"));
        Path androidNested = Files.createDirectory(androidDocs.resolve("nested"));
        Files.writeString(androidNested.resolve("inside.txt"), "Android nested network reference", StandardCharsets.UTF_8);

        int desktopPort = freePort();
        int androidPort = freePort();
        Process desktop = null;
        PeerNode android = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "--add-modules", "jdk.httpserver", "-jar", jar.toString());
            Map<String, String> env = builder.environment();
            env.put("PERSONALCLOUD_NAME", "Desktop-Interop-Test");
            env.put("PERSONALCLOUD_BIND_ADDRESS", "127.0.0.1");
            env.put("PERSONALCLOUD_PORT", Integer.toString(desktopPort));
            env.put("PERSONALCLOUD_DATA_DIR", desktopData.toString());
            env.put("PERSONALCLOUD_STORAGE_ROOT", desktopStorage.toString());
            env.put("PERSONALCLOUD_ELIGIBLE_ROOTS", desktopEligible.toString());
            env.put("PERSONALCLOUD_TLS_KEYSTORE", desktopP12.toString());
            env.put("PERSONALCLOUD_TLS_KEYSTORE_PASSWORD", desktopPassword);
            env.put("PERSONALCLOUD_TLS_TRUSTSTORE", androidTruststore.toString());
            env.put("PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD", trustPassword);
            builder.redirectErrorStream(true).redirectOutput(desktopLog.toFile());
            desktop = builder.start();

            String desktopBase = "https://127.0.0.1:" + desktopPort;
            waitForDesktop(desktopBase, desktop, desktopLog, desktopData.resolve("control.sock"), desktopCertificate);
            LocalControlClient control = new LocalControlClient(desktopData.resolve("control.sock"));
            String desktopNodeId = String.valueOf(control.ping().get("nodeId"));
            String networkPassword = "NetworkInterop-2026!";
            control.networkBootstrap("Interop Private Network", "interop", networkPassword.toCharArray());
            control.grantFilesystemConsent();

            SSLContext androidTls = serverTls(androidP12, androidPassword);
            MemoryStateStore androidState = new MemoryStateStore();
            android = new PeerNode("android-interop-node", "Android-Interop-Test", androidStorage,
                    androidState, message -> { });
            FakeExternalReferenceStore externalReferences = new FakeExternalReferenceStore();
            android.configureExternalReferenceStore(externalReferences);
            String androidBase = "https://127.0.0.1:" + androidPort;
            String androidNodeId = "android-interop-node";
            NetworkMembershipClient androidMembership = new NetworkMembershipClient(androidState,
                    androidNodeId, "Android-Interop-Test", androidBase);
            android.configureNetworkMembership(androidMembership);
            android.start(InetAddress.getByName("127.0.0.1"), androidPort, androidTls.getServerSocketFactory());

            // Android joins the desktop-created private network through the real HTTP enrollment API.
            Map<String, Object> joinRequest = androidMembership.beginJoin(desktopBase, "interop",
                    networkPassword.toCharArray(), desktopCertificate.toString());
            check("PENDING".equals(joinRequest.get("status")), "Android enrollment must wait for explicit approval");
            List<Map<String, Object>> pendingMembership = control.networkRequests();
            check(pendingMembership.size() == 1 && androidNodeId.equals(pendingMembership.get(0).get("nodeId")),
                    "desktop must receive the Android enrollment request");
            String enrollmentId = String.valueOf(pendingMembership.get(0).get("requestId"));
            control.networkApprove(enrollmentId);
            Map<String, Object> joined = androidMembership.refreshJoin(desktopCertificate.toString());
            check(Boolean.TRUE.equals(joined.get("joined")), "Android must install its certificate only after approval");
            boolean endpointIdentityMismatchRejected = false;
            try {
                androidMembership.syncCatalogue(desktopBase, androidNodeId, desktopCertificate.toString());
            } catch (SecurityException expected) {
                endpointIdentityMismatchRejected = true;
            }
            check(endpointIdentityMismatchRejected,
                    "Android must not accept a catalogue response from an endpoint claiming a different member identity");
            Map<String, Object> sync = androidMembership.synchronizeOnce(desktopCertificate.toString());
            check(((List<?>) sync.get("online")).contains(desktopNodeId),
                    "Android periodic catalogue synchronization must discover and heartbeat the desktop member");
            check(control.networkMembers().stream().anyMatch(item -> androidNodeId.equals(item.get("nodeId"))
                    && "ACTIVE".equals(item.get("status"))), "desktop must catalogue the approved Android member");
            NetworkMembershipClient restoredMembership = new NetworkMembershipClient(androidState,
                    androidNodeId, "Android-Interop-Test", androidBase);
            check(Boolean.TRUE.equals(restoredMembership.status().get("joined"))
                    && androidMembership.identity().publicKeyBase64().equals(restoredMembership.identity().publicKeyBase64()),
                    "Android membership certificate and per-device identity must survive state-store restart");

            // Android writes to the desktop owner's actual eligible filesystem through the
            // same signed protocol; every mutation is authorized by the owning peer.
            String desktopCa = desktopCertificate.toString();
            List<Map<String,Object>> eligibleRoots = NetworkPeerConnector.listFilesystemRoots(
                    desktopBase, androidMembership, desktopCa);
            check(eligibleRoots.size() == 1, "Android must discover exactly one consented desktop eligible root");
            String eligibleRootId = String.valueOf(eligibleRoots.get(0).get("rootId"));
            List<Map<String,Object>> eligibleListing = NetworkPeerConnector.browseFilesystem(
                    desktopBase, eligibleRootId, "", androidMembership, desktopCa);
            check(eligibleListing.stream().anyMatch(row -> "Documents".equals(row.get("name"))),
                    "Android must browse the owner's actual eligible directory");
            Map<String,Object> eligibleStat = NetworkPeerConnector.statFilesystem(
                    desktopBase, eligibleRootId, "Documents/report.txt", androidMembership, desktopCa);
            check(((Number) eligibleStat.get("size")).longValue() == "desktop eligible original".length(),
                    "Android must stat the owner's original file");
            PeerConnector.RangeResult eligibleRange = NetworkPeerConnector.readFilesystemRange(
                    desktopBase, eligibleRootId, "Documents/report.txt", 8, 8, androidMembership, desktopCa);
            check(new String(eligibleRange.bytes, StandardCharsets.UTF_8).equals("eligible"),
                    "Android must perform bounded signed range reads on eligible storage");

            Path androidUpload = workspace.resolve("android-filesystem-write.txt");
            byte[] filesystemUploadBytes = "written by the Android peer".getBytes(StandardCharsets.UTF_8);
            Files.write(androidUpload, filesystemUploadBytes);
            NetworkPeerConnector.uploadFilesystemFile(desktopBase, eligibleRootId, "Documents/android-write.txt",
                    androidUpload, false, "", androidMembership, desktopCa, 10 * 1024 * 1024);
            check(java.util.Arrays.equals(Files.readAllBytes(desktopEligibleDocs.resolve("android-write.txt")),
                    filesystemUploadBytes), "Android write-back must publish exact bytes to the owner's path");

            NetworkPeerConnector.createFilesystemDirectory(desktopBase, eligibleRootId, "AndroidDir",
                    androidMembership, desktopCa);
            check(Files.isDirectory(desktopEligible.resolve("AndroidDir")),
                    "Android mkdir must create the directory on the owner's filesystem");
            NetworkPeerConnector.moveFilesystemEntry(desktopBase, eligibleRootId, "AndroidDir",
                    "AndroidDirRenamed", false, "", androidMembership, desktopCa);
            check(Files.isDirectory(desktopEligible.resolve("AndroidDirRenamed"))
                            && !Files.exists(desktopEligible.resolve("AndroidDir")),
                    "Android rename must move the owner's original directory");
            NetworkPeerConnector.deleteFilesystemEntry(desktopBase, eligibleRootId, "AndroidDirRenamed",
                    true, "", androidMembership, desktopCa);
            check(!Files.exists(desktopEligible.resolve("AndroidDirRenamed")),
                    "Android delete must remove the owner's original directory");
            NetworkPeerConnector.deleteFilesystemEntry(desktopBase, eligibleRootId, "Documents/android-write.txt",
                    false, "", androidMembership, desktopCa);
            check(!Files.exists(desktopEligibleDocs.resolve("android-write.txt")),
                    "Android delete must remove the owner's original file");

            boolean traversalDenied = false;
            try {
                NetworkPeerConnector.statFilesystem(desktopBase, eligibleRootId, "../outside.txt",
                        androidMembership, desktopCa);
            } catch (Exception expected) { traversalDenied = true; }
            check(traversalDenied, "Android must reject parent-directory traversal at the owner");

            Path desktopOutside = Files.createDirectory(workspace.resolve("desktop-outside-eligible"));
            Files.writeString(desktopOutside.resolve("secret.txt"), "outside secret", StandardCharsets.UTF_8);
            Files.createSymbolicLink(desktopEligible.resolve("outside-link"), desktopOutside);
            boolean symlinkBrowseDenied = false;
            try {
                NetworkPeerConnector.browseFilesystem(desktopBase, eligibleRootId, "outside-link",
                        androidMembership, desktopCa);
            } catch (Exception expected) { symlinkBrowseDenied = true; }
            check(symlinkBrowseDenied, "Android must not follow owner symlinks outside eligible storage");
            boolean symlinkWriteDenied = false;
            try {
                NetworkPeerConnector.uploadFilesystemFile(desktopBase, eligibleRootId,
                        "outside-link/secret.txt", androidUpload, true, "",
                        androidMembership, desktopCa, 10 * 1024 * 1024);
            } catch (Exception expected) { symlinkWriteDenied = true; }
            check(symlinkWriteDenied && Files.readString(desktopOutside.resolve("secret.txt"),
                            StandardCharsets.UTF_8).equals("outside secret"),
                    "Android writes must not follow symlinks or corrupt outside files");
            Files.delete(desktopEligible.resolve("outside-link"));

            Path concurrentAndroidA = workspace.resolve("android-concurrent-a.txt");
            Path concurrentAndroidB = workspace.resolve("android-concurrent-b.txt");
            Files.writeString(concurrentAndroidA, "android concurrent A", StandardCharsets.UTF_8);
            Files.writeString(concurrentAndroidB, "android concurrent B", StandardCharsets.UTF_8);
            java.util.concurrent.atomic.AtomicInteger androidWins = new java.util.concurrent.atomic.AtomicInteger();
            Thread androidWriterA = new Thread(() -> {
                try { NetworkPeerConnector.uploadFilesystemFile(desktopBase, eligibleRootId,
                        "Documents/android-concurrent.txt", concurrentAndroidA, false, "",
                        androidMembership, desktopCa, 10 * 1024 * 1024); androidWins.incrementAndGet(); }
                catch (Exception ignored) { }
            });
            Thread androidWriterB = new Thread(() -> {
                try { NetworkPeerConnector.uploadFilesystemFile(desktopBase, eligibleRootId,
                        "Documents/android-concurrent.txt", concurrentAndroidB, false, "",
                        androidMembership, desktopCa, 10 * 1024 * 1024); androidWins.incrementAndGet(); }
                catch (Exception ignored) { }
            });
            androidWriterA.start(); androidWriterB.start();
            androidWriterA.join(10_000); androidWriterB.join(10_000);
            check(androidWins.get() == 1, "exactly one concurrent Android no-overwrite commit must succeed");
            String androidConcurrent = Files.readString(desktopEligibleDocs.resolve("android-concurrent.txt"),
                    StandardCharsets.UTF_8);
            check(androidConcurrent.equals("android concurrent A")
                            || androidConcurrent.equals("android concurrent B"),
                    "concurrent Android writes must never publish mixed or partial content");
            NetworkPeerConnector.deleteFilesystemEntry(desktopBase, eligibleRootId,
                    "Documents/android-concurrent.txt", false, "", androidMembership, desktopCa);

            control.setPolicy(eligibleRootId, "Protected", "PROTECTED");
            boolean protectedWriteDenied = false;
            try {
                NetworkPeerConnector.uploadFilesystemFile(desktopBase, eligibleRootId, "Protected/plan.txt",
                        androidUpload, true, "", androidMembership, desktopCa, 10 * 1024 * 1024);
            } catch (Exception expected) { protectedWriteDenied = true; }
            check(protectedWriteDenied && Files.readString(desktopEligibleProtected.resolve("plan.txt"),
                            StandardCharsets.UTF_8).equals("desktop protected original"),
                    "Android must not bypass PROTECTED owner approval or corrupt the original file");
            control.removePolicy(eligibleRootId, "Protected");

            control.setPolicy(eligibleRootId, "Protected", "PRIVATE");
            boolean privateBrowseDenied = false;
            try {
                NetworkPeerConnector.browseFilesystem(desktopBase, eligibleRootId, "Protected",
                        androidMembership, desktopCa);
            } catch (Exception expected) { privateBrowseDenied = true; }
            check(privateBrowseDenied, "Android must not browse PRIVATE directories");
            control.removePolicy(eligibleRootId, "Protected");

            control.revokeFilesystemConsent();
            boolean revokedAccessDenied = false;
            try {
                NetworkPeerConnector.listFilesystemRoots(desktopBase, androidMembership, desktopCa);
            } catch (Exception expected) { revokedAccessDenied = true; }
            check(revokedAccessDenied, "consent revocation must disable Android eligible-storage access immediately");
            control.grantFilesystemConsent();
            check(NetworkPeerConnector.listFilesystemRoots(desktopBase, androidMembership, desktopCa).size() == 1,
                    "Android access must resume only after explicit consent is restored");

            // A SAF-backed adapter exposes existing provider-owned bytes without importing them into app storage.
            Map<String,Object> safGrant = android.grantExternalNetworkReference(desktopNodeId,
                    "content://test.documents/tree/root", "DOWNLOAD");
            String safGrantId = String.valueOf(safGrant.get("grantId"));
            List<Map<String,Object>> desktopVisibleSafGrants = control.listRemoteNetworkReferences(androidNodeId);
            check(desktopVisibleSafGrants.stream().anyMatch(row -> safGrantId.equals(row.get("grantId"))),
                    "Android must list platform-backed document references through the signed network API");
            List<Map<String,Object>> desktopVisibleSafEntries = control.browseRemoteNetworkReference(androidNodeId, safGrantId, "");
            check(desktopVisibleSafEntries.stream().anyMatch(row -> "Existing cloud-provider file.txt".equals(row.get("name"))),
                    "desktop must browse an Android external reference without copying its source bytes");
            byte[] safExpected = externalReferences.payload();
            byte[] safRange = control.readRemoteRange(androidNodeId, "REFERENCE", safGrantId,
                    "Existing cloud-provider file.txt", 7, 19);
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(safExpected, 7, 26), safRange),
                    "desktop must obtain signed, SHA-256-verified random-access bytes from an external document provider");
            boolean safDeleteDenied = false;
            try { control.deleteRemoteNetworkReference(androidNodeId, safGrantId, "Existing cloud-provider file.txt"); }
            catch (java.io.IOException expected) { safDeleteDenied = true; }
            check(safDeleteDenied && !externalReferences.deleted(),
                    "DOWNLOAD-only SAF references must not authorize deletion of user-owned documents");
            Map<String,Object> safDeleteGrant = android.grantExternalNetworkReference(desktopNodeId,
                    "content://test.documents/tree/delete-root", "DOWNLOAD+DELETE");
            control.deleteRemoteNetworkReference(androidNodeId, String.valueOf(safDeleteGrant.get("grantId")),
                    "Existing cloud-provider file.txt");
            check(externalReferences.deleted(),
                    "DOWNLOAD+DELETE must use the external provider's owner-side snapshot and delete contract");

            String signedPath = "/network/members";
            Map<String, String> replayableHeaders = restoredMembership.createAuthHeaders("GET", signedPath, new byte[0]);
            PeerConnector.getSignedJson(desktopBase, signedPath, replayableHeaders, desktopCertificate.toString());
            boolean replayRejected = false;
            try { PeerConnector.getSignedJson(desktopBase, signedPath, replayableHeaders, desktopCertificate.toString()); }
            catch (IllegalStateException expected) { replayRejected = true; }
            check(replayRejected, "desktop must reject replayed Android membership signatures");

            Map<String, String> overflowHeaders = androidMembership.createAuthHeaders("GET", signedPath, new byte[0]);
            String extremeTimestamp = Long.toString(Long.MIN_VALUE);
            String emptyBodyHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[0]));
            String overflowCanonical = "GET\n" + signedPath + "\n" + extremeTimestamp + "\n"
                    + overflowHeaders.get("X-PC-Nonce") + "\n" + emptyBodyHash;
            overflowHeaders.put("X-PC-Timestamp", extremeTimestamp);
            overflowHeaders.put("X-PC-Signature", java.util.Base64.getEncoder().encodeToString(
                    androidMembership.identity().sign(overflowCanonical.getBytes(StandardCharsets.UTF_8))));
            check(!androidMembership.authenticate("GET", signedPath, overflowHeaders, new byte[0]),
                    "Android peer core must reject a correctly signed request with an overflowed extreme timestamp");

            // Android must consume the same signed network APIs as a desktop member.
            Map<String, Object> desktopReference = control.registerReference("Desktop references", desktopReferences);
            String desktopReferenceId = String.valueOf(object(desktopReference.get("reference")).get("id"));
            Map<String, Object> desktopNetworkGrant = control.createReferenceGrant(androidNodeId, desktopReferenceId, "", "DOWNLOAD");
            String desktopGrantId = String.valueOf(object(desktopNetworkGrant.get("grant")).get("grantId"));
            String registeredDesktopEndpoint = NetworkPeerConnector.activeEndpoint(androidMembership, desktopNodeId);
            List<Map<String, Object>> androidVisibleDesktopGrants = NetworkPeerConnector.listReferences(
                    registeredDesktopEndpoint, androidMembership, desktopCertificate.toString());
            check(androidVisibleDesktopGrants.stream().anyMatch(item -> desktopGrantId.equals(item.get("grantId"))),
                    "Android network client must list grants shared to its member identity; endpoint=" + registeredDesktopEndpoint
                            + "; members=" + androidMembership.members() + "; grants=" + androidVisibleDesktopGrants
                            + "; expected=" + desktopGrantId + "; root=" + desktopNetworkGrant);
            List<Map<String, Object>> androidVisibleDesktopEntries = NetworkPeerConnector.browseReference(
                    registeredDesktopEndpoint, desktopGrantId, "", androidMembership, desktopCertificate.toString());
            check(androidVisibleDesktopEntries.stream().anyMatch(item -> "desktop-owned.txt".equals(item.get("name"))),
                    "Android network client must browse a desktop-owned reference folder");
            Map<String, Object> desktopFileStat = NetworkPeerConnector.statReference(registeredDesktopEndpoint,
                    desktopGrantId, "desktop-owned.txt", androidMembership, desktopCertificate.toString());
            check("FILE".equals(desktopFileStat.get("kind")) && ((Number) desktopFileStat.get("size")).longValue() > 0,
                    "Android network client must stat remote desktop files");
            PeerConnector.RangeResult desktopFileRange = NetworkPeerConnector.readReferenceRange(
                    registeredDesktopEndpoint, desktopGrantId, "desktop-owned.txt", 4, 12,
                    androidMembership, desktopCertificate.toString());
            byte[] desktopOwnedBytes = Files.readAllBytes(desktopReferences.resolve("desktop-owned.txt"));
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(desktopOwnedBytes, 4, 16), desktopFileRange.bytes),
                    "Android network client must perform signed, SHA-256-verified range reads");
            check(NetworkPeerConnector.searchReferences(registeredDesktopEndpoint, "desktop-owned", 10,
                    androidMembership, desktopCertificate.toString()).stream().anyMatch(item ->
                    "desktop-owned.txt".equals(item.get("name"))), "Android network client must search remote member references");

            Map<String, Object> androidDeleteGrant = control.createReferenceGrant(androidNodeId, desktopReferenceId,
                    "desktop-network-delete.txt", "DOWNLOAD+DELETE");
            String androidDeleteGrantId = String.valueOf(object(androidDeleteGrant.get("grant")).get("grantId"));
            int snapshotsBeforeAndroidDelete = control.listReferenceSnapshots().size();
            Map<String, Object> androidDeletedReference = NetworkPeerConnector.deleteReference(registeredDesktopEndpoint,
                    androidDeleteGrantId, "", androidMembership, desktopCertificate.toString());
            check(Boolean.TRUE.equals(androidDeletedReference.get("deleted"))
                            && !Files.exists(desktopReferences.resolve("desktop-network-delete.txt")),
                    "Android must be able to delete a desktop reference when the owner granted DOWNLOAD+DELETE");
            check(control.listReferenceSnapshots().size() == snapshotsBeforeAndroidDelete + 1,
                    "Android-originated deletion must create an owner-side recovery snapshot on the desktop");

            Path androidUploadSource = workspace.resolve("android-managed-source.bin");
            Files.writeString(androidUploadSource, "Android-to-desktop direct managed placement", StandardCharsets.UTF_8);
            Map<String, Object> desktopManagedReceipt = NetworkPeerConnector.uploadManagedFile(
                    registeredDesktopEndpoint, "from-android/android-managed-source.bin", androidUploadSource,
                    androidMembership, desktopCertificate.toString(), 1024 * 1024);
            String desktopManagedFileId = String.valueOf(desktopManagedReceipt.get("fileId"));
            List<Map<String, Object>> desktopManagedForAndroid = NetworkPeerConnector.listManagedFiles(
                    registeredDesktopEndpoint, androidMembership, desktopCertificate.toString());
            check(desktopManagedForAndroid.stream().anyMatch(item -> desktopManagedFileId.equals(item.get("fileId"))),
                    "Android must directly place and list a whole file on a desktop node");
            PeerConnector.RangeResult desktopManagedRange = NetworkPeerConnector.readManagedRange(
                    registeredDesktopEndpoint, desktopManagedFileId, 7, 10, androidMembership, desktopCertificate.toString());
            byte[] androidUploadBytes = Files.readAllBytes(androidUploadSource);
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(androidUploadBytes, 7, 17), desktopManagedRange.bytes),
                    "Android managed placement must be readable through verified remote byte ranges");

            byte[] providerBytes = "Android SAF source streamed directly to the destination peer".getBytes(StandardCharsets.UTF_8);
            int[] providerOpens = {0};
            Map<String,Object> providerUpload = NetworkPeerConnector.uploadManagedFile(
                    registeredDesktopEndpoint, "from-android/provider-streamed.bin",
                    () -> { providerOpens[0]++; return new ByteArrayInputStream(providerBytes); }, -1L,
                    androidMembership, desktopCertificate.toString(), 1024 * 1024);
            String providerFileId = String.valueOf(providerUpload.get("fileId"));
            check(providerOpens[0] == 2 && providerBytes.length == ((Number) providerUpload.get("size")).longValue(),
                    "Android content-provider managed upload must hash then stream from a reopenable source without staging a local copy");
            PeerConnector.RangeResult providerRange = NetworkPeerConnector.readManagedRange(
                    registeredDesktopEndpoint, providerFileId, 7, 16, androidMembership, desktopCertificate.toString());
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(providerBytes, 7, 23), providerRange.bytes),
                    "Android content-provider managed upload must arrive intact and remain remotely range-readable");
            // Exercise multiple independently authenticated chunks over the real desktop/Android peer protocol.
            byte[] largeTransferBytes = new byte[9 * 1024 * 1024 + 37];
            for (int i = 0; i < largeTransferBytes.length; i++) largeTransferBytes[i] = (byte)(i * 17 + 3);
            Path largeTransferSource = workspace.resolve("large-multichunk-source.bin");
            Files.write(largeTransferSource, largeTransferBytes);
            String largeTransferHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(largeTransferBytes));
            Map<String,Object> transferCreateBody = new LinkedHashMap<>();
            transferCreateBody.put("path", "from-android/large-multichunk.bin");
            transferCreateBody.put("size", (long)largeTransferBytes.length);
            transferCreateBody.put("sha256", largeTransferHash);
            byte[] transferCreateBytes = Json.stringify(transferCreateBody).getBytes(StandardCharsets.UTF_8);
            Map<String,String> transferCreateHeaders = androidMembership.createAuthHeaders(
                    "POST", "/network/transfers", transferCreateBytes);
            Map<String,Object> transferSession = PeerConnector.postSignedJson(registeredDesktopEndpoint,
                    "/network/transfers", transferCreateBody, transferCreateHeaders, desktopCertificate.toString());
            String transferSessionId = String.valueOf(transferSession.get("transferId"));
            Map<String,Object> largeTransferReceipt = NetworkPeerConnector.resumeManagedFile(
                    registeredDesktopEndpoint, transferSessionId,
                    () -> Files.newInputStream(largeTransferSource), largeTransferBytes.length,
                    androidMembership, desktopCertificate.toString(), 16 * 1024 * 1024);
            String largeTransferId = String.valueOf(largeTransferReceipt.get("fileId"));
            check(((Number)largeTransferReceipt.get("size")).longValue() == largeTransferBytes.length,
                    "multi-chunk direct transfer must preserve the complete source size");
            Map<String,Object> committedTransferStatus = NetworkPeerConnector.transferStatus(
                    registeredDesktopEndpoint, transferSessionId, androidMembership, desktopCertificate.toString());
            check("COMMITTED".equals(committedTransferStatus.get("state"))
                            && object(committedTransferStatus.get("receipt")).get("fileId").equals(largeTransferId),
                    "receiver must retain a durable commit receipt after releasing staged chunks");
            int[] committedResumeOpens = {0};
            Map<String,Object> replayedReceipt = NetworkPeerConnector.resumeManagedFile(
                    registeredDesktopEndpoint, transferSessionId,
                    () -> { committedResumeOpens[0]++; return Files.newInputStream(largeTransferSource); },
                    largeTransferBytes.length, androidMembership, desktopCertificate.toString(), 16 * 1024 * 1024);
            check(largeTransferId.equals(replayedReceipt.get("fileId")) && committedResumeOpens[0] == 1,
                    "Android sender must recover a completed receipt without reopening and retransmitting source chunks");
            PeerConnector.RangeResult largeTransferRange = NetworkPeerConnector.readManagedRange(
                    registeredDesktopEndpoint, largeTransferId, 4 * 1024 * 1024 + 11, 8192,
                    androidMembership, desktopCertificate.toString());
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(largeTransferBytes,
                            4 * 1024 * 1024 + 11, 4 * 1024 * 1024 + 11 + 8192), largeTransferRange.bytes),
                    "multi-chunk direct transfer must preserve bytes across chunk boundaries");
            NetworkPeerConnector.deleteManagedFile(registeredDesktopEndpoint, largeTransferId,
                    androidMembership, desktopCertificate.toString());

            Map<String,Object> providerDelete = NetworkPeerConnector.deleteManagedFile(
                    registeredDesktopEndpoint, providerFileId, androidMembership, desktopCertificate.toString());
            check(Boolean.TRUE.equals(providerDelete.get("deleted")), "Android content-provider managed upload must be owner-addressable for normal authorized deletion");
            boolean wrongProviderSizeRejected = false;
            try {
                NetworkPeerConnector.uploadManagedFile(registeredDesktopEndpoint, "from-android/wrong-size.bin",
                        () -> new ByteArrayInputStream(providerBytes), providerBytes.length + 1L,
                        androidMembership, desktopCertificate.toString(), 1024 * 1024);
            } catch (IllegalStateException expected) { wrongProviderSizeRejected = true; }
            check(wrongProviderSizeRejected, "Android content-provider upload must reject provider metadata size mismatches before network transfer");
            int[] unsafeSourceOpens = {0};
            boolean unsafeDestinationRejected = false;
            try {
                NetworkPeerConnector.uploadManagedFile(registeredDesktopEndpoint, "../escape.bin",
                        () -> { unsafeSourceOpens[0]++; return new ByteArrayInputStream(providerBytes); }, -1L,
                        androidMembership, desktopCertificate.toString(), 1024 * 1024);
            } catch (IllegalArgumentException expected) { unsafeDestinationRejected = true; }
            check(unsafeDestinationRejected && unsafeSourceOpens[0] == 0,
                    "Android content-provider upload must reject traversal destinations before reading the source");

            Map<String, Object> androidManagedDelete = NetworkPeerConnector.deleteManagedFile(registeredDesktopEndpoint,
                    desktopManagedFileId, androidMembership, desktopCertificate.toString());
            check(Boolean.TRUE.equals(androidManagedDelete.get("deleted"))
                            && !Files.exists(desktopStorage.resolve("from-android/android-managed-source.bin")),
                    "the uploading Android member must be able to remove a managed file after remote verification");

            // New signed-member reference API: no legacy bearer token is required for these operations.
            Map<String, Object> androidReferenceGrant = android.grantNetworkReference(desktopNodeId,
                    "android-network-read.txt", "DOWNLOAD");
            String androidGrantId = String.valueOf(androidReferenceGrant.get("grantId"));
            List<Map<String, Object>> androidReferences = control.listRemoteNetworkReferences(androidNodeId);
            check(androidReferences.stream().anyMatch(item -> androidGrantId.equals(item.get("grantId"))),
                    "desktop must list the Android reference shared through signed network membership");
            Path networkReferenceDownload = workspace.resolve("android-network-reference.txt");
            control.downloadRemoteNetworkReference(androidNodeId, androidGrantId, "", networkReferenceDownload);
            check("Network-member reference content from Android".equals(Files.readString(networkReferenceDownload)),
                    "desktop must download Android reference bytes through signed membership");
            byte[] androidReferenceBytes = Files.readAllBytes(androidStorage.resolve("android-network-read.txt"));
            byte[] androidReferenceRange = control.readRemoteRange(androidNodeId, "REFERENCE", androidGrantId, "", 8, 15);
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(androidReferenceBytes, 8, 23), androidReferenceRange),
                    "desktop must read a verified byte range from an Android reference");
            boolean networkDownloadDeleteDenied = false;
            try { control.deleteRemoteNetworkReference(androidNodeId, androidGrantId, ""); }
            catch (java.io.IOException expected) { networkDownloadDeleteDenied = true; }
            check(networkDownloadDeleteDenied && Files.exists(androidStorage.resolve("android-network-read.txt")),
                    "Android DOWNLOAD grant must not authorize deletion");

            Map<String, Object> androidFolderGrant = android.grantNetworkReference(desktopNodeId,
                    "android-docs", "DOWNLOAD");
            String androidFolderGrantId = String.valueOf(androidFolderGrant.get("grantId"));
            List<Map<String, Object>> androidEntries = control.browseRemoteNetworkReference(androidNodeId,
                    androidFolderGrantId, "");
            check(androidEntries.size() == 1 && "nested".equals(androidEntries.get(0).get("name")),
                    "desktop must browse Android-owned reference folders");

            Map<String, Object> androidOwnedDeleteGrant = android.grantNetworkReference(desktopNodeId,
                    "android-network-delete.txt", "DOWNLOAD+DELETE");
            String androidOwnedDeleteGrantId = String.valueOf(androidOwnedDeleteGrant.get("grantId"));
            control.deleteRemoteNetworkReference(androidNodeId, androidOwnedDeleteGrantId, "");
            check(!Files.exists(androidStorage.resolve("android-network-delete.txt")),
                    "Android DOWNLOAD+DELETE grant must permit the authorized deletion");
            try (var snapshots = Files.list(workspace.resolve("versions"))) {
                check(snapshots.findAny().isPresent(), "Android signed-member delete must retain an owner-side recovery snapshot");
            }

            // New signed-member managed storage: destination receives the complete file directly and verifies its digest.
            Map<String, Object> androidManaged = control.placeManagedFile(androidNodeId,
                    desktopStorage.resolve("desktop-owned.txt"), "incoming/desktop-owned.txt");
            String androidManagedId = String.valueOf(androidManaged.get("fileId"));
            List<Map<String, Object>> androidManagedFiles = control.listRemoteManagedFiles(androidNodeId);
            check(androidManagedFiles.size() == 1 && androidManagedId.equals(androidManagedFiles.get(0).get("fileId")),
                    "desktop must list a managed file placed on Android; placement=" + androidManaged + "; files=" + androidManagedFiles);
            Path managedDownload = workspace.resolve("android-managed-download.txt");
            control.downloadRemoteManagedFile(androidNodeId, androidManagedId, managedDownload);
            check("Original file owned by desktop node".equals(Files.readString(managedDownload)),
                    "Android managed placement must be downloadable with SHA-256 verification");
            byte[] managedRange = control.readRemoteRange(androidNodeId, "MANAGED", androidManagedId, "", 5, 10);
            byte[] managedBytes = Files.readAllBytes(managedDownload);
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(managedBytes, 5, 15), managedRange),
                    "desktop must read verified byte ranges from Android managed storage");
            boolean managedOverwriteDenied = false;
            try { control.placeManagedFile(androidNodeId, desktopStorage.resolve("desktop-owned.txt"), "incoming/desktop-owned.txt"); }
            catch (java.io.IOException expected) { managedOverwriteDenied = true; }
            check(managedOverwriteDenied && androidManagedFiles.size() == 1,
                    "Android managed placement must reject overwrites");
            control.deleteRemoteManagedFile(androidNodeId, androidManagedId);
            check(control.listRemoteManagedFiles(androidNodeId).isEmpty(), "uploader can delete its managed file on Android");

            // Exercise the reverse direction with a payload spanning multiple 4 MiB chunks.
            byte[] desktopLargeBytes = new byte[9 * 1024 * 1024 + 53];
            for (int i = 0; i < desktopLargeBytes.length; i++) desktopLargeBytes[i] = (byte)(i * 13 + 9);
            Path desktopLargeSource = desktopStorage.resolve("desktop-large-source.bin");
            Files.write(desktopLargeSource, desktopLargeBytes);
            Map<String,Object> androidLargeReceipt = control.placeManagedFile(androidNodeId,
                    desktopLargeSource, "incoming/desktop-large-source.bin");
            String androidLargeId = String.valueOf(androidLargeReceipt.get("fileId"));
            byte[] androidLargeRange = control.readRemoteRange(androidNodeId, "MANAGED", androidLargeId,
                    "", 4 * 1024 * 1024 + 19, 4096);
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(desktopLargeBytes,
                            4 * 1024 * 1024 + 19, 4 * 1024 * 1024 + 19 + 4096), androidLargeRange),
                    "desktop-to-Android multi-chunk placement must preserve bytes across chunk boundaries");
            control.deleteRemoteManagedFile(androidNodeId, androidLargeId);

            // Desktop initiates pairing with Android. Android keeps incoming trust; desktop keeps outgoing token.
            String androidInvitation = android.createInvitation();
            Map<String, Object> paired = control.addPeer(androidBase, androidInvitation);
            check(androidNodeId.equals(paired.get("nodeId")), "desktop must pair with the Android node");
            check(hasPeer(control.listPeers(), androidNodeId, "OUTGOING"), "desktop must persist its outgoing Android peer");

            android.grant(desktopNodeId, "android-view.txt", "VIEW");
            Map<String, Object> viewShare = findShare(control.listRemoteShares(androidNodeId), "android-view.txt");
            Path viewDownload = workspace.resolve("android-view-download.txt");
            LocalControlClient.DownloadResult viewResult = control.downloadRemoteShare(
                    androidNodeId, String.valueOf(viewShare.get("shareId")), viewDownload);
            check("Original file owned by Android node".equals(Files.readString(viewDownload)), "desktop must download Android-owned file");
            check(viewResult.sha256() != null && viewResult.sizeBytes() == Files.size(viewDownload), "download must verify Android file bytes");

            boolean viewDeleteDenied = false;
            try { control.deleteRemoteShare(androidNodeId, String.valueOf(viewShare.get("shareId"))); }
            catch (java.io.IOException expected) { viewDeleteDenied = true; }
            check(viewDeleteDenied, "DOWNLOAD/VIEW peer must not delete the owner's original");
            check(Files.exists(androidStorage.resolve("android-view.txt")), "VIEW permission must preserve Android original");

            android.grant(desktopNodeId, "android-modify.txt", "MODIFY");
            Map<String, Object> modifyShare = findShare(control.listRemoteShares(androidNodeId), "android-modify.txt");
            control.deleteRemoteShare(androidNodeId, String.valueOf(modifyShare.get("shareId")));
            check(!Files.exists(androidStorage.resolve("android-modify.txt")), "DOWNLOAD+DELETE must delete the owner's original");
            Path androidVersions = workspace.resolve("versions");
            try (var snapshots = Files.list(androidVersions)) {
                check(snapshots.findAny().isPresent(), "authorized delete must create an owner-local recovery snapshot");
            }

            // Android initiates the reciprocal pairing using a new desktop invitation.
            String desktopInvitation = String.valueOf(control.createInvitation().get("code"));
            android.pairWith(desktopBase, desktopInvitation, desktopCertificate.toString());
            check(hasPeer(control.listPeers(), androidNodeId, "INCOMING"), "desktop must persist Android's incoming trust");
            Map<String, Object> desktopGrant = control.createGrant(androidNodeId, "desktop-owned.txt", "DOWNLOAD");
            check("DOWNLOAD".equals(((Map<?, ?>) desktopGrant.get("grant")).get("permission")), "local control must expose the new permission vocabulary");

            List<Map<String, Object>> androidShares = android.outgoingShares(desktopNodeId, desktopCertificate.toString());
            check(androidShares.size() == 1, "Android must list the desktop-owned grant");
            Path androidDownload = workspace.resolve("android-downloads/desktop-owned.txt");
            Files.createDirectories(androidDownload.getParent());
            android.downloadShare(desktopNodeId, String.valueOf(androidShares.get(0).get("shareId")),
                    androidDownload, desktopCertificate.toString());
            check("Original file owned by desktop node".equals(Files.readString(androidDownload)),
                    "Android must download desktop-owned file with SHA-256 verification");
            byte[] desktopPayload = Files.readAllBytes(desktopStorage.resolve("desktop-owned.txt"));
            PeerConnector.RangeResult desktopRange = android.readShareRange(desktopNodeId,
                    String.valueOf(androidShares.get(0).get("shareId")), 4, 13, desktopCertificate.toString());
            check(desktopRange.totalSize == desktopPayload.length, "Android must read desktop Content-Range metadata");
            check(java.util.Arrays.equals(java.util.Arrays.copyOfRange(desktopPayload, 4, 17), desktopRange.bytes),
                    "Android must verify byte-range reads from the desktop node");
            PeerConnector.RangeResult desktopEof = android.readShareRange(desktopNodeId,
                    String.valueOf(androidShares.get(0).get("shareId")), desktopPayload.length + 3, 5, desktopCertificate.toString());
            check(desktopEof.totalSize == desktopPayload.length && desktopEof.bytes.length == 0,
                    "Android must handle desktop unsatisfied-range responses without downloading the file");

            // Revoke both directions independently and verify each old token is rejected.
            android.revokePeer(desktopNodeId, "OUTGOING", desktopCertificate.toString());
            boolean androidOutgoingRevoked = false;
            try { android.outgoingShares(desktopNodeId, desktopCertificate.toString()); }
            catch (Exception expected) { androidOutgoingRevoked = true; }
            check(androidOutgoingRevoked, "Android outgoing revocation must invalidate its stored token");

            android.revokePeer(desktopNodeId, "INCOMING", desktopCertificate.toString());
            boolean desktopOutgoingRevoked = false;
            try { control.listRemoteShares(androidNodeId); }
            catch (java.io.IOException expected) { desktopOutgoingRevoked = true; }
            check(desktopOutgoingRevoked, "Android incoming revocation must invalidate the desktop's old token");

            System.out.println("PASS: Android approval-gated private-network enrollment against desktop; signed certificate verification; catalogue sync; signed heartbeat; membership identity persistence; replay rejection; signed-member Android reference listing/browse/stat/download/range/delete; Android owner recovery snapshots; direct managed placement/list/download/range/delete; writable eligible filesystem browse/stat/range/write/mkdir/rename/delete with PRIVATE, PROTECTED and consent enforcement; no-overwrite behavior; legacy reciprocal pairing compatibility; independent peer revocation.");
        } finally {
            if (android != null) {
                Thread closer = new Thread(android::close, "personalcloud-interop-android-close");
                closer.setDaemon(true);
                closer.start();
                closer.join(2500);
                if (closer.isAlive()) {
                    System.err.println("WARN: Android peer close exceeded 2.5 seconds; isolated test process will exit after cleanup.");
                }
            }
            if (desktop != null) {
                desktop.destroy();
                if (!desktop.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    desktop.destroyForcibly();
                    if (!desktop.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Desktop test node did not terminate after forcible shutdown.");
                    }
                }
            }
            deleteTree(workspace);
        }
        // This standalone integration process owns several TLS/HTTP executors. All test-owned
        // resources and child processes are closed above; halt avoids unrelated shutdown hooks.
        Runtime.getRuntime().halt(0);
    }

    private static SSLContext serverTls(Path identity, String password) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(identity)) { keys.load(input, password.toCharArray()); }
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, password.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, null);
        return context;
    }

    private static void waitForDesktop(String base, Process process, Path log, Path socket, Path desktopCertificate) throws Exception {
        long deadline = System.currentTimeMillis() + 20000;
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive()) throw new IllegalStateException("Desktop process exited: " + Files.readString(log));
            if (Files.exists(socket)) {
                try {
                    javax.net.ssl.HttpsURLConnection connection = (javax.net.ssl.HttpsURLConnection)
                            java.net.URI.create(base + "/node/info").toURL().openConnection();
                    connection.setSSLSocketFactory(trustClient(desktopCertificate).getSocketFactory());
                    connection.setConnectTimeout(1000);
                    connection.setReadTimeout(1000);
                    int status = connection.getResponseCode();
                    connection.disconnect();
                    if (status == 200) return;
                } catch (Exception ignored) { }
            }
            Thread.sleep(150);
        }
        throw new IllegalStateException("Desktop did not become ready: " + Files.readString(log));
    }

    private static SSLContext trustClient(Path certificatePath) throws Exception {
        java.security.KeyStore trust = java.security.KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        try (InputStream input = Files.newInputStream(certificatePath)) {
            java.security.cert.Certificate certificate = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
            trust.setCertificateEntry("personalcloud-desktop", certificate);
        }
        javax.net.ssl.TrustManagerFactory managers = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, managers.getTrustManagers(), new java.security.SecureRandom());
        return context;
    }

    private static Map<String, Object> findShare(List<Map<String, Object>> shares, String path) {
        return shares.stream().filter(item -> path.equals(item.get("path"))).findFirst()
                .orElseThrow(() -> new AssertionError("Share not found: " + path));
    }

    private static boolean hasPeer(List<Map<String, Object>> peers, String nodeId, String direction) {
        return peers.stream().anyMatch(peer -> nodeId.equals(peer.get("nodeId")) && direction.equals(peer.get("direction")));
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) { return socket.getLocalPort(); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?> map)) throw new AssertionError("Expected object response.");
        return (Map<String, Object>) map;
    }

    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }

    private static final class FakeExternalReferenceStore implements ExternalReferenceStore {
        private final byte[] data = "Bytes remain in the user's external Android document provider.".getBytes(StandardCharsets.UTF_8);
        private final Map<String,Map<String,Object>> grants = new LinkedHashMap<>();
        private boolean deleted;
        @Override public synchronized Map<String,Object> grantReference(String memberId,String selector,String permission) {
            String id="saf-grant-"+(grants.size()+1);
            Map<String,Object> grant=new LinkedHashMap<>();grant.put("memberId",memberId);grant.put("selector",selector);
            grant.put("permission",permission);grant.put("name","External Android folder");grant.put("createdAt",java.time.Instant.now().toString());
            grants.put(id,grant);
            return Map.of("grantId",id,"name",grant.get("name"),"kind","FOLDER","permission",permission,"available",true);
        }
        @Override public synchronized void revokeReference(String grantId) { grants.remove(grantId); }
        @Override public synchronized boolean hasGrant(String memberId,String grantId) { Map<String,Object> row=grants.get(grantId);return row!=null&&memberId.equals(row.get("memberId")); }
        @Override public synchronized boolean hasGrantForOwner(String grantId) { return grants.containsKey(grantId); }
        @Override public synchronized List<Map<String,Object>> listReferencesForMember(String memberId) {
            List<Map<String,Object>> result=new ArrayList<>();
            for(Map.Entry<String,Map<String,Object>> entry:grants.entrySet())if(memberId.equals(entry.getValue().get("memberId")))
                result.add(Map.of("grantId",entry.getKey(),"name",entry.getValue().get("name"),"kind","FOLDER","path","","permission",entry.getValue().get("permission"),"available",true));
            return result;
        }
        @Override public synchronized List<Map<String,Object>> browseReference(String memberId,String grantId,String relativeDirectory) {
            require(memberId,grantId);if(!relativeDirectory.isEmpty())return List.of();
            return List.of(Map.of("name","Existing cloud-provider file.txt","path","Existing cloud-provider file.txt","kind","FILE","size",data.length,"modified",1L));
        }
        @Override public synchronized Map<String,Object> statReference(String memberId,String grantId,String relativePath) throws Exception {
            Map<String,Object> row=new LinkedHashMap<>(browseReference(memberId,grantId,"").getFirst());
            row.put("permission",grants.get(grantId).get("permission"));
            row.put("sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)));return row;
        }
        @Override public synchronized NetworkReferenceContent openReference(String memberId,String grantId,String relativePath) {
            require(memberId,grantId);if(!relativePath.equals("Existing cloud-provider file.txt"))throw new IllegalArgumentException("Not found");
            return new NetworkReferenceContent(){public long size(){return data.length;}public InputStream openRange(long offset,long length){return new ByteArrayInputStream(data,(int)offset,(int)length);}};
        }
        @Override public synchronized Map<String,Object> deleteReference(String memberId,String grantId,String relativePath) {
            require(memberId,grantId);if(!"DOWNLOAD+DELETE".equals(grants.get(grantId).get("permission")))throw new SecurityException("Delete not authorized");
            deleted=true;return Map.of("deleted",true,"path",relativePath,"snapshotId","external-test-snapshot");
        }
        @Override public synchronized List<Map<String,Object>> searchReferences(String memberId,String query,int limit) { return List.of(); }
        synchronized boolean deleted(){return deleted;}
        byte[] payload(){return data.clone();}
        private void require(String memberId,String grantId){if(!hasGrant(memberId,grantId))throw new SecurityException("Grant does not belong to member");}
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (Exception ignored) { }
            });
        }
    }
}
