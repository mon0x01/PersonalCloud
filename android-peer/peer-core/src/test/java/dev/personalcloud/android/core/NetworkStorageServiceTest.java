package dev.personalcloud.android.core;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Automated authorization, persistence and integrity tests for Android network storage. */
public final class NetworkStorageServiceTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("pc-android-network-storage-");
        try {
            Path local = Files.createDirectory(workspace.resolve("node-storage"));
            Path docs = Files.createDirectory(local.resolve("Docs"));
            Files.writeString(docs.resolve("readme.txt"), "Android referenced content", StandardCharsets.UTF_8);
            Files.writeString(docs.resolve("delete-me.txt"), "Snapshot before delete", StandardCharsets.UTF_8);
            Path nested = Files.createDirectory(docs.resolve("Nested"));
            Files.writeString(nested.resolve("child.txt"), "nested content", StandardCharsets.UTF_8);

            MemoryStateStore state = new MemoryStateStore();
            NetworkStorageService storage = new NetworkStorageService("android-node-0001", local, state);
            Map<String, Object> folderGrant = storage.grantReference("desktop-node-0001", "Docs", "DOWNLOAD");
            String folderGrantId = String.valueOf(folderGrant.get("grantId"));
            check(storage.listReferencesForMember("desktop-node-0001").size() == 1, "grant is visible to intended member");
            check(storage.listReferencesForMember("other-node-0001").isEmpty(), "grant is not visible to another member");
            List<Map<String, Object>> entries = storage.browseReference("desktop-node-0001", folderGrantId, "");
            check(entries.size() == 3, "folder grant browses direct entries only");
            Map<String, Object> nestedDirectory = entries.stream().filter(row -> "Nested".equals(row.get("name"))).findFirst().orElseThrow();
            check("Nested".equals(nestedDirectory.get("path")), "browse paths are relative to the granted folder");
            List<Map<String, Object>> nestedEntries = storage.browseReference("desktop-node-0001", folderGrantId, "Nested");
            check(nestedEntries.size() == 1 && "child.txt".equals(nestedEntries.get(0).get("name"))
                    && "Nested/child.txt".equals(nestedEntries.get(0).get("path")),
                    "nested folder browsing must produce paths that can be passed back to stat and read");
            Map<String, Object> nestedStat = storage.statReference("desktop-node-0001", folderGrantId, "Nested/child.txt");
            check("Nested/child.txt".equals(nestedStat.get("path")), "nested stat must preserve grant-relative path semantics");
            Map<String, Object> readme = storage.statReference("desktop-node-0001", folderGrantId, "readme.txt");
            check("FILE".equals(readme.get("kind")) && "Android referenced content".equals(Files.readString(
                    storage.openReference("desktop-node-0001", folderGrantId, "readme.txt"))), "file stat and zero-copy open resolve original bytes");
            List<Map<String, Object>> nestedSearch = storage.searchReferences("desktop-node-0001", "child", 20);
            check(nestedSearch.size() == 1 && "Nested/child.txt".equals(nestedSearch.get(0).get("path")),
                    "search results must use the same grant-relative paths as browse and stat");
            boolean wrongMemberDenied = false;
            try { storage.openReference("other-node-0001", folderGrantId, "readme.txt"); }
            catch (SecurityException expected) { wrongMemberDenied = true; }
            check(wrongMemberDenied, "another member cannot access a grant identifier");
            boolean downloadOnlyDeleteDenied = false;
            try { storage.deleteReference("desktop-node-0001", folderGrantId, "readme.txt"); }
            catch (SecurityException expected) { downloadOnlyDeleteDenied = true; }
            check(downloadOnlyDeleteDenied && Files.exists(docs.resolve("readme.txt")), "DOWNLOAD does not authorize deletion");

            Map<String, Object> deleteGrant = storage.grantReference("desktop-node-0001", "Docs/delete-me.txt", "DOWNLOAD+DELETE");
            Map<String, Object> deleted = storage.deleteReference("desktop-node-0001", String.valueOf(deleteGrant.get("grantId")), "");
            check(Boolean.TRUE.equals(deleted.get("deleted")) && !Files.exists(docs.resolve("delete-me.txt")), "DOWNLOAD+DELETE removes the selected original");
            String snapshotId = String.valueOf(deleted.get("snapshotId"));
            Path snapshot = workspace.resolve("versions").resolve(snapshotId + ".blob");
            check(Files.exists(snapshot) && "Snapshot before delete".equals(Files.readString(snapshot)), "authorized deletion keeps an owner-side recovery snapshot");
            List<Map<String, Object>> recoveryPoints = storage.listRecoverySnapshots("android-node-0001");
            check(recoveryPoints.size() == 1 && Boolean.TRUE.equals(recoveryPoints.get(0).get("available")),
                    "owner-local recovery snapshots are enumerable without exposing them as a network route");
            boolean remoteSnapshotEnumerationDenied = false;
            try { storage.listRecoverySnapshots("desktop-node-0001"); }
            catch (SecurityException expected) { remoteSnapshotEnumerationDenied = true; }
            check(remoteSnapshotEnumerationDenied, "network members cannot enumerate owner-local recovery history");
            boolean snapshotTamperingRejected = false;
            byte[] intactSnapshot = Files.readAllBytes(snapshot);
            Files.writeString(snapshot, "tampered recovery bytes", StandardCharsets.UTF_8);
            try { storage.restoreRecoverySnapshot("android-node-0001", snapshotId); }
            catch (SecurityException expected) { snapshotTamperingRejected = true; }
            check(snapshotTamperingRejected && !Files.exists(docs.resolve("delete-me.txt")),
                    "tampered recovery snapshots cannot be restored");
            Files.write(snapshot, intactSnapshot);
            boolean remoteRestoreDenied = false;
            try { storage.restoreRecoverySnapshot("desktop-node-0001", snapshotId); }
            catch (SecurityException expected) { remoteRestoreDenied = true; }
            check(remoteRestoreDenied, "network members cannot restore owner-local recovery snapshots");
            Map<String, Object> restoredSnapshot = storage.restoreRecoverySnapshot("android-node-0001", snapshotId);
            check(Boolean.TRUE.equals(restoredSnapshot.get("restored"))
                            && "Snapshot before delete".equals(Files.readString(docs.resolve("delete-me.txt"))),
                    "owner can restore the original file from a SHA-256-verified recovery snapshot");
            boolean restoreOverwriteRejected = false;
            try { storage.restoreRecoverySnapshot("android-node-0001", snapshotId); }
            catch (IllegalArgumentException expected) { restoreOverwriteRejected = true; }
            check(restoreOverwriteRejected && "Snapshot before delete".equals(Files.readString(docs.resolve("delete-me.txt"))),
                    "recovery never overwrites a file that appeared at the original path");

            for (int index = 0; index < 22; index++) {
                Path retentionFile = docs.resolve("retention.txt");
                Files.writeString(retentionFile, "snapshot " + index, StandardCharsets.UTF_8);
                Map<String, Object> retentionGrant = storage.grantReference("desktop-node-0001", "Docs/retention.txt", "DOWNLOAD+DELETE");
                storage.deleteReference("desktop-node-0001", String.valueOf(retentionGrant.get("grantId")), "");
            }
            List<Map<String, Object>> boundedSnapshots = storage.listRecoverySnapshots("android-node-0001");
            long retainedForPath = boundedSnapshots.stream().filter(row -> "Docs/retention.txt".equals(row.get("path"))).count();
            check(retainedForPath == 20,
                    "Android recovery retention must keep the newest 20 snapshots for a path and prune older blobs");

            byte[] payload = "managed bytes sent directly to Android".getBytes(StandardCharsets.UTF_8);
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
            Map<String, Object> managed = storage.receiveManagedFile("desktop-node-0001", "Incoming/desktop.bin",
                    new ByteArrayInputStream(payload), payload.length, payload.length, digest);
            String managedId = String.valueOf(managed.get("fileId"));
            check(Files.exists(workspace.resolve("distributed-storage/Incoming/desktop.bin")), "managed file is stored under the separate managed root");
            check(storage.listManagedFilesForMember("desktop-node-0001").size() == 1, "uploader can list its managed file");
            check(storage.listManagedFilesForMember("other-node-0001").size() == 1, "other authenticated members can discover files in the same network-owned storage");
            check(java.util.Arrays.equals(payload, Files.readAllBytes(storage.openManagedFile("desktop-node-0001", managedId))), "managed bytes are identical after verified receive");
            check(java.util.Arrays.equals(payload, Files.readAllBytes(storage.openManagedFile("other-node-0001", managedId))),
                    "another authenticated network member can open a managed file stored on this node");
            check("FILE".equals(storage.statManagedFile("other-node-0001", managedId).get("kind")),
                    "another authenticated member can stat a network-managed file");

            boolean badDigestRejected = false;
            try { storage.receiveManagedFile("desktop-node-0001", "Incoming/tampered.bin",
                    new ByteArrayInputStream(payload), payload.length, payload.length, "0".repeat(64)); }
            catch (SecurityException expected) { badDigestRejected = true; }
            check(badDigestRejected && !Files.exists(workspace.resolve("distributed-storage/Incoming/tampered.bin")), "bad digest leaves no committed managed file");
            boolean overwriteRejected = false;
            try { storage.receiveManagedFile("desktop-node-0001", "Incoming/desktop.bin",
                    new ByteArrayInputStream(payload), payload.length, payload.length, digest); }
            catch (IllegalArgumentException expected) { overwriteRejected = true; }
            check(overwriteRejected && java.util.Arrays.equals(payload,
                    Files.readAllBytes(workspace.resolve("distributed-storage/Incoming/desktop.bin"))), "managed placement never overwrites existing data");
            Path concurrentTarget = workspace.resolve("distributed-storage/Incoming/concurrent.txt");
            java.io.InputStream racingInput = new java.io.FilterInputStream(new ByteArrayInputStream(payload)) {
                private boolean inserted;
                @Override public int read(byte[] bytes, int offset, int length) throws java.io.IOException {
                    if (!inserted) {
                        inserted = true;
                        try { Files.writeString(concurrentTarget, "concurrent owner file", StandardCharsets.UTF_8); }
                        catch (java.io.IOException failure) { throw failure; }
                    }
                    return super.read(bytes, offset, length);
                }
            };
            boolean concurrentOverwriteRejected = false;
            try { storage.receiveManagedFile("desktop-node-0001", "Incoming/concurrent.txt",
                    racingInput, payload.length, payload.length, digest); }
            catch (IllegalStateException expected) { concurrentOverwriteRejected = true; }
            check(concurrentOverwriteRejected && "concurrent owner file".equals(Files.readString(concurrentTarget)),
                    "a destination created while the upload is streaming must never be overwritten");
            boolean traversalRejected = false;
            try { storage.receiveManagedFile("desktop-node-0001", "../escape.bin",
                    new ByteArrayInputStream(payload), payload.length, payload.length, digest); }
            catch (IllegalArgumentException expected) { traversalRejected = true; }
            check(traversalRejected && !Files.exists(workspace.resolve("escape.bin")), "managed path traversal is rejected");

            NetworkStorageService restored = new NetworkStorageService("android-node-0001", local, state);
            check(restored.listReferencesForMember("desktop-node-0001").size() == 1,
                    "folder grants persist while deleted single-file grants are retired across service reconstruction");
            check(restored.listManagedFilesForMember("desktop-node-0001").size() == 1
                    && restored.listManagedFilesForMember("other-node-0001").size() == 1,
                    "managed records persist and remain visible to every authenticated member after service reconstruction");
            selectedManagedRootTest(workspace);
            managedBackendContractTest(workspace);
            System.out.println("PASS: Android signed-network storage; member-scoped reference grants; browse/stat/search; DOWNLOAD vs DOWNLOAD+DELETE; bounded owner-local recovery snapshots; snapshot tamper rejection and verified restore; no-overwrite recovery and managed receive; separate managed root; network-wide managed listing/stat/open; persistence; traversal rejection.");
        } finally {
            try (var paths = Files.walk(workspace)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }

    private static void selectedManagedRootTest(Path workspace) throws Exception {
        Path nodeRoot = Files.createDirectory(workspace.resolve("placement-node-root"));
        Path selectedRoot = Files.createDirectory(workspace.resolve("selected-removable-volume"));
        MemoryStateStore state = new MemoryStateStore();
        NetworkStorageService selected = new NetworkStorageService(
                "android-node-placement", nodeRoot, selectedRoot, "external-uuid:test-volume", state);

        byte[] payload = "stored on selected volume".getBytes(StandardCharsets.UTF_8);
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        Map<String, Object> receipt = selected.receiveManagedFile(
                "desktop-node-placement", "Placement/selected.bin",
                new ByteArrayInputStream(payload), payload.length, payload.length, digest);
        String fileId = String.valueOf(receipt.get("fileId"));
        Path stored = selectedRoot.resolve("Placement/selected.bin");

        check(Files.exists(stored), "managed upload is written to the explicitly selected volume");
        check(!Files.exists(workspace.resolve("distributed-storage/Placement/selected.bin")),
                "selected-volume upload does not silently write to the internal default root");
        check(java.util.Arrays.equals(payload, Files.readAllBytes(selected.openManagedFile("desktop-node-placement", fileId))),
                "selected-volume managed file can be reopened and verified");

        NetworkStorageService reopened = new NetworkStorageService(
                "android-node-placement", nodeRoot, selectedRoot, "external-uuid:test-volume", state);
        check(reopened.listManagedFilesForMember("other-authenticated-member").size() == 1,
                "selected storage identity and managed-file metadata survive service reconstruction");

        boolean volumeSwitchRejected = false;
        Path differentVolume = workspace.resolve("different-volume");
        try {
            new NetworkStorageService("android-node-placement", nodeRoot,
                    differentVolume, "external-uuid:other-volume", state);
        } catch (IllegalStateException expected) {
            volumeSwitchRejected = true;
        }
        check(volumeSwitchRejected && !Files.exists(differentVolume),
                "changing a selected volume cannot hide registered files or create a misleading replacement root");
    }

    private static void managedBackendContractTest(Path workspace) throws Exception {
        Path nodeRoot = Files.createDirectory(workspace.resolve("backend-contract-node"));
        MemoryStateStore state = new MemoryStateStore();
        FakeManagedBackend backend = new FakeManagedBackend("saf:contract-test");
        NetworkStorageService service = new NetworkStorageService(
                "android-saf-contract", nodeRoot, null, backend.storageId(), state, backend);
        byte[] payload = "SAF managed backend range verification".getBytes(StandardCharsets.UTF_8);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        Map<String,Object> receipt = service.receiveManagedFile("desktop-saf-contract", "Usb/managed.bin",
                new ByteArrayInputStream(payload), payload.length, payload.length, hash);
        String fileId = String.valueOf(receipt.get("fileId"));
        check("Usb/managed.bin".equals(receipt.get("path")), "SAF backend catalogue retains the logical managed path");
        check("SAF".equals(receipt.get("storageKind")), "SAF backend receipt identifies provider-backed storage");
        check(service.listManagedFilesForMember("desktop-saf-contract").size() == 1,
                "SAF-backed managed file is listed through the common catalogue");
        check(service.statManagedFile("desktop-saf-contract", fileId).get("sha256").equals(hash),
                "SAF-backed managed file exposes the verified SHA-256 metadata");
        try (InputStream range = service.openManagedContent("desktop-saf-contract", fileId).openRange(4, 7)) {
            check("managed".equals(new String(range.readAllBytes(), StandardCharsets.UTF_8)),
                    "SAF-backed managed content supports exact byte-range reads");
        }
        boolean duplicateDenied = false;
        try {
            service.receiveManagedFile("desktop-saf-contract", "Usb/managed.bin",
                    new ByteArrayInputStream(payload), payload.length, payload.length, hash);
        } catch (IllegalArgumentException expected) { duplicateDenied = true; }
        check(duplicateDenied, "SAF backend never overwrites a logical destination");
        boolean tamperDenied = false;
        try {
            service.receiveManagedFile("desktop-saf-contract", "Usb/tampered.bin",
                    new ByteArrayInputStream(payload), payload.length, payload.length, "0".repeat(64));
        } catch (SecurityException expected) { tamperDenied = true; }
        check(tamperDenied && backend.fileCount() == 1,
                "SAF backend aborts and removes a failed-digest upload");
        FakeManagedBackend restartedBackend = new FakeManagedBackend("saf:contract-restart");
        boolean identityGuarded = false;
        try {
            new NetworkStorageService("android-saf-contract", nodeRoot, null,
                    restartedBackend.storageId(), state, restartedBackend);
        } catch (IllegalStateException expected) { identityGuarded = true; }
        check(identityGuarded, "persisted managed-storage identity cannot silently change while managed files exist");
        service.deleteManagedFile("desktop-saf-contract", fileId);
        check(backend.fileCount() == 0 && service.listManagedFilesForMember("desktop-saf-contract").isEmpty(),
                "SAF backend deletion removes the provider object and catalogue record");
    }

    private static final class FakeManagedBackend implements ManagedStorageBackend {
        private final String id;
        private final java.util.Map<String,byte[]> files = new java.util.LinkedHashMap<>();
        FakeManagedBackend(String id) { this.id = id; }
        @Override public String storageId() { return id; }
        int fileCount() { return files.size(); }
        @Override public UploadSession beginUpload(String fileId, String relativePath, long expectedSize) {
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            return new UploadSession() {
                private boolean done;
                @Override public OutputStream outputStream() { return output; }
                @Override public String commit() throws Exception {
                    if(done)throw new IllegalStateException("Upload already finished.");
                    if(files.containsKey(fileId))throw new IllegalStateException("No overwrite.");
                    files.put(fileId,output.toByteArray());done=true;return "memory:"+fileId;
                }
                @Override public void abort() { if(!done){done=true;output.reset();} }
                @Override public void close() { abort(); }
            };
        }
        private String idFrom(String key) {
            if(key==null||!key.startsWith("memory:"))throw new SecurityException("Invalid fake key.");
            return key.substring(7);
        }
        @Override public Map<String,Object> stat(String key) {
            byte[] bytes=files.get(idFrom(key));
            if(bytes==null)throw new IllegalArgumentException("Missing fake object.");
            return Map.of("name","fake.blob","size",(long)bytes.length,"modified","");
        }
        @Override public ExternalReferenceStore.NetworkReferenceContent open(String key) {
            byte[] bytes=files.get(idFrom(key));
            if(bytes==null)throw new IllegalArgumentException("Missing fake object.");
            return new ExternalReferenceStore.NetworkReferenceContent() {
                @Override public long size(){return bytes.length;}
                @Override public InputStream openRange(long offset,long length) {
                    if(offset<0||length<0||offset>bytes.length||length>bytes.length-offset)throw new IllegalArgumentException("Bad range.");
                    return new ByteArrayInputStream(bytes,(int)offset,(int)length);
                }
            };
        }
        @Override public void delete(String key) { files.remove(idFrom(key)); }
        @Override public void reconcile(java.util.Collection<String> active) { }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
