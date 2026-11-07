package dev.personalcloud.storage;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.policy.ApprovalRequiredException;
import dev.personalcloud.policy.FilesystemPolicyService;
import dev.personalcloud.policy.PolicyMode;
import dev.personalcloud.policy.PolicyOperation;
import dev.personalcloud.policy.ProtectionApprovalService;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Broad eligible-root access, consent, policy enforcement and safe-write tests. */
public final class EligibleStorageServiceTest {
    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-eligible-storage-test-");
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path storage = Files.createDirectory(workspace.resolve("storage"));
            Path root = Files.createDirectory(workspace.resolve("user-data"));
            Path documents = Files.createDirectory(root.resolve("Documents"));
            Path protectedDirectory = Files.createDirectory(root.resolve("Protected"));
            Path privateDirectory = Files.createDirectory(root.resolve("Private"));
            Files.writeString(documents.resolve("report.txt"), "hello PersonalCloud");
            Files.writeString(protectedDirectory.resolve("plan.txt"), "protected plan");
            Files.writeString(privateDirectory.resolve("keys.txt"), "private keys");
            Files.createSymbolicLink(root.resolve("link.txt"), documents.resolve("report.txt"));

            StateStore state = new StateStore(data);
            AppConfig config = new AppConfig("Storage Test", "node-storage-test", "127.0.0.1", 0,
                    data, storage, null, null, 64L * 1024 * 1024);
            FilesystemPolicyService policy = new FilesystemPolicyService(state);
            ProtectionApprovalService approvals = new ProtectionApprovalService();
            EligibleStorageService filesystem = new EligibleStorageService(config, state, policy, approvals, List.of(root));
            String member = "member-1";
            String rootId = String.valueOf(filesystem.rootsForOwner().get(0).get("rootId"));

            Path fakeHome = workspace.resolve("home").resolve("alice");
            check(EligibleStorageService.isSafeRootLocation(fakeHome, fakeHome),
                    "the current user's own home must be a safe eligible-root location");
            check(EligibleStorageService.isSafeRootLocation(fakeHome.resolve("Documents"), fakeHome),
                    "a directory inside the current user's home must be a safe eligible-root location");
            check(!EligibleStorageService.isSafeRootLocation(fakeHome.getParent(), fakeHome),
                    "a shared home parent must never be an eligible root");
            check(!EligibleStorageService.isSafeRootLocation(workspace, fakeHome),
                    "an ancestor of the current user's home must never be an eligible root");
            check(EligibleStorageService.isOwnedByCurrentUser(root),
                    "a current-user-owned eligible root must pass the ownership check");
            check(!EligibleStorageService.isOwnedByCurrentUser(workspace.resolve("missing-root")),
                    "the ownership check must fail closed when ownership cannot be established");
            Path userHome = Path.of(System.getProperty("user.home")).toAbsolutePath().normalize();
            Path sharedHomeParent = userHome.getParent();
            if (sharedHomeParent != null) {
                EligibleStorageService sharedParentService = new EligibleStorageService(config, state, policy, approvals,
                        List.of(sharedHomeParent));
                check(sharedParentService.rootsForOwner().isEmpty(),
                        "an explicitly configured shared home parent must be rejected");
            }

            expectFailure(() -> filesystem.rootsForMember(), "broad access must stay disabled until the owner consents");
            expectFailure(() -> filesystem.list(member, rootId, ""), "listing must fail before owner consent");
            Map<String, Object> consent = filesystem.grantConsent();
            check(Boolean.TRUE.equals(consent.get("consentGranted")), "owner consent must be recorded");
            check(filesystem.rootsForMember().size() == 1, "the eligible root must become visible after consent");

            List<Map<String, Object>> entries = filesystem.list(member, rootId, "");
            check(entries.stream().anyMatch(row -> "Documents".equals(row.get("name"))), "default access must list eligible directories");
            check(entries.stream().noneMatch(row -> "link.txt".equals(row.get("name"))), "symbolic links must never be listed");
            Map<String, Object> stat = filesystem.stat(member, rootId, "Documents/report.txt");
            check("FILE".equals(stat.get("kind")) && ((Number) stat.get("size")).longValue() == 19,
                    "stat must report ordinary file metadata");
            try (var input = filesystem.open(member, rootId, "Documents/report.txt")) {
                check(new String(input.readAllBytes(), StandardCharsets.UTF_8).equals("hello PersonalCloud"),
                        "default access must read the original file without copying it");
            }
            expectFailure(() -> filesystem.open(member, rootId, "link.txt"), "symbolic links must not be readable");
            expectFailure(() -> filesystem.stat(member, rootId, "../data"), "traversal must be rejected");

            Path credentials = Files.createDirectory(root.resolve(".ssh"));
            Files.writeString(credentials.resolve("id_test"), "credential secret");
            check(filesystem.list(member, rootId, "").stream().noneMatch(row -> ".ssh".equals(row.get("name"))),
                    "credential stores must never be listed, even when created after startup");
            expectFailure(() -> filesystem.stat(member, rootId, ".ssh/id_test"),
                    "credential stores must be denied even when created after startup");

            policy.set(rootId, "Private", PolicyMode.PRIVATE);
            check(filesystem.list(member, rootId, "").stream().noneMatch(row -> "Private".equals(row.get("name"))),
                    "private directories must disappear from remote listings");
            expectFailure(() -> filesystem.stat(member, rootId, "Private/keys.txt"), "private descendants must be denied");
            expectFailure(() -> filesystem.open(member, rootId, "Private/keys.txt"), "private files must not be readable");

            policy.set(rootId, "Protected", PolicyMode.PROTECTED);
            check(filesystem.list(member, rootId, "").stream().anyMatch(row -> "Protected".equals(row.get("name"))),
                    "protected directories must remain visible");
            try (var input = filesystem.open(member, rootId, "Protected/plan.txt")) {
                check(new String(input.readAllBytes(), StandardCharsets.UTF_8).equals("protected plan"),
                        "protected files must remain readable");
            }
            expectFailure(() -> filesystem.delete(member, rootId, "Protected/plan.txt", false, null),
                    "protected deletion must require approval");
            Map<String, Object> approval = filesystem.requestApproval(member, rootId, "Protected/plan.txt",
                    PolicyOperation.DELETE, 60);
            String approvalId = String.valueOf(approval.get("approvalId"));
            check("PENDING".equals(approval.get("state")), "remote approval requests must start pending");
            approvals.approve(approvalId);
            Map<String, Object> deleted = filesystem.delete(member, rootId, "Protected/plan.txt", false, approvalId);
            check(Boolean.TRUE.equals(deleted.get("deleted")), "an approved destructive operation must proceed");
            check(!Files.exists(protectedDirectory.resolve("plan.txt")), "deletion must act on the original file");

            byte[] payload = "remote write payload".getBytes(StandardCharsets.UTF_8);
            String payloadHash = sha256(payload);
            Map<String, Object> written = filesystem.write(member, rootId, "Documents/new.txt",
                    new ByteArrayInputStream(payload), payload.length, payloadHash, false, null);
            check(payloadHash.equals(written.get("sha256")), "write must return the verified content digest");
            check(java.util.Arrays.equals(Files.readAllBytes(documents.resolve("new.txt")), payload), "write must publish exact bytes");
            expectFailure(() -> filesystem.write(member, rootId, "Documents/new.txt",
                    new ByteArrayInputStream(payload), payload.length, payloadHash, false, null),
                    "write must not overwrite without authorization");

            policy.set(rootId, "Documents/new.txt", PolicyMode.PROTECTED);
            expectFailure(() -> filesystem.write(member, rootId, "Documents/new.txt",
                    new ByteArrayInputStream(payload), payload.length, payloadHash, true, null),
                    "protected overwrite must require approval");
            Map<String, Object> writeApproval = filesystem.requestApproval(member, rootId, "Documents/new.txt",
                    PolicyOperation.WRITE, 60);
            String writeApprovalId = String.valueOf(writeApproval.get("approvalId"));
            approvals.approve(writeApprovalId);
            filesystem.write(member, rootId, "Documents/new.txt", new ByteArrayInputStream(payload),
                    payload.length, payloadHash, true, writeApprovalId);
            check(java.util.Arrays.equals(Files.readAllBytes(documents.resolve("new.txt")), payload), "approved overwrite must publish exact bytes");
            policy.remove(rootId, "Documents/new.txt");

            byte[] bad = "bad".getBytes(StandardCharsets.UTF_8);
            expectFailure(() -> filesystem.write(member, rootId, "Documents/bad.txt",
                    new ByteArrayInputStream(bad), bad.length, "0".repeat(64), false, null),
                    "hash mismatch must be rejected");
            check(!Files.exists(documents.resolve("bad.txt")), "failed uploads must not publish partial files");

            filesystem.createDirectory(member, rootId, "Documents/New Folder");
            check(Files.isDirectory(documents.resolve("New Folder")), "remote directory creation must act on the original path");
            Map<String, Object> moved = filesystem.move(member, rootId, "Documents/new.txt", "Documents/New Folder/moved.txt",
                    false, null);
            check("Documents/New Folder/moved.txt".equals(moved.get("path")), "move must report the committed destination");
            check(!Files.exists(documents.resolve("new.txt")) && Files.exists(documents.resolve("New Folder/moved.txt")),
                    "move must rename the original file");
            filesystem.delete(member, rootId, "Documents/New Folder", true, null);
            check(!Files.exists(documents.resolve("New Folder")), "recursive delete must remove the directory tree");

            Path protectedTree = Files.createDirectory(root.resolve("ProtectedTree"));
            Files.writeString(protectedTree.resolve("secret.txt"), "protected descendant");
            policy.set(rootId, "ProtectedTree/secret.txt", PolicyMode.PROTECTED);
            expectFailure(() -> filesystem.delete(member, rootId, "ProtectedTree", true, null),
                    "recursive delete must not bypass a protected descendant");
            check(Files.exists(protectedTree.resolve("secret.txt")), "a blocked recursive delete must not remove protected data");
            expectFailure(() -> filesystem.move(member, rootId, "ProtectedTree", "ProtectedTreeMoved", false, null),
                    "a directory move must not bypass a protected descendant");
            check(Files.exists(protectedTree.resolve("secret.txt")), "a blocked directory move must leave protected data in place");
            policy.remove(rootId, "ProtectedTree/secret.txt");
            filesystem.delete(member, rootId, "ProtectedTree", true, null);

            Path moveSource = documents.resolve("move-source.txt");
            Path moveDestination = documents.resolve("move-destination.txt");
            Files.writeString(moveSource, "move source payload");
            Files.writeString(moveDestination, "old destination payload");
            policy.set(rootId, "Documents/move-source.txt", PolicyMode.PROTECTED);
            policy.set(rootId, "Documents/move-destination.txt", PolicyMode.PROTECTED);
            expectFailure(() -> filesystem.move(member, rootId, "Documents/move-source.txt",
                            "Documents/move-destination.txt", true, null),
                    "moving with protected source and destination must require approvals");
            Map<String, Object> sourceApproval = filesystem.requestApproval(member, rootId,
                    "Documents/move-source.txt", PolicyOperation.MOVE, 60);
            String sourceApprovalId = String.valueOf(sourceApproval.get("approvalId"));
            Map<String, Object> destinationApproval = filesystem.requestApproval(member, rootId,
                    "Documents/move-destination.txt", PolicyOperation.WRITE, 60);
            String destinationApprovalId = String.valueOf(destinationApproval.get("approvalId"));
            approvals.approve(sourceApprovalId);
            approvals.approve(destinationApprovalId);
            expectFailure(() -> filesystem.move(member, rootId, "Documents/move-source.txt",
                            "Documents/move-destination.txt", true, sourceApprovalId, ""),
                    "a source approval alone must not authorize a protected destination overwrite");
            check(Files.exists(moveSource) && Files.readString(moveDestination).equals("old destination payload"),
                    "a blocked dual-approval move must not modify either side");
            Map<String, Object> freshSourceApproval = filesystem.requestApproval(member, rootId,
                    "Documents/move-source.txt", PolicyOperation.MOVE, 60);
            String freshSourceApprovalId = String.valueOf(freshSourceApproval.get("approvalId"));
            approvals.approve(freshSourceApprovalId);
            Map<String, Object> dualApprovedMove = filesystem.move(member, rootId,
                    "Documents/move-source.txt", "Documents/move-destination.txt", true,
                    freshSourceApprovalId, destinationApprovalId);
            check("Documents/move-destination.txt".equals(dualApprovedMove.get("path")),
                    "a move with both approvals must report the committed destination");
            check(!Files.exists(moveSource) && Files.readString(moveDestination).equals("move source payload"),
                    "a move with both approvals must replace the protected destination");
            policy.remove(rootId, "Documents/move-source.txt");
            policy.remove(rootId, "Documents/move-destination.txt");

            expectFailure(() -> filesystem.stat(member, rootId, "data"), "PersonalCloud private state must stay excluded");
            expectFailure(() -> filesystem.stat(member, rootId, "storage"), "managed storage must stay excluded");

            filesystem.revokeConsent();
            expectFailure(() -> filesystem.rootsForMember(), "revoking consent must disable broad access immediately");
            expectFailure(() -> filesystem.stat(member, rootId, "Documents/report.txt"), "revoked consent must deny reads");
        } finally {
            try (var paths = Files.walk(workspace)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: eligible-root consent, default access, private/protected enforcement, approvals, safe writes, moves, deletes and exclusions.");
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (SecurityException | IllegalArgumentException | IllegalStateException expected) {
            // Expected: unsafe or unauthorized operations fail closed.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
