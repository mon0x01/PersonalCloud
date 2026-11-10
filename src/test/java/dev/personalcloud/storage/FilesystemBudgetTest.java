package dev.personalcloud.storage;

import dev.personalcloud.core.AppConfig;
import dev.personalcloud.core.StateStore;
import dev.personalcloud.policy.FilesystemPolicyService;
import dev.personalcloud.policy.ProtectionApprovalService;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Durable per-member write-byte and delete-entry budget tests. */
public final class FilesystemBudgetTest {
    public static void main(String[] args) throws Exception {
        writeAndDeleteBudgets();
        dayRolloverResetsLedger();
        System.out.println("PASS: durable per-member write-byte and delete-entry budgets, reservations, "
                + "per-member overrides, failed-write release, recursive-delete preflight and UTC day rollover.");
    }

    private static void writeAndDeleteBudgets() throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-filesystem-budget-");
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path storage = Files.createDirectory(workspace.resolve("storage"));
            Path root = Files.createDirectory(workspace.resolve("files"));
            Files.createDirectory(root.resolve("Documents"));
            Files.createDirectory(root.resolve("Trash"));
            StateStore state = new StateStore(data);
            AppConfig config = new AppConfig("Budget Test", "budget-node", "127.0.0.1", 0,
                    data, storage, null, null, 1024L * 1024);
            FilesystemPolicyService policy = new FilesystemPolicyService(state);
            ProtectionApprovalService approvals = new ProtectionApprovalService();
            FilesystemBudgetService budgets = new FilesystemBudgetService(state, 100, 3);
            EligibleStorageService filesystem = new EligibleStorageService(config, state, policy, approvals,
                    List.of(root), budgets);
            filesystem.grantConsent();
            String rootId = String.valueOf(filesystem.rootsForOwner().get(0).get("rootId"));
            String member = "member-one";

            byte[] sixty = bytes(60, 1);
            filesystem.write(member, rootId, "Documents/a.bin", new ByteArrayInputStream(sixty),
                    sixty.length, sha256(sixty), false, null);
            byte[] fifty = bytes(50, 2);
            expectBudget(() -> filesystem.write(member, rootId, "Documents/b.bin",
                    new ByteArrayInputStream(fifty), fifty.length, sha256(fifty), false, null),
                    "a write over the daily byte budget must be rejected");
            check(!Files.exists(root.resolve("Documents/b.bin")),
                    "a rejected over-budget write must not publish a file");

            byte[] zero = new byte[0];
            filesystem.write(member, rootId, "Documents/empty.bin", new ByteArrayInputStream(zero),
                    0, sha256(zero), false, null);
            byte[] forty = bytes(40, 3);
            filesystem.write(member, rootId, "Documents/c.bin", new ByteArrayInputStream(forty),
                    forty.length, sha256(forty), false, null);
            byte[] one = bytes(1, 4);
            expectBudget(() -> filesystem.write(member, rootId, "Documents/d.bin",
                    new ByteArrayInputStream(one), one.length, sha256(one), false, null),
                    "the byte budget must remain exhausted after reaching the limit");
            Map<String, Object> status = budgets.status(member);
            check(number(status, "writeBytesUsed") == 100,
                    "the ledger must record exactly the published bytes");
            check(number(status, "writeBytesRemaining") == 0,
                    "the remaining byte budget must be zero at the limit");

            byte[] other = bytes(60, 5);
            filesystem.write("member-two", rootId, "Documents/other.bin", new ByteArrayInputStream(other),
                    other.length, sha256(other), false, null);
            check(number(budgets.status("member-two"), "writeBytesUsed") == 60,
                    "budgets must be isolated per member");

            FilesystemBudgetService reopened = new FilesystemBudgetService(state, 100, 3);
            check(number(reopened.status(member), "writeBytesUsed") == 100,
                    "the budget ledger must survive process restart");
            EligibleStorageService reopenedFilesystem = new EligibleStorageService(config, state, policy,
                    approvals, List.of(root), reopened);
            expectBudget(() -> reopenedFilesystem.write(member, rootId, "Documents/e.bin",
                    new ByteArrayInputStream(one), one.length, sha256(one), false, null),
                    "a reopened node must still enforce the persisted budget");

            budgets.setPolicy(member, 200, 10);
            byte[] hundred = bytes(100, 6);
            filesystem.write(member, rootId, "Documents/f.bin", new ByteArrayInputStream(hundred),
                    hundred.length, sha256(hundred), false, null);
            check(number(budgets.status(member), "writeBytesPerDay") == 200,
                    "a per-member override must raise the effective limit");
            budgets.clearPolicy(member);
            expectBudget(() -> filesystem.write(member, rootId, "Documents/g.bin",
                    new ByteArrayInputStream(one), one.length, sha256(one), false, null),
                    "clearing an override must restore the default limit");

            budgets.setPolicy("member-three", 30, 3);
            byte[] thirty = bytes(30, 7);
            expectFailure(() -> filesystem.write("member-three", rootId, "Documents/bad.bin",
                    new ByteArrayInputStream(thirty), thirty.length, sha256(bytes(30, 8)), false, null),
                    "a digest mismatch must fail the upload");
            filesystem.write("member-three", rootId, "Documents/good.bin", new ByteArrayInputStream(thirty),
                    thirty.length, sha256(thirty), false, null);
            check(number(budgets.status("member-three"), "writeBytesUsed") == 30,
                    "a failed verification must release its write reservation");

            budgets.setPolicy("member-four", 0, 0);
            byte[] large = bytes(1000, 9);
            filesystem.write("member-four", rootId, "Documents/unlimited.bin", new ByteArrayInputStream(large),
                    large.length, sha256(large), false, null);
            check(number(budgets.status("member-four"), "writeBytesPerDay") == 0,
                    "a zero limit must mean unlimited");

            for (int index = 1; index <= 4; index++) {
                Files.writeString(root.resolve("Trash/file-" + index + ".txt"), "delete me " + index,
                        StandardCharsets.UTF_8);
            }
            expectBudget(() -> filesystem.delete("member-two", rootId, "Trash", true, null),
                    "a recursive delete that exceeds the entry budget must fail before deleting");
            for (int index = 1; index <= 4; index++) {
                check(Files.exists(root.resolve("Trash/file-" + index + ".txt")),
                        "a rejected recursive delete must leave every entry in place");
            }
            filesystem.delete("member-two", rootId, "Trash/file-1.txt", false, null);
            filesystem.delete("member-two", rootId, "Trash/file-2.txt", false, null);
            filesystem.delete("member-two", rootId, "Trash/file-3.txt", false, null);
            expectBudget(() -> filesystem.delete("member-two", rootId, "Trash/file-4.txt", false, null),
                    "the delete-entry budget must reject one more deletion");
            check(Files.exists(root.resolve("Trash/file-4.txt")),
                    "the over-budget deletion must not remove the file");
            check(number(budgets.status("member-two"), "deleteEntriesUsed") == 3,
                    "the delete ledger must record the accepted deletions");

            List<Map<String, Object>> statuses = budgets.statuses();
            check(statuses.stream().anyMatch(row -> member.equals(row.get("memberId"))),
                    "the owner budget listing must include active member usage");

            expectFailure(() -> budgets.setPolicy("member-one", -1, 1),
                    "negative budget overrides must be rejected");
        } finally {
            deleteTree(workspace);
        }
    }

    private static void dayRolloverResetsLedger() throws Exception {
        Path workspace = Files.createTempDirectory("personalcloud-filesystem-budget-rollover-");
        try {
            Path data = Files.createDirectory(workspace.resolve("data"));
            Path storage = Files.createDirectory(workspace.resolve("storage"));
            Path root = Files.createDirectory(workspace.resolve("files"));
            Files.createDirectory(root.resolve("Documents"));
            StateStore state = new StateStore(data);
            AppConfig config = new AppConfig("Rollover Test", "rollover-node", "127.0.0.1", 0,
                    data, storage, null, null, 1024L * 1024);
            AtomicReference<LocalDate> day = new AtomicReference<>(LocalDate.of(2026, 11, 10));
            FilesystemBudgetService budgets = new FilesystemBudgetService(state, 50, 2, day::get);
            EligibleStorageService filesystem = new EligibleStorageService(config, state,
                    new FilesystemPolicyService(state), new ProtectionApprovalService(), List.of(root), budgets);
            filesystem.grantConsent();
            String rootId = String.valueOf(filesystem.rootsForOwner().get(0).get("rootId"));
            byte[] fifty = bytes(50, 10);
            filesystem.write("rollover-member", rootId, "Documents/one.bin", new ByteArrayInputStream(fifty),
                    fifty.length, sha256(fifty), false, null);
            byte[] one = bytes(1, 11);
            expectBudget(() -> filesystem.write("rollover-member", rootId, "Documents/two.bin",
                    new ByteArrayInputStream(one), one.length, sha256(one), false, null),
                    "the same UTC day must remain exhausted");
            day.set(day.get().plusDays(1));
            filesystem.write("rollover-member", rootId, "Documents/two.bin", new ByteArrayInputStream(fifty),
                    fifty.length, sha256(fifty), false, null);
            check(number(budgets.status("rollover-member"), "writeBytesUsed") == 50,
                    "a new UTC day must start with a fresh budget");
        } finally {
            deleteTree(workspace);
        }
    }

    private static byte[] bytes(int size, int seed) {
        byte[] result = new byte[size];
        for (int index = 0; index < size; index++) result[index] = (byte) ((index * 31 + seed) & 0xff);
        return result;
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static long number(Map<String, Object> row, String key) {
        return ((Number) row.get(key)).longValue();
    }

    private static void expectBudget(ThrowingRunnable operation, String message) throws Exception {
        try {
            operation.run();
            throw new AssertionError(message);
        } catch (FilesystemBudgetExceededException expected) { }
    }

    private static void expectFailure(ThrowingRunnable operation, String message) throws Exception {
        try {
            operation.run();
            throw new AssertionError(message);
        } catch (FilesystemBudgetExceededException unexpected) {
            throw new AssertionError("Unexpected budget rejection: " + message, unexpected);
        } catch (Exception expected) { }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (Exception ignored) { }
            });
        }
    }

    @FunctionalInterface private interface ThrowingRunnable { void run() throws Exception; }
}
