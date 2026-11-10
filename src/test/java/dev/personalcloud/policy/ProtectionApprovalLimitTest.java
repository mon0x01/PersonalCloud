package dev.personalcloud.policy;

/** Pending protection-approval bounds tests. */
public final class ProtectionApprovalLimitTest {
    private static final int PER_MEMBER_LIMIT = 32;
    private static final int TOTAL_LIMIT = 256;

    public static void main(String[] args) throws Exception {
        ProtectionApprovalService perMember = new ProtectionApprovalService();
        for (int i = 0; i < PER_MEMBER_LIMIT; i++) {
            perMember.request("member-1", "root-a", "Protected/file-" + i + ".txt", PolicyOperation.DELETE, 60);
        }
        expectFailure(() -> perMember.request("member-1", "root-a", "Protected/overflow.txt",
                        PolicyOperation.DELETE, 60),
                "one member must not create unbounded pending approvals");
        perMember.request("member-2", "root-a", "Protected/other.txt", PolicyOperation.DELETE, 60);

        ProtectionApprovalService total = new ProtectionApprovalService();
        for (int member = 0; member < TOTAL_LIMIT / PER_MEMBER_LIMIT; member++) {
            for (int i = 0; i < PER_MEMBER_LIMIT; i++) {
                total.request("member-" + member, "root-a", "Protected/file-" + i + ".txt",
                        PolicyOperation.DELETE, 60);
            }
        }
        expectFailure(() -> total.request("member-overflow", "root-a", "Protected/overflow.txt",
                        PolicyOperation.DELETE, 60),
                "the node must not create unbounded pending approvals across members");

        // Terminal approvals still release their slot only after retention, so
        // the bound applies to pending work rather than lifetime history.
        ProtectionApprovalService released = new ProtectionApprovalService();
        for (int i = 0; i < PER_MEMBER_LIMIT; i++) {
            String id = String.valueOf(released.request("member-1", "root-a", "Protected/file-" + i + ".txt",
                    PolicyOperation.DELETE, 60).get("approvalId"));
            released.deny(id);
        }
        released.request("member-1", "root-a", "Protected/new.txt", PolicyOperation.DELETE, 60);

        System.out.println("PASS: pending protection approvals are bounded per member and per node; terminal approvals release capacity.");
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalStateException expected) {
            // Expected: bounded approval capacity fails closed.
        }
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
