package dev.personalcloud.policy;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/** Short-lived, single-use protection approval tests. */
public final class ProtectionApprovalServiceTest {
    public static void main(String[] args) throws Exception {
        ProtectionApprovalService service = new ProtectionApprovalService();

        expectFailure(() -> service.request("member-1", "root-a", "Documents", PolicyOperation.READ, 0),
                "non-destructive operations must not require protection approval");

        Map<String, Object> requested = service.request("member-1", "root-a", "/Protected/", PolicyOperation.DELETE, 120);
        String approvalId = (String) requested.get("approvalId");
        check(approvalId != null && !approvalId.isBlank(), "approval request must return an ID");
        check("PENDING".equals(requested.get("state")), "new approvals must be pending");
        check("Protected".equals(requested.get("path")), "approval paths must be normalized");

        check(!service.consume(approvalId, "member-1", "root-a", "Protected", PolicyOperation.DELETE),
                "pending approvals must not authorize an operation");
        service.approve(approvalId);
        check("APPROVED".equals(service.status(approvalId).get("state")), "approved state must be observable");
        check(!service.consume(approvalId, "member-2", "root-a", "Protected", PolicyOperation.DELETE),
                "approvals must be bound to the requesting member");
        check(!service.consume(approvalId, "member-1", "root-b", "Protected", PolicyOperation.DELETE),
                "approvals must be bound to the eligible root");
        check(!service.consume(approvalId, "member-1", "root-a", "Protected/other.txt", PolicyOperation.DELETE),
                "approvals must be bound to the exact path");
        check(!service.consume(approvalId, "member-1", "root-a", "Protected", PolicyOperation.MOVE),
                "approvals must be bound to the exact operation");
        check(service.consume(approvalId, "member-1", "root-a", "Protected", PolicyOperation.DELETE),
                "an approved matching operation must be authorized");
        check(!service.consume(approvalId, "member-1", "root-a", "Protected", PolicyOperation.DELETE),
                "approvals must be single-use");
        check("CONSUMED".equals(service.status(approvalId).get("state")), "consumed state must be observable");

        Map<String, Object> denied = service.request("member-1", "root-a", "Protected", PolicyOperation.TRUNCATE, 60);
        String deniedId = (String) denied.get("approvalId");
        service.deny(deniedId);
        check("DENIED".equals(service.status(deniedId).get("state")), "denied state must be observable");
        check(!service.consume(deniedId, "member-1", "root-a", "Protected", PolicyOperation.TRUNCATE),
                "denied approvals must never authorize an operation");

        Map<String, Object> longLived = service.request("member-1", "root-a", "Protected", PolicyOperation.BULK_DELETE, 999_999);
        Instant expiresAt = Instant.parse((String) longLived.get("expiresAt"));
        check(Duration.between(Instant.now(), expiresAt).toSeconds() <= 3600,
                "approval TTL must be capped at one hour");

        Map<String, Object> expired = service.request("member-1", "root-a", "Protected", PolicyOperation.DELETE, 1);
        String expiredId = (String) expired.get("approvalId");
        service.approve(expiredId);
        Thread.sleep(1100);
        check("EXPIRED".equals(service.status(expiredId).get("state")), "expired approvals must be reported as expired");
        check(!service.consume(expiredId, "member-1", "root-a", "Protected", PolicyOperation.DELETE),
                "expired approvals must never authorize an operation");

        expectFailure(() -> service.approve("missing"), "unknown approvals must be rejected");
        expectFailure(() -> service.request("", "root-a", "Protected", PolicyOperation.DELETE, 60),
                "a requesting member is required");

        System.out.println("PASS: protection approvals are bound, single-use, expiring and fail closed.");
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException expected) {
            // Expected: invalid or unknown approvals fail closed.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws Exception; }
}
