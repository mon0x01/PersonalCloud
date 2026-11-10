package dev.personalcloud.policy;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Short-lived, single-use approvals for destructive operations on protected paths.
 *
 * <p>Approvals are intentionally process-local: after a restart an unapproved
 * request fails closed and the owner must approve again. Tokens are bound to the
 * requesting member, root, path, and operation, and cannot be reused.</p>
 */
public final class ProtectionApprovalService {
    private static final long DEFAULT_TTL_SECONDS = 300;
    private static final long MAX_TTL_SECONDS = 3600;
    private static final int MAX_PENDING_PER_MEMBER = envInt("PERSONALCLOUD_MAX_PENDING_APPROVALS_PER_MEMBER", 32, 1, 1024);
    private static final int MAX_PENDING_TOTAL = envInt("PERSONALCLOUD_MAX_PENDING_APPROVALS", 256, 8, 8192);
    private static final long RETENTION_SECONDS = 3600;

    private final Map<String, Approval> approvals = new ConcurrentHashMap<>();

    public synchronized Map<String, Object> request(String memberId, String rootId, String path,
                                                    PolicyOperation operation, long ttlSeconds) {
        requireText(memberId, "A requesting member ID is required.");
        requireText(rootId, "An eligible root ID is required.");
        if (operation == null || !operation.destructive()) {
            throw new IllegalArgumentException("Only destructive operations require protection approval.");
        }
        purgeExpired();
        int memberPending = 0;
        int totalPending = 0;
        for (Approval existing : approvals.values()) {
            if (existing.state != ApprovalState.PENDING) continue;
            totalPending++;
            if (existing.memberId.equals(memberId)) memberPending++;
        }
        if (memberPending >= MAX_PENDING_PER_MEMBER) {
            throw new IllegalStateException("This device has reached its pending protection-approval limit.");
        }
        if (totalPending >= MAX_PENDING_TOTAL) {
            throw new IllegalStateException("The node has reached its pending protection-approval limit.");
        }
        long ttl = ttlSeconds <= 0 ? DEFAULT_TTL_SECONDS : Math.min(ttlSeconds, MAX_TTL_SECONDS);
        String id = UUID.randomUUID().toString();
        Approval approval = new Approval(id, memberId, rootId, PolicyStore.normalize(path), operation,
                Instant.now().plusSeconds(ttl));
        approvals.put(id, approval);
        return approval.toMap();
    }

    public synchronized Map<String, Object> approve(String approvalId) {
        Approval approval = require(approvalId);
        approval.expireIfNeeded();
        if (approval.state != ApprovalState.PENDING) {
            throw new IllegalStateException("Approval is not pending.");
        }
        approval.state = ApprovalState.APPROVED;
        approval.decidedAt = Instant.now();
        return approval.toMap();
    }

    public synchronized Map<String, Object> deny(String approvalId) {
        Approval approval = require(approvalId);
        approval.expireIfNeeded();
        if (approval.state != ApprovalState.PENDING) {
            throw new IllegalStateException("Approval is not pending.");
        }
        approval.state = ApprovalState.DENIED;
        approval.decidedAt = Instant.now();
        return approval.toMap();
    }

    /** Consumes an approved token exactly once when every binding matches. */
    public synchronized boolean consume(String approvalId, String memberId, String rootId,
                                        String path, PolicyOperation operation) {
        Approval approval = approvals.get(approvalId);
        if (approval == null) return false;
        approval.expireIfNeeded();
        if (approval.state != ApprovalState.APPROVED) return false;
        boolean matches = approval.memberId.equals(memberId)
                && approval.rootId.equals(rootId)
                && approval.path.equals(PolicyStore.normalize(path))
                && approval.operation == operation;
        if (!matches) return false;
        approval.state = ApprovalState.CONSUMED;
        approval.consumedAt = Instant.now();
        return true;
    }

    public synchronized Map<String, Object> status(String approvalId) {
        Approval approval = require(approvalId);
        approval.expireIfNeeded();
        return approval.toMap();
    }

    /** Lists every approval known to this process, newest first, for the owner-only control socket. */
    public synchronized java.util.List<Map<String, Object>> list() {
        java.util.List<Map<String, Object>> result = new java.util.ArrayList<>();
        for (Approval approval : approvals.values()) {
            approval.expireIfNeeded();
            result.add(approval.toMap());
        }
        result.sort((left, right) -> String.valueOf(right.get("expiresAt")).compareTo(String.valueOf(left.get("expiresAt"))));
        return java.util.List.copyOf(result);
    }

    /** Drops old terminal approvals so hostile request churn stays bounded. */
    private void purgeExpired() {
        Instant cutoff = Instant.now().minusSeconds(RETENTION_SECONDS);
        approvals.entrySet().removeIf(entry -> {
            Approval approval = entry.getValue();
            approval.expireIfNeeded();
            return approval.state != ApprovalState.PENDING && approval.expiresAt.isBefore(cutoff);
        });
    }

    private static int envInt(String name, int fallback, int minimum, int maximum) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) return fallback;
        try {
            return Math.max(minimum, Math.min(maximum, Integer.parseInt(value.trim())));
        } catch (NumberFormatException invalid) {
            return fallback;
        }
    }

    private Approval require(String approvalId) {
        if (approvalId == null || approvalId.isBlank()) throw new IllegalArgumentException("An approval ID is required.");
        Approval approval = approvals.get(approvalId);
        if (approval == null) throw new IllegalArgumentException("Approval was not found or has expired.");
        return approval;
    }

    private static void requireText(String value, String message) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(message);
    }

    private enum ApprovalState { PENDING, APPROVED, DENIED, CONSUMED, EXPIRED }

    private static final class Approval {
        private final String id;
        private final String memberId;
        private final String rootId;
        private final String path;
        private final PolicyOperation operation;
        private final Instant expiresAt;
        private ApprovalState state = ApprovalState.PENDING;
        private Instant decidedAt;
        private Instant consumedAt;

        private Approval(String id, String memberId, String rootId, String path,
                         PolicyOperation operation, Instant expiresAt) {
            this.id = id;
            this.memberId = memberId;
            this.rootId = rootId;
            this.path = path;
            this.operation = operation;
            this.expiresAt = expiresAt;
        }

        private void expireIfNeeded() {
            if (state == ApprovalState.PENDING || state == ApprovalState.APPROVED) {
                if (Instant.now().isAfter(expiresAt)) state = ApprovalState.EXPIRED;
            }
        }

        private Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("approvalId", id);
            result.put("memberId", memberId);
            result.put("rootId", rootId);
            result.put("path", path);
            result.put("operation", operation.name());
            result.put("state", state.name());
            result.put("expiresAt", expiresAt.toString());
            if (decidedAt != null) result.put("decidedAt", decidedAt.toString());
            if (consumedAt != null) result.put("consumedAt", consumedAt.toString());
            return result;
        }
    }
}
