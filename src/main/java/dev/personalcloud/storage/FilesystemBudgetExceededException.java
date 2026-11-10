package dev.personalcloud.storage;

/**
 * Raised when an authenticated member has exhausted one of its durable daily
 * filesystem budgets. Carries only accounting metadata, never file contents.
 */
public final class FilesystemBudgetExceededException extends IllegalStateException {
    private final String memberId;
    private final String budget;
    private final long limit;
    private final long used;
    private final long reserved;
    private final long requested;
    private final long retryAfterSeconds;

    public FilesystemBudgetExceededException(String memberId, String budget, long limit,
                                             long used, long reserved, long requested,
                                             long retryAfterSeconds) {
        super("Daily filesystem " + budget + " budget exceeded for this member (limit=" + limit
                + ", used=" + used + ", reserved=" + reserved + ", requested=" + requested
                + "); retry after UTC midnight.");
        this.memberId = memberId;
        this.budget = budget;
        this.limit = limit;
        this.used = used;
        this.reserved = reserved;
        this.requested = requested;
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    public String memberId() { return memberId; }
    public String budget() { return budget; }
    public long limit() { return limit; }
    public long used() { return used; }
    public long reserved() { return reserved; }
    public long requested() { return requested; }
    public long retryAfterSeconds() { return retryAfterSeconds; }
}
