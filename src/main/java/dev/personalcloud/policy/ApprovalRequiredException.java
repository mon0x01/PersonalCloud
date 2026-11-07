package dev.personalcloud.policy;

/** Raised when a destructive operation needs an owner approval that was not supplied. */
public final class ApprovalRequiredException extends SecurityException {
    private final String rootId;
    private final String path;
    private final PolicyOperation operation;

    public ApprovalRequiredException(String rootId, String path, PolicyOperation operation) {
        super("Owner approval is required for this protected operation.");
        this.rootId = rootId;
        this.path = path;
        this.operation = operation;
    }

    public String rootId() { return rootId; }
    public String path() { return path; }
    public PolicyOperation operation() { return operation; }
}
