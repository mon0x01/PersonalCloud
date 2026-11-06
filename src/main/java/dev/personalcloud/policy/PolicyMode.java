package dev.personalcloud.policy;

/** Owner-controlled exception mode for a filesystem path. */
public enum PolicyMode {
    /** Ordinary eligible file: broad access by default. */
    NORMAL,
    /** Hidden from remote discovery and denied to all remote operations. */
    PRIVATE,
    /** Visible and readable; destructive operations require owner approval. */
    PROTECTED
}
