package dev.personalcloud.policy;

/** Filesystem operations evaluated by the source-side policy engine. */
public enum PolicyOperation {
    LIST,
    STAT,
    READ,
    CREATE,
    WRITE,
    TRUNCATE,
    MOVE,
    DELETE,
    BULK_DELETE,
    BULK_MOVE;

    /**
     * Destructive operations mutate or remove existing owner data. Creating a new
     * name is not destructive by itself; callers use {@link #WRITE} when replacing
     * existing content.
     */
    public boolean destructive() {
        return switch (this) {
            case WRITE, TRUNCATE, MOVE, DELETE, BULK_DELETE, BULK_MOVE -> true;
            case LIST, STAT, READ, CREATE -> false;
        };
    }
}
