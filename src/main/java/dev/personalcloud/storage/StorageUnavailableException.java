package dev.personalcloud.storage;

import java.io.IOException;

/** A referenced directory is known to the node but is currently unavailable. */
public final class StorageUnavailableException extends IOException {
    public StorageUnavailableException(String message) { super(message); }
}
