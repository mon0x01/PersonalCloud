package dev.personalcloud.network;

import java.io.IOException;

/** Carries the destination's durable session identifier when a direct transfer is interrupted. */
public final class RemoteTransferInterruptedException extends IOException {
    private final String transferId;
    public RemoteTransferInterruptedException(String transferId, String message, Throwable cause) {
        super(message, cause);
        this.transferId = transferId;
    }
    public String transferId() { return transferId; }
}
