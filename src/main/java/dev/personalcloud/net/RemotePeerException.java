package dev.personalcloud.net;

public final class RemotePeerException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int statusCode;
    public RemotePeerException(int statusCode, String message) { super(message); this.statusCode = statusCode; }
    public int statusCode() { return statusCode; }
}
