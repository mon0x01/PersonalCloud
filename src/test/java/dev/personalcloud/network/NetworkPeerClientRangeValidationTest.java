package dev.personalcloud.network;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Focused integrity tests for desktop HTTP byte-range responses. */
public final class NetworkPeerClientRangeValidationTest {
    public static void main(String[] args) throws Exception {
        byte[] bytes = "range-data".getBytes(StandardCharsets.UTF_8);
        String rangeHash = sha256(bytes);
        String fullHash = sha256("prefix-range-data-suffix".getBytes(StandardCharsets.UTF_8));
        String contentRange = "bytes 7-16/24";

        NetworkPeerClient.RemoteRangeResult accepted = NetworkPeerClient.validateRangePayload(
                bytes, contentRange, rangeHash, fullHash, 7, bytes.length, 24);
        check(java.util.Arrays.equals(bytes, accepted.bytes()), "valid range bytes must be returned unchanged");
        check(fullHash.equals(accepted.sha256()), "full-file digest metadata must be preserved");

        expectRejected(() -> NetworkPeerClient.validateRangePayload(bytes, contentRange,
                sha256("tampered".getBytes(StandardCharsets.UTF_8)), fullHash, 7, bytes.length, 24),
                "tampered range digest must be rejected");
        expectRejected(() -> NetworkPeerClient.validateRangePayload(bytes, "bytes 0-9/24",
                rangeHash, fullHash, 7, bytes.length, 24), "mismatched Content-Range must be rejected");
        expectRejected(() -> NetworkPeerClient.validateRangePayload(bytes, contentRange,
                "", fullHash, 7, bytes.length, 24), "missing range digest must be rejected");
        expectRejected(() -> NetworkPeerClient.validateRangePayload(bytes, contentRange,
                rangeHash, "not-a-digest", 7, bytes.length, 24), "malformed full digest must be rejected");
        expectRejected(() -> NetworkPeerClient.validateRangePayload(bytes, contentRange,
                rangeHash, fullHash, 20, bytes.length, 24), "range extending beyond EOF must be rejected");
        expectRejected(() -> NetworkPeerClient.validateRangePayload(new byte[bytes.length - 1], contentRange,
                rangeHash, fullHash, 7, bytes.length, 24), "truncated range body must be rejected");

        System.out.println("PASS: desktop remote range reads validate exact Content-Range, byte count, mandatory range SHA-256 and optional full-file digest; tampering/truncation/bounds are rejected.");
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void expectRejected(Checked action, String message) throws Exception {
        try { action.run(); throw new AssertionError(message); }
        catch (java.io.IOException expected) { }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
}
