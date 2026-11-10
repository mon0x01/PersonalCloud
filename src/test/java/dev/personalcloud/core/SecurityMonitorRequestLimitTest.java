package dev.personalcloud.core;

/** Bounded per-source request throttling tests. */
public final class SecurityMonitorRequestLimitTest {
    public static void main(String[] args) {
        SecurityMonitor monitor = new SecurityMonitor();

        check(monitor.requestAllowed("source-a", 3, 60), "the first request must be allowed");
        check(monitor.requestAllowed("source-a", 3, 60), "the second request must be allowed");
        check(monitor.requestAllowed("source-a", 3, 60), "the third request must be allowed");
        check(!monitor.requestAllowed("source-a", 3, 60), "a source must be limited after reaching its window quota");
        check(monitor.requestAllowed("source-b", 3, 60), "one source must not consume another source's quota");
        check(monitor.requestAllowed("", 3, 60), "blank source keys must not break the limiter");
        check(monitor.requestAllowed("source-c", 0, 60), "a disabled limit must allow requests");

        // Pairing lockouts remain independent of ordinary request windows.
        check(monitor.pairingAllowed("pair-source"), "a source must start unlocked");
        for (int i = 0; i < 8; i++) monitor.pairingFailed("pair-source");
        check(!monitor.pairingAllowed("pair-source"), "repeated pairing failures must lock the source");
        check(monitor.pairingAllowed("other-pair-source"), "a pairing lockout must not affect other sources");

        System.out.println("PASS: per-source request windows and pairing lockouts are independent and bounded.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
