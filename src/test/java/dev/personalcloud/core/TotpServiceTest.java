package dev.personalcloud.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

public final class TotpServiceTest {
    public static void main(String[] args) throws Exception {
        // RFC 6238 Appendix B, SHA-1, 6-digit truncation, T=59 seconds.
        String vectorSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        String actual = TotpService.codeForTest(vectorSecret, 59);
        if (!"287082".equals(actual)) throw new AssertionError("RFC 6238 vector failed: " + actual);

        // Browser sessions are stored as hashes, refresh on use, and have a bounded count.
        SessionManager sessions = new SessionManager();
        String firstSession = sessions.create();
        if (!sessions.valid(firstSession)) throw new AssertionError("New browser session was rejected.");
        sessions.revoke(firstSession);
        if (sessions.valid(firstSession)) throw new AssertionError("Revoked browser session was accepted.");
        String oldestSession = sessions.create();
        for (int i = 1; i <= SessionManager.MAX_SESSIONS; i++) sessions.create();
        if (sessions.valid(oldestSession)) throw new AssertionError("Oldest session was not evicted at the session cap.");

        Path data = Files.createTempDirectory("personalcloud-totp-test-");
        try {
            StateStore store = new StateStore(data);
            MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_700_000_000));
            TotpService totp = new TotpService(store, data, clock);
            Map<String, String> setup = totp.beginSetup();
            String secret = setup.get("secret");
            String enrollmentCode = TotpService.codeForTest(secret, clock.instant().getEpochSecond());
            List<String> recovery = totp.enable(enrollmentCode);
            if (recovery.size() != 10 || !totp.isEnabled()) throw new AssertionError("MFA enrollment failed.");
            if (totp.verifyAndConsume(enrollmentCode)) throw new AssertionError("TOTP replay was accepted.");
            if (totp.remainingRecoveryCodes() != 10) throw new AssertionError("Recovery code count changed unexpectedly.");

            clock.set(Instant.ofEpochSecond(1_700_000_030));
            String nextCode = TotpService.codeForTest(secret, clock.instant().getEpochSecond());
            if (!totp.verifyAndConsume(nextCode)) throw new AssertionError("Fresh TOTP was rejected.");
            if (totp.verifyAndConsume(nextCode)) throw new AssertionError("Fresh TOTP replay was accepted.");

            if (!totp.verifyAndConsume(recovery.get(0))) throw new AssertionError("Recovery code was rejected.");
            if (totp.verifyAndConsume(recovery.get(0))) throw new AssertionError("Recovery code replay was accepted.");
            if (totp.remainingRecoveryCodes() != 9) throw new AssertionError("Recovery code was not consumed.");

            // Recovery codes remain available if the encrypted TOTP seed's vault key is lost.
            Files.delete(data.resolve("vault.key"));
            TotpService afterVaultLoss = new TotpService(store, data, clock);
            if (!afterVaultLoss.verifyAndConsume(recovery.get(1))) throw new AssertionError("Recovery failed after vault-key loss.");
            if (afterVaultLoss.verifyAndConsume(recovery.get(1))) throw new AssertionError("Recovery code was accepted twice after vault-key loss.");
        } finally {
            try (var paths = Files.walk(data)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                });
            }
        }
        System.out.println("PASS: RFC 6238 vector; TOTP enrollment and fresh-code validation; replay rejection; one-time recovery codes; recovery after vault-key loss; browser-session revocation and capacity limit.");
    }

    private static final class MutableClock extends Clock {
        private Instant current;
        MutableClock(Instant current) { this.current = current; }
        void set(Instant value) { current = value; }
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return current; }
    }
}
