package dev.personalcloud.core;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/** Process-local pairing brute-force throttling. Restarting the process clears temporary lockouts. */
public final class SecurityMonitor {
    private static final int MAX_FAILURES = 8;
    private static final long WINDOW_SECONDS = 600;
    private static final long LOCK_SECONDS = 300;
    private static final class Entry { int failures; long firstFailure; long lockedUntil; }
    private final ConcurrentHashMap<String, Entry> pairing = new ConcurrentHashMap<>();

    public boolean pairingAllowed(String key) { return allowed(key); }
    public void pairingFailed(String key) { failed(key); }
    public void pairingSucceeded(String key) { pairing.remove(key); }

    private boolean allowed(String key) {
        Entry entry = pairing.get(key);
        if (entry == null) return true;
        long now = Instant.now().getEpochSecond();
        synchronized (entry) {
            if (entry.lockedUntil > now) return false;
            if (now - entry.firstFailure > WINDOW_SECONDS && entry.lockedUntil <= now) pairing.remove(key, entry);
            return true;
        }
    }

    private void failed(String key) {
        long now = Instant.now().getEpochSecond();
        Entry entry = pairing.computeIfAbsent(key, ignored -> new Entry());
        synchronized (entry) {
            if (now - entry.firstFailure > WINDOW_SECONDS) { entry.failures = 0; entry.firstFailure = now; }
            entry.failures++;
            if (entry.failures >= MAX_FAILURES) entry.lockedUntil = now + LOCK_SECONDS;
        }
    }
}
