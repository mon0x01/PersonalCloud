package dev.personalcloud.core;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/** Process-local brute-force throttling. Restarting the process clears temporary lockouts. */
public final class SecurityMonitor {
    private static final int MAX_FAILURES = 6;
    private static final long WINDOW_SECONDS = 300;
    private static final long LOCK_SECONDS = 120;
    private static final class Entry { int failures; long firstFailure; long lockedUntil; }
    private final ConcurrentHashMap<String, Entry> logins = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Entry> pairing = new ConcurrentHashMap<>();

    public boolean loginAllowed(String key) { return allowed(logins, key, WINDOW_SECONDS); }
    public void loginFailed(String key) { failed(logins, key, MAX_FAILURES, WINDOW_SECONDS, LOCK_SECONDS); }
    public void loginSucceeded(String key) { logins.remove(key); }
    public boolean pairingAllowed(String key) { return allowed(pairing, key, 600); }
    public void pairingFailed(String key) { failed(pairing, key, 8, 600, 300); }
    public void pairingSucceeded(String key) { pairing.remove(key); }

    private boolean allowed(ConcurrentHashMap<String, Entry> map, String key, long windowSeconds) {
        Entry e = map.get(key);
        if (e == null) return true;
        long now = Instant.now().getEpochSecond();
        synchronized (e) {
            if (e.lockedUntil > now) return false;
            if (now - e.firstFailure > windowSeconds && e.lockedUntil <= now) map.remove(key, e);
            return true;
        }
    }

    private void failed(ConcurrentHashMap<String, Entry> map, String key, int max, long window, long lock) {
        long now = Instant.now().getEpochSecond();
        Entry e = map.computeIfAbsent(key, ignored -> new Entry());
        synchronized (e) {
            if (now - e.firstFailure > window) { e.failures = 0; e.firstFailure = now; }
            e.failures++;
            if (e.failures >= max) e.lockedUntil = now + lock;
        }
    }
}
