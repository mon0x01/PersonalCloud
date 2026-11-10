package dev.personalcloud.core;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-local brute-force and request throttling. Restarting the process
 * clears temporary lockouts. Tracking is bounded so hostile sources cannot
 * grow the monitor without limit.
 */
public final class SecurityMonitor {
    private static final int MAX_FAILURES = 8;
    private static final long WINDOW_SECONDS = 600;
    private static final long LOCK_SECONDS = 300;
    private static final int MAX_TRACKED_SOURCES = 4096;
    private static final class Entry { int failures; long firstFailure; long lockedUntil; }
    private static final class Window {
        long windowStart;
        int count;
    }
    private final ConcurrentHashMap<String, Entry> pairing = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Window> requests = new ConcurrentHashMap<>();

    public boolean pairingAllowed(String key) { return allowed(key); }
    public void pairingFailed(String key) { failed(key); }
    public void pairingSucceeded(String key) { pairing.remove(key); }

    /**
     * Counts one request for a bounded per-source sliding window.
     * Returns false when {@code limit} requests were already observed inside
     * {@code windowSeconds}. Limit and window are supplied by the caller so
     * individual routes can be tuned without changing this primitive.
     */
    public boolean requestAllowed(String key, int limit, long windowSeconds) {
        if (key == null || key.isBlank() || limit <= 0) return true;
        long now = Instant.now().getEpochSecond();
        if (requests.size() > MAX_TRACKED_SOURCES) evictExpiredWindows(now);
        Window window = requests.computeIfAbsent(key, ignored -> new Window());
        synchronized (window) {
            if (window.windowStart == 0 || now - window.windowStart >= windowSeconds) {
                window.windowStart = now;
                window.count = 0;
            }
            window.count++;
            return window.count <= limit;
        }
    }

    private void evictExpiredWindows(long now) {
        for (Map.Entry<String, Window> entry : requests.entrySet()) {
            Window window = entry.getValue();
            synchronized (window) {
                // Windows are at most one hour in practice; anything older than
                // two hours is certainly stale and safe to drop.
                if (window.windowStart == 0 || now - window.windowStart > 7200) requests.remove(entry.getKey(), window);
            }
            if (requests.size() <= MAX_TRACKED_SOURCES / 2) break;
        }
        if (requests.size() > MAX_TRACKED_SOURCES) requests.clear();
    }

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
