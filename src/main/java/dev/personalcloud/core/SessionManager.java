package dev.personalcloud.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.Map;

/** In-memory, HttpOnly cookie sessions. A node restart invalidates every browser session. */
public final class SessionManager {
    public static final String COOKIE_NAME = "PC_SESSION";
    public static final long SESSION_SECONDS = 12 * 60 * 60;
    public static final int MAX_SESSIONS = 64;
    private final LinkedHashMap<String, Long> sessions = new LinkedHashMap<>();

    public synchronized String create() throws Exception {
        long now = Instant.now().getEpochSecond();
        sessions.entrySet().removeIf(entry -> entry.getValue() <= now);
        while (sessions.size() >= MAX_SESSIONS) {
            Iterator<Map.Entry<String, Long>> iterator = sessions.entrySet().iterator();
            if (!iterator.hasNext()) break;
            iterator.next();
            iterator.remove();
        }
        byte[] random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        sessions.put(hash(token), now + SESSION_SECONDS);
        return token;
    }

    public synchronized boolean valid(String token) throws Exception {
        if (token == null || token.isBlank()) return false;
        String key = hash(token);
        Long expiry = sessions.get(key);
        long now = Instant.now().getEpochSecond();
        if (expiry == null) return false;
        if (expiry <= now) {
            sessions.remove(key);
            return false;
        }
        sessions.put(key, now + SESSION_SECONDS);
        return true;
    }

    public synchronized void revoke(String token) throws Exception {
        if (token != null && !token.isBlank()) sessions.remove(hash(token));
    }

    public synchronized void revokeAll() { sessions.clear(); }

    private static String hash(String token) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
