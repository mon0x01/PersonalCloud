package dev.personalcloud.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** RFC 6238 TOTP with encrypted seed storage and one-time recovery codes. */
public final class TotpService {
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final StateStore store;
    private final TokenVault vault;
    private final java.time.Clock clock;

    public TotpService(StateStore store, java.nio.file.Path dataDirectory) throws Exception {
        this(store, dataDirectory, java.time.Clock.systemUTC());
    }

    TotpService(StateStore store, java.nio.file.Path dataDirectory, java.time.Clock clock) throws Exception {
        this.store = store;
        this.vault = new TokenVault(dataDirectory);
        this.clock = clock;
    }

    public boolean isEnabled() { return "true".equals(store.get("mfa.enabled")); }

    public Map<String, String> beginSetup() throws Exception {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        String secret = base32Encode(bytes);
        store.put("mfa.pending", vault.encrypt(secret));
        String label = java.net.URLEncoder.encode("PersonalCloud:admin", StandardCharsets.UTF_8);
        String issuer = java.net.URLEncoder.encode("PersonalCloud", StandardCharsets.UTF_8);
        String uri = "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30";
        return Map.of("secret", secret, "otpauthUri", uri, "algorithm", "SHA1", "digits", "6", "periodSeconds", "30");
    }

    public synchronized List<String> enable(String code) throws Exception {
        String pending = store.get("mfa.pending");
        if (pending == null) throw new IllegalStateException("Start MFA setup before confirming it.");
        String secret = vault.decrypt(pending);
        long acceptedCounter = matchingCounter(secret, code, Instant.now(clock).getEpochSecond());
        if (acceptedCounter < 0) throw new SecurityException("Authenticator code is invalid or expired.");
        store.put("mfa.secret", vault.encrypt(secret));
        store.put("mfa.lastCounter", Long.toString(acceptedCounter));
        store.put("mfa.enabled", "true");
        store.remove("mfa.pending");
        for (Map<String, String> old : store.records("mfaRecovery")) store.removeRecord("mfaRecovery", old.get("_id"));
        List<String> recoveryCodes = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String recovery = recoveryCode();
            String hash = hash(recovery);
            store.putRecord("mfaRecovery", hash, Map.of("createdAt", Instant.now(clock).toString()));
            recoveryCodes.add(recovery);
        }
        return recoveryCodes;
    }

    public synchronized boolean verifyAndConsume(String code) throws Exception {
        if (!isEnabled()) return true;
        String encrypted = store.get("mfa.secret");
        if (encrypted != null && code != null && code.matches("\\d{6}")) {
            try {
                String secret = vault.decrypt(encrypted);
                long counter = matchingCounter(secret, code, Instant.now(clock).getEpochSecond());
                long lastCounter = Long.parseLong(java.util.Objects.requireNonNullElse(store.get("mfa.lastCounter"), "-1"));
                if (counter > lastCounter) {
                    store.put("mfa.lastCounter", Long.toString(counter));
                    return true;
                }
            } catch (Exception ignored) {
                // Recovery codes remain usable if the encrypted authenticator seed is unavailable.
            }
        }
        if (code == null || code.isBlank()) return false;
        String hash = hash(code.trim().toUpperCase(java.util.Locale.ROOT));
        for (Map<String, String> record : store.records("mfaRecovery")) {
            if (MessageDigest.isEqual(record.get("_id").getBytes(StandardCharsets.UTF_8), hash.getBytes(StandardCharsets.UTF_8))) {
                store.removeRecord("mfaRecovery", record.get("_id"));
                return true;
            }
        }
        return false;
    }

    public synchronized void disable(String code) throws Exception {
        if (isEnabled() && !verifyAndConsume(code)) throw new SecurityException("Authenticator code or recovery code is incorrect.");
        store.remove("mfa.enabled");
        store.remove("mfa.secret");
        store.remove("mfa.pending");
        store.remove("mfa.lastCounter");
        for (Map<String, String> record : store.records("mfaRecovery")) store.removeRecord("mfaRecovery", record.get("_id"));
    }

    public int remainingRecoveryCodes() { return store.records("mfaRecovery").size(); }

    public static String codeForTest(String secret, long epochSeconds) throws Exception {
        return generateCode(base32Decode(secret), epochSeconds / 30);
    }

    private static long matchingCounter(String secret, String code, long epochSeconds) throws Exception {
        if (code == null || !code.matches("\\d{6}")) return -1;
        byte[] key = base32Decode(secret);
        byte[] supplied = code.getBytes(StandardCharsets.US_ASCII);
        long current = epochSeconds / 30;
        // Prefer the newest matching counter in the clock-skew window.
        for (long counter = current + 1; counter >= current - 1; counter--) {
            String expected = generateCode(key, counter);
            if (MessageDigest.isEqual(supplied, expected.getBytes(StandardCharsets.US_ASCII))) return counter;
        }
        return -1;
    }

    private static String generateCode(byte[] key, long counter) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        return String.format(java.util.Locale.ROOT, "%06d", binary % 1_000_000);
    }

    private static String recoveryCode() {
        String raw = SecretFiles.randomToken().replace('-', 'X').replace('_', 'Y').toUpperCase(java.util.Locale.ROOT);
        return raw.substring(0, 12);
    }

    private static String hash(String value) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static String base32Encode(byte[] input) {
        StringBuilder result = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : input) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                result.append(BASE32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) result.append(BASE32.charAt((buffer << (5 - bits)) & 31));
        return result.toString();
    }

    private static byte[] base32Decode(String value) {
        String normalized = value.replace("=", "").replace(" ", "").toUpperCase(java.util.Locale.ROOT);
        byte[] output = new byte[normalized.length() * 5 / 8];
        int buffer = 0, bits = 0, index = 0;
        for (char c : normalized.toCharArray()) {
            int digit = BASE32.indexOf(c);
            if (digit < 0) throw new IllegalArgumentException("Invalid base32 authenticator secret.");
            buffer = (buffer << 5) | digit;
            bits += 5;
            if (bits >= 8) {
                output[index++] = (byte) ((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return output;
    }
}
