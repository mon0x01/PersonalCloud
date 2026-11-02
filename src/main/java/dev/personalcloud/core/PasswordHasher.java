package dev.personalcloud.core;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** PBKDF2 password storage with per-password salt and constant-time verification. */
public final class PasswordHasher {
    private static final int ITERATIONS = 310_000;
    private static final int BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();
    private PasswordHasher() { }

    public static String hash(String password) throws Exception {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS);
        return "pbkdf2-sha256$" + ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt) + "$" + Base64.getEncoder().encodeToString(derived);
    }

    public static boolean verify(String password, String encoded) {
        if (password == null || encoded == null) return false;
        try {
            String[] parts = encoded.split("\\$", -1);
            if (parts.length != 4 || !parts[0].equals("pbkdf2-sha256")) return false;
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < 100_000 || iterations > 2_000_000) return false;
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            return MessageDigest.isEqual(expected, derive(password, salt, iterations));
        } catch (Exception ignored) { return false; }
    }

    private static byte[] derive(String password, byte[] salt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, BITS);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }
}
