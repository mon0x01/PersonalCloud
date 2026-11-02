package dev.personalcloud.core;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Encrypts locally stored outgoing peer credentials with AES-256-GCM. */
public final class TokenVault {
    private static final String PREFIX = "v1:";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final byte[] key;

    public TokenVault(Path dataDirectory) throws Exception {
        Path keyFile = dataDirectory.resolve("vault.key");
        if (Files.exists(keyFile)) {
            key = Base64.getDecoder().decode(Files.readString(keyFile).trim());
            if (key.length != 32) throw new IllegalStateException("Invalid token-vault key. Restore vault.key or re-pair devices.");
        } else {
            key = new byte[32];
            RANDOM.nextBytes(key);
            Files.writeString(keyFile, Base64.getEncoder().encodeToString(key));
        }
        SecretFiles.restrict(keyFile);
    }

    public String encrypt(String plaintext) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] combined = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(encrypted, 0, combined, nonce.length, encrypted.length);
        return PREFIX + Base64.getEncoder().encodeToString(combined);
    }

    public String decrypt(String value) throws Exception {
        if (value == null || !value.startsWith(PREFIX)) return value; // legacy plaintext; caller migrates it.
        byte[] combined = Base64.getDecoder().decode(value.substring(PREFIX.length()));
        if (combined.length < 29) throw new IllegalStateException("Stored peer credential is corrupt.");
        byte[] nonce = Arrays.copyOfRange(combined, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(combined, 12, combined.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return new String(cipher.doFinal(ciphertext), java.nio.charset.StandardCharsets.UTF_8);
    }

    public boolean isEncrypted(String value) { return value != null && value.startsWith(PREFIX); }
}
