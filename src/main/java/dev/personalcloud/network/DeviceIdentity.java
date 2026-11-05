package dev.personalcloud.network;

import dev.personalcloud.core.SecretFiles;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Per-device Ed25519 identity. The private key is protected by owner-only filesystem permissions. */
public final class DeviceIdentity {
    private final Path directory;
    private final KeyPair keyPair;

    public DeviceIdentity(Path dataDirectory) throws Exception {
        directory = dataDirectory.resolve("identity");
        SecretFiles.restrictDirectory(directory);
        Files.createDirectories(directory);
        Path privateFile = directory.resolve("device-ed25519.pk8");
        Path publicFile = directory.resolve("device-ed25519.pub");
        if (Files.exists(privateFile) != Files.exists(publicFile)) {
            throw new IllegalStateException("The PersonalCloud device identity is incomplete. Restore both identity key files from backup; refusing to generate a replacement.");
        }
        if (Files.exists(privateFile)) {
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateFile)));
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicFile)));
            keyPair = new KeyPair(publicKey, privateKey);
            byte[] challenge = "PersonalCloud identity self-check".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (!verify(publicKey, challenge, sign(challenge))) {
                throw new SecurityException("The saved PersonalCloud device identity failed its key-pair self-check.");
            }
        } else {
            KeyPair generated = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            writeAtomic(privateFile, generated.getPrivate().getEncoded());
            writeAtomic(publicFile, generated.getPublic().getEncoded());
            SecretFiles.restrict(privateFile);
            SecretFiles.restrict(publicFile);
            keyPair = generated;
        }
        SecretFiles.restrict(privateFile);
        SecretFiles.restrict(publicFile);
        SecretFiles.restrictDirectory(directory);
    }

    public PrivateKey privateKey() { return keyPair.getPrivate(); }
    public PublicKey publicKey() { return keyPair.getPublic(); }
    public String publicKeyBase64() { return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()); }

    public byte[] sign(byte[] payload) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keyPair.getPrivate());
        signer.update(payload);
        return signer.sign();
    }

    public static boolean verify(PublicKey key, byte[] payload, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(payload);
        return verifier.verify(signature);
    }

    public static PublicKey decodePublicKey(String encoded) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(encoded);
        if (bytes.length > 512) throw new IllegalArgumentException("Device public key is too large.");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(bytes));
    }

    private static void writeAtomic(Path target, byte[] bytes) throws Exception {
        Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(temporary, bytes);
        SecretFiles.restrict(temporary);
        try { Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE); }
        catch (java.nio.file.AtomicMoveNotSupportedException unavailable) { Files.move(temporary, target); }
    }
}
