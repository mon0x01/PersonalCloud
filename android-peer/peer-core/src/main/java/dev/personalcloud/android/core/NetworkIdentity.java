package dev.personalcloud.android.core;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Per-Android-device Ed25519 identity stored only in the encrypted network state domain. */
public final class NetworkIdentity {
    private final KeyPair keyPair;

    public NetworkIdentity(StateStore store) throws Exception {
        Map<String, Object> state = store.loadDomain("network");
        String privateText = string(state.get("identityPrivate"));
        String publicText = string(state.get("identityPublic"));
        if (privateText.isEmpty() && publicText.isEmpty()) {
            try {
                KeyPair generated = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                Map<String, Object> updated = new LinkedHashMap<String, Object>(state);
                updated.put("identityPrivate", Base64.getEncoder().encodeToString(generated.getPrivate().getEncoded()));
                updated.put("identityPublic", Base64.getEncoder().encodeToString(generated.getPublic().getEncoded()));
                store.saveDomain("network", updated);
                state = updated;
            } catch (java.security.NoSuchAlgorithmException unsupported) {
                throw new IllegalStateException("This Android version does not provide Ed25519. PersonalCloud network membership requires Android 13/API 33 or newer; the existing peer features remain available.", unsupported);
            }
            privateText = string(state.get("identityPrivate"));
            publicText = string(state.get("identityPublic"));
        }
        if (privateText.isEmpty() || publicText.isEmpty()) throw new SecurityException("The Android network identity is incomplete; refusing to silently replace it.");
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateText)));
        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicText)));
        keyPair = new KeyPair(publicKey, privateKey);
        byte[] challenge = "PersonalCloud Android identity self-check".getBytes(StandardCharsets.UTF_8);
        if (!verify(publicKey, challenge, sign(challenge))) throw new SecurityException("The saved Android network identity failed its key-pair self-check.");
    }

    public PrivateKey privateKey() { return keyPair.getPrivate(); }
    public PublicKey publicKey() { return keyPair.getPublic(); }
    public String publicKeyBase64() { return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()); }
    public byte[] sign(byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(payload);
        return signature.sign();
    }
    public static boolean verify(PublicKey key, byte[] payload, byte[] signed) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(key);
        signature.update(payload);
        return signature.verify(signed);
    }
    public static PublicKey decodePublicKey(String value) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(value);
        if (encoded.length < 32 || encoded.length > 512) throw new IllegalArgumentException("Invalid network public key size.");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }
    public static byte[] sha256(byte[] value) throws Exception { return MessageDigest.getInstance("SHA-256").digest(value); }
    public static String string(Object value) { return value instanceof String text ? text : ""; }
}
