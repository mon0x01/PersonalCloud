package dev.personalcloud.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import dev.personalcloud.android.core.Json;
import dev.personalcloud.android.core.StateStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Base64;

/** Encrypts peer tokens, invitations and configuration at rest with an Android Keystore AES-GCM key. */
public final class AndroidStateStore implements StateStore {
    private static final String ALIAS = "personalcloud.peer.state.v1";
    private final SharedPreferences prefs;
    public AndroidStateStore(Context context) { prefs = context.getSharedPreferences("personalcloud_secure_state", Context.MODE_PRIVATE); }

    @Override public synchronized Map<String,Object> load() throws Exception {
        String value=prefs.getString("peer_state",null);if(value==null)return new LinkedHashMap<String,Object>();
        return Json.object(decrypt(value));
    }
    @Override public synchronized void save(Map<String,Object> state) throws Exception {
        String encrypted=encrypt(Json.stringify(state));if(!prefs.edit().putString("peer_state",encrypted).commit())throw new IllegalStateException("Could not persist encrypted peer state.");
    }
    public synchronized void putConfig(String key,String value)throws Exception{Map<String,Object> config=readConfig();config.put(key,value);if(!prefs.edit().putString("config",encrypt(Json.stringify(config))).commit())throw new IllegalStateException("Could not save encrypted configuration.");}
    public synchronized String getConfig(String key)throws Exception{return String.valueOf(readConfig().getOrDefault(key,""));}
    @Override public synchronized Map<String,Object> loadDomain(String domain)throws Exception{String safe=validateDomain(domain);String value=prefs.getString("domain_"+safe,null);return value==null?new LinkedHashMap<String,Object>():Json.object(decrypt(value));}
    @Override public synchronized void saveDomain(String domain,Map<String,Object> state)throws Exception{String safe=validateDomain(domain);String encrypted=encrypt(Json.stringify(state));if(!prefs.edit().putString("domain_"+safe,encrypted).commit())throw new IllegalStateException("Could not persist encrypted "+safe+" state.");}
    private static String validateDomain(String value){if(value==null||!value.matches("[a-z0-9_-]{1,48}"))throw new IllegalArgumentException("Invalid state domain.");return value;}
    private Map<String,Object> readConfig()throws Exception{String value=prefs.getString("config",null);return value==null?new LinkedHashMap<String,Object>():Json.object(decrypt(value));}
    private String encrypt(String text)throws Exception{Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());byte[] encrypted=cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));byte[] iv=cipher.getIV();byte[] all=new byte[iv.length+encrypted.length];System.arraycopy(iv,0,all,0,iv.length);System.arraycopy(encrypted,0,all,iv.length,encrypted.length);return Base64.getEncoder().encodeToString(all);}
    private String decrypt(String value)throws Exception{byte[] all=Base64.getDecoder().decode(value);if(all.length<29)throw new IllegalStateException("Encrypted state is truncated.");byte[] iv=new byte[12],data=new byte[all.length-12];System.arraycopy(all,0,iv,0,12);System.arraycopy(all,12,data,0,data.length);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,iv));return new String(cipher.doFinal(data),StandardCharsets.UTF_8);}
    private SecretKey key()throws Exception{KeyStore ks=KeyStore.getInstance("AndroidKeyStore");ks.load(null);if(ks.containsAlias(ALIAS))return (SecretKey)ks.getKey(ALIAS,null);KeyGenerator gen=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");gen.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build());return gen.generateKey();}
}
