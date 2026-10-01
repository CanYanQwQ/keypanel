package com.cardkey.client;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public final class TransportCrypto {
    public static final String INFO = "cardkey-enc-v1";
    public static final int IV_LENGTH = 12;
    public static final int TAG_LENGTH = 16;
    public static final int KEY_LENGTH = 32;

    private TransportCrypto() {}

    public static byte[] deriveKey(String appSecret, String appId) {
        byte[] prk = Signer.hmac(appId.getBytes(StandardCharsets.UTF_8), appSecret.getBytes(StandardCharsets.UTF_8));
        byte[] info = INFO.getBytes(StandardCharsets.UTF_8);
        byte[] input = new byte[info.length + 1];
        System.arraycopy(info, 0, input, 0, info.length);
        input[input.length - 1] = 1;
        byte[] block = Signer.hmac(prk, input);
        byte[] key = new byte[KEY_LENGTH];
        System.arraycopy(block, 0, key, 0, KEY_LENGTH);
        return key;
    }

    public static TransportPayload encrypt(String plaintext, String appSecret, String appId) {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deriveKey(appSecret, appId), "AES"), new GCMParameterSpec(TAG_LENGTH * 8, iv));
            cipher.updateAAD(appId.getBytes(StandardCharsets.UTF_8));
            byte[] combined = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            int split = combined.length - TAG_LENGTH;
            byte[] data = java.util.Arrays.copyOf(combined, split);
            byte[] tag = java.util.Arrays.copyOfRange(combined, split, combined.length);
            return new TransportPayload(b64(iv), b64(data), b64(tag));
        } catch (GeneralSecurityException e) { throw new CardKeyApiException("卡密加密失败", e); }
    }

    public static String decrypt(TransportPayload payload, String appSecret, String appId) {
        byte[] iv = decode(payload.iv(), IV_LENGTH, "iv");
        byte[] data = decode(payload.data(), -1, "data");
        byte[] tag = decode(payload.tag(), TAG_LENGTH, "tag");
        byte[] combined = new byte[data.length + tag.length];
        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(tag, 0, combined, data.length, tag.length);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(appSecret, appId), "AES"), new GCMParameterSpec(TAG_LENGTH * 8, iv));
            cipher.updateAAD(appId.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(combined), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) { throw new CardKeyApiException("卡密解密失败：认证标签校验不通过", e); }
    }

    private static String b64(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    private static byte[] decode(String value, int expected, String name) {
        final byte[] result;
        try { result = Base64.getDecoder().decode(value); }
        catch (IllegalArgumentException e) { throw new CardKeyApiException("加密载荷不是合法 Base64: " + name, e); }
        if (expected >= 0 && result.length != expected) throw new CardKeyApiException(name + " 长度错误");
        return result;
    }
}
