package com.cardkey.client;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

public final class Signer {
    public static final String VERSION = "v1";
    public static final String HEADER_APP_ID = "X-App-Id";
    public static final String HEADER_TIMESTAMP = "X-Timestamp";
    public static final String HEADER_NONCE = "X-Nonce";
    public static final String HEADER_SIGNATURE = "X-Signature";
    public static final String HEADER_VERSION = "X-Signature-Version";
    public static final String HEADER_RESPONSE_SIGNATURE = "X-Response-Signature";
    public static final String HEADER_RESPONSE_TIMESTAMP = "X-Response-Timestamp";

    private Signer() {}

    public static String normalizePath(String path) {
        String value = path.split("[?#]", 2)[0];
        if (value.isEmpty()) return "/";
        value = value.replaceAll("/{2,}", "/");
        return value.length() > 1 ? value.replaceAll("/+$", "") : "/";
    }

    public static String sha256Hex(byte[] raw) { return HexFormat.of().formatHex(digest("SHA-256", raw)); }

    public static String canonicalString(String method, String path, String timestamp, String nonce, byte[] rawBody) {
        return String.join("\n", method.toUpperCase(), normalizePath(path), timestamp, nonce, sha256Hex(rawBody));
    }

    public static String sign(String appSecret, String canonical) {
        return HexFormat.of().formatHex(hmac(appSecret.getBytes(StandardCharsets.UTF_8), canonical.getBytes(StandardCharsets.UTF_8)));
    }

    public static String signRequest(String appSecret, String method, String path, String timestamp, String nonce, byte[] rawBody) {
        return sign(appSecret, canonicalString(method, path, timestamp, nonce, rawBody));
    }

    public static String responseCanonical(String timestamp, String requestNonce, byte[] rawResponse) {
        return String.join("\n", timestamp, requestNonce, sha256Hex(rawResponse));
    }

    public static boolean verifyResponse(String appSecret, byte[] rawResponse, String responseTimestamp, String requestNonce, String signature) {
        byte[] expected = sign(appSecret, responseCanonical(responseTimestamp, requestNonce, rawResponse)).toLowerCase().getBytes(StandardCharsets.US_ASCII);
        byte[] actual = signature.trim().toLowerCase().getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, actual);
    }

    public static String generateNonce() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) { throw new CardKeyApiException("HMAC-SHA256 unavailable", e); }
    }

    private static byte[] digest(String algorithm, byte[] data) {
        try { return MessageDigest.getInstance(algorithm).digest(data); }
        catch (Exception e) { throw new CardKeyApiException("Digest unavailable", e); }
    }
}
