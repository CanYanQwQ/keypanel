package com.cardkey.client

import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object TransportCrypto {
    const val INFO = "cardkey-enc-v1"
    const val IV_LENGTH = 12
    const val TAG_LENGTH = 16
    const val KEY_LENGTH = 32

    /** HKDF-Extract + HKDF-Expand, with AppID as salt and info. */
    fun deriveKey(appSecret: String, appId: String): ByteArray {
        val salt = appId.toByteArray(StandardCharsets.UTF_8)
        val ikm = appSecret.toByteArray(StandardCharsets.UTF_8)
        val prk = hmac(salt, ikm)
        val info = INFO.toByteArray(StandardCharsets.UTF_8)
        val block = hmac(prk, info + byteArrayOf(1))
        return block.copyOf(KEY_LENGTH)
    }

    fun encrypt(plaintext: String, appSecret: String, appId: String, random: SecureRandom = SecureRandom()): TransportPayload {
        val iv = ByteArray(IV_LENGTH).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(deriveKey(appSecret, appId), "AES"), GCMParameterSpec(TAG_LENGTH * 8, iv))
        cipher.updateAAD(appId.toByteArray(StandardCharsets.UTF_8))
        val combined = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        val ciphertextLength = combined.size - TAG_LENGTH
        return TransportPayload(
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(combined.copyOf(ciphertextLength)),
            Base64.getEncoder().encodeToString(combined.copyOfRange(ciphertextLength, combined.size)),
        )
    }

    fun decrypt(payload: TransportPayload, appSecret: String, appId: String): String {
        val iv = decode(payload.iv, IV_LENGTH, "iv")
        val ciphertext = decode(payload.data, -1, "data")
        val tag = decode(payload.tag, TAG_LENGTH, "tag")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(deriveKey(appSecret, appId), "AES"), GCMParameterSpec(TAG_LENGTH * 8, iv))
        cipher.updateAAD(appId.toByteArray(StandardCharsets.UTF_8))
        return try {
            String(cipher.doFinal(ciphertext + tag), StandardCharsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            throw CardKeyApiException("卡密解密失败：认证标签校验不通过", e)
        }
    }

    private fun decode(value: String, expectedLength: Int, field: String): ByteArray {
        val bytes = try { Base64.getDecoder().decode(value) } catch (e: IllegalArgumentException) {
            throw CardKeyApiException("加密载荷字段不是合法的 Base64：$field", e)
        }
        if (expectedLength >= 0 && bytes.size != expectedLength) throw CardKeyApiException("$field 长度错误")
        return bytes
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256")
        .apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
}
