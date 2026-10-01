package com.cardkey.client

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Signer {
    const val VERSION = "v1"
    const val HEADER_APP_ID = "X-App-Id"
    const val HEADER_TIMESTAMP = "X-Timestamp"
    const val HEADER_NONCE = "X-Nonce"
    const val HEADER_SIGNATURE = "X-Signature"
    const val HEADER_VERSION = "X-Signature-Version"
    const val HEADER_RESPONSE_SIGNATURE = "X-Response-Signature"
    const val HEADER_RESPONSE_TIMESTAMP = "X-Response-Timestamp"

    fun normalizePath(path: String): String {
        val withoutQuery = path.substringBefore('#').substringBefore('?')
        if (withoutQuery.isEmpty()) return "/"
        val collapsed = withoutQuery.replace(Regex("/{2,}"), "/")
        return if (collapsed.length > 1) collapsed.trimEnd('/') else "/"
    }

    fun sha256Hex(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).toHex()

    fun canonicalString(method: String, path: String, timestamp: String, nonce: String, rawBody: ByteArray): String =
        listOf(method.uppercase(), normalizePath(path), timestamp, nonce, sha256Hex(rawBody)).joinToString("\n")

    fun sign(appSecret: String, canonical: String): String = hmacSha256Hex(
        appSecret.toByteArray(StandardCharsets.UTF_8), canonical.toByteArray(StandardCharsets.UTF_8)
    )

    fun signRequest(appSecret: String, method: String, path: String, timestamp: String, nonce: String, rawBody: ByteArray): String =
        sign(appSecret, canonicalString(method, path, timestamp, nonce, rawBody))

    fun responseCanonical(timestamp: String, requestNonce: String, rawResponse: ByteArray): String =
        listOf(timestamp, requestNonce, sha256Hex(rawResponse)).joinToString("\n")

    fun verifyResponse(appSecret: String, rawResponse: ByteArray, responseTimestamp: String, requestNonce: String, signature: String): Boolean {
        val expected = sign(appSecret, responseCanonical(responseTimestamp, requestNonce, rawResponse))
        return MessageDigest.isEqual(expected.lowercase().toByteArray(), signature.trim().lowercase().toByteArray())
    }

    fun generateNonce(bytes: Int = 16): String {
        require(bytes > 0)
        val value = ByteArray(bytes)
        SecureRandom().nextBytes(value)
        return value.toHex()
    }

    private fun hmacSha256Hex(key: ByteArray, data: ByteArray): String = Mac.getInstance("HmacSHA256")
        .apply { init(SecretKeySpec(key, "HmacSHA256")) }
        .doFinal(data).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
