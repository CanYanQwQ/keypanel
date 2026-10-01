package com.cardkey.client

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant

/** Minimal Kotlin/JVM 17 client. Exact serialized bytes are signed and sent. */
class CardKeyClient(
    private val config: ClientConfig,
    private val http: java.net.http.HttpClient = defaultHttpClient(config),
    private val mapper: ObjectMapper = jacksonObjectMapper(),
    private val clock: () -> Long = { Instant.now().epochSecond },
    private val nonceFactory: () -> String = { Signer.generateNonce() },
) {
    init {
        val scheme = config.baseUrl.scheme.lowercase()
        val host = config.baseUrl.host.lowercase()
        require(scheme == "https" || (scheme == "http" && host in setOf("localhost", "127.0.0.1", "::1"))) {
            "Use HTTPS in production; HTTP is allowed only for localhost examples"
        }
    }

    fun verify(cardKey: CardKeyValue, deviceId: String? = null): ApiResponse = post("verify", payload(cardKey, deviceId))
    fun activate(cardKey: CardKeyValue, deviceId: String? = null): ApiResponse = post("activate", payload(cardKey, deviceId))
    /** No automatic retry: consume has no server-side idempotency key. */
    fun consume(cardKey: CardKeyValue, deviceId: String? = null, count: Int = 1): ApiResponse {
        require(count in 1..1000) { "count must be between 1 and 1000" }
        return post("consume", buildMap {
            put("card_key", cardKeyValue(cardKey))
            if (deviceId != null) put("device_id", deviceId)
            put("count", count)
        })
    }
    fun query(cardKey: CardKeyValue, deviceId: String? = null): ApiResponse = post("query", payload(cardKey, deviceId))
    fun unbind(cardKey: CardKeyValue, deviceId: String? = null, force: Boolean = false): ApiResponse = post("unbind", buildMap {
        put("card_key", cardKeyValue(cardKey))
        if (deviceId != null) put("device_id", deviceId)
        if (force) put("force", true)
    })

    /** Opt-in retry for safe operations. Each attempt gets a new nonce and signature. */
    fun post(path: String, body: Map<String, Any?>, retryOnIoFailure: Boolean = false, maxAttempts: Int = 2): ApiResponse {
        require(maxAttempts >= 1)
        var attempt = 0
        while (true) {
            attempt++
            val rawBody = mapper.writeValueAsBytes(body)
            try { return requestOnce(path, rawBody) }
            catch (e: CardKeyApiException) {
                if (!retryOnIoFailure || e.cause !is java.io.IOException || attempt >= maxAttempts) throw e
            }
        }
    }

    private fun requestOnce(path: String, rawBody: ByteArray): ApiResponse {
        val normalizedPath = Signer.normalizePath(path)
        val timestamp = clock().toString()
        val nonce = nonceFactory()
        val request = HttpRequest.newBuilder(config.baseUrl.resolve(normalizedPath))
            .timeout(config.timeout)
            .header(Signer.HEADER_APP_ID, config.appId)
            .header(Signer.HEADER_TIMESTAMP, timestamp)
            .header(Signer.HEADER_NONCE, nonce)
            .header(Signer.HEADER_VERSION, Signer.VERSION)
            .header(Signer.HEADER_SIGNATURE, Signer.signRequest(config.appSecret, "POST", normalizedPath, timestamp, nonce, rawBody))
            .header("Content-Type", "application/json").header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofByteArray(rawBody)).build()
        val response = try { http.send(request, HttpResponse.BodyHandlers.ofByteArray()) }
        catch (e: java.io.IOException) { throw CardKeyApiException("请求失败", e) }
        catch (e: InterruptedException) { Thread.currentThread().interrupt(); throw CardKeyApiException("请求被中断", e) }
        val rawResponse = response.body()
        if (config.requireResponseSignature) {
            val responseTimestamp = response.headers().firstValue(Signer.HEADER_RESPONSE_TIMESTAMP).orElse(null)
            val responseSignature = response.headers().firstValue(Signer.HEADER_RESPONSE_SIGNATURE).orElse(null)
            if (responseTimestamp == null || responseSignature == null) {
                if (response.statusCode() in 200..299) throw ResponseSignatureException("响应签名缺失")
            } else if (!Signer.verifyResponse(config.appSecret, rawResponse, responseTimestamp, nonce, responseSignature)) {
                throw ResponseSignatureException("响应签名校验失败")
            }
        }
        val parsed = try { mapper.readTree(rawResponse) } catch (e: Exception) { throw CardKeyApiException("响应不是合法 JSON", e) }
        return ApiResponse(parsed.path("code").asInt(-1), parsed.path("message").asText("未知错误"), parsed.path("success").asBoolean(false), parsed.get("server_time")?.takeUnless(JsonNode::isNull)?.asLong(), parsed.get("data")?.takeUnless(JsonNode::isNull), response.statusCode())
    }

    private fun payload(cardKey: CardKeyValue, deviceId: String?): Map<String, Any?> = buildMap {
        put("card_key", cardKeyValue(cardKey))
        if (deviceId != null) put("device_id", deviceId)
    }

    private fun cardKeyValue(cardKey: CardKeyValue): Any = when (cardKey) {
        is CardKeyValue.Plain -> cardKey.value
        is CardKeyValue.Encrypted -> mapOf("iv" to cardKey.payload.iv, "data" to cardKey.payload.data, "tag" to cardKey.payload.tag)
    }
}
