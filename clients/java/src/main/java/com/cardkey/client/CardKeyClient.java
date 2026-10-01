package com.cardkey.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

public final class CardKeyClient {
    private final ClientConfig config;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final Supplier<Long> clock;
    private final Supplier<String> nonceFactory;

    public CardKeyClient(ClientConfig config) { this(config, HttpClient.newBuilder().connectTimeout(config.timeout()).build(), new ObjectMapper(), () -> Instant.now().getEpochSecond(), Signer::generateNonce); }
    CardKeyClient(ClientConfig config, HttpClient http, ObjectMapper mapper, Supplier<Long> clock, Supplier<String> nonceFactory) {
        this.config = config; this.http = http; this.mapper = mapper; this.clock = clock; this.nonceFactory = nonceFactory;
        if (!config.baseUrl().getScheme().equalsIgnoreCase("https") && !isLocalHttp(config.baseUrl())) throw new IllegalArgumentException("Use HTTPS in production; HTTP only for localhost examples");
    }

    public ApiResponse verify(CardKeyValue cardKey, String deviceId) { return post("verify", cardInput(cardKey, deviceId)); }
    public ApiResponse activate(CardKeyValue cardKey, String deviceId) { return post("activate", cardInput(cardKey, deviceId)); }
    /** No automatic retry: consume has no server-side idempotency key. */
    public ApiResponse consume(CardKeyValue cardKey, String deviceId, int count) {
        if (count < 1 || count > 1000) throw new IllegalArgumentException("count must be between 1 and 1000");
        Map<String, Object> body = cardInput(cardKey, deviceId); body.put("count", count); return post("consume", body);
    }
    public ApiResponse query(CardKeyValue cardKey, String deviceId) { return post("query", cardInput(cardKey, deviceId)); }
    public ApiResponse unbind(CardKeyValue cardKey, String deviceId, boolean force) {
        Map<String, Object> body = cardInput(cardKey, deviceId); if (force) body.put("force", true); return post("unbind", body);
    }

    private ApiResponse post(String method, Map<String, Object> body) {
        String path = "/api/v1/" + method;
        final byte[] rawBody;
        try { rawBody = mapper.writeValueAsBytes(body); } catch (IOException e) { throw new CardKeyApiException("无法序列化请求", e); }
        String timestamp = Long.toString(clock.get());
        String nonce = nonceFactory.get();
        HttpRequest request = HttpRequest.newBuilder(config.baseUrl().resolve(Signer.normalizePath(path)))
                .timeout(config.timeout())
                .header(Signer.HEADER_APP_ID, config.appId()).header(Signer.HEADER_TIMESTAMP, timestamp)
                .header(Signer.HEADER_NONCE, nonce).header(Signer.HEADER_VERSION, Signer.VERSION)
                .header(Signer.HEADER_SIGNATURE, Signer.signRequest(config.appSecret(), "POST", path, timestamp, nonce, rawBody))
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(rawBody)).build();
        HttpResponse<byte[]> response;
        try { response = http.send(request, HttpResponse.BodyHandlers.ofByteArray()); }
        catch (IOException e) { throw new CardKeyApiException("请求失败", e); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new CardKeyApiException("请求被中断", e); }
        byte[] rawResponse = response.body();
        if (config.requireResponseSignature()) {
            String responseTimestamp = response.headers().firstValue(Signer.HEADER_RESPONSE_TIMESTAMP).orElse(null);
            String responseSignature = response.headers().firstValue(Signer.HEADER_RESPONSE_SIGNATURE).orElse(null);
            if (responseTimestamp == null || responseSignature == null) {
                if (response.statusCode() >= 200 && response.statusCode() <= 299) throw new ResponseSignatureException("响应签名缺失");
            } else if (!Signer.verifyResponse(config.appSecret(), rawResponse, responseTimestamp, nonce, responseSignature)) {
                throw new ResponseSignatureException("响应签名校验失败");
            }
        }
        final JsonNode json;
        try { json = mapper.readTree(rawResponse); } catch (IOException e) { throw new CardKeyApiException("响应不是合法 JSON", e); }
        return new ApiResponse(json.path("code").asInt(-1), json.path("message").asText("未知错误"), json.path("success").asBoolean(false), json.hasNonNull("server_time") ? json.get("server_time").asLong() : null, json.hasNonNull("data") ? json.get("data") : null, response.statusCode());
    }

    private static Map<String, Object> cardInput(CardKeyValue cardKey, String deviceId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("card_key", cardJson(cardKey)); if (deviceId != null) body.put("device_id", deviceId); return body;
    }
    private static Object cardJson(CardKeyValue value) {
        if (value instanceof PlainCardKey plain) return plain.value();
        TransportPayload p = ((EncryptedCardKey) value).payload(); return Map.of("iv", p.iv(), "data", p.data(), "tag", p.tag());
    }
    private static boolean isLocalHttp(java.net.URI uri) { String host = uri.getHost(); return uri.getScheme().equalsIgnoreCase("http") && ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)); }
}
