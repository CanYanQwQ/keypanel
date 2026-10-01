package com.cardkey.client

import java.net.URI
import java.net.http.HttpClient
import java.time.Duration

/** Placeholder-only configuration. Never commit real AppSecret values. */
data class ClientConfig(
    val baseUrl: URI = URI.create(System.getenv("CARDKEY_BASE_URL") ?: "https://example.invalid"),
    val appId: String = System.getenv("CARDKEY_APP_ID") ?: "ak_test_replace_me",
    val appSecret: String = System.getenv("CARDKEY_APP_SECRET") ?: "sk_test_replace_me",
    val timeout: Duration = Duration.ofSeconds(15),
    val requireResponseSignature: Boolean = true,
)

fun defaultHttpClient(config: ClientConfig): HttpClient = HttpClient.newBuilder()
    .connectTimeout(config.timeout)
    .build()
