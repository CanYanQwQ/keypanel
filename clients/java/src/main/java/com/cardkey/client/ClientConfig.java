package com.cardkey.client;

import java.net.URI;
import java.time.Duration;

/** Placeholder-only configuration. Use a secret manager or environment in production. */
public record ClientConfig(
        URI baseUrl,
        String appId,
        String appSecret,
        Duration timeout,
        boolean requireResponseSignature
) {
    public static ClientConfig fromEnvironment() {
        return new ClientConfig(
                URI.create(env("CARDKEY_BASE_URL", "https://example.invalid")),
                env("CARDKEY_APP_ID", "ak_test_replace_me"),
                env("CARDKEY_APP_SECRET", "sk_test_replace_me"),
                Duration.ofSeconds(15),
                true
        );
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
