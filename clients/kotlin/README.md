# CardKey API v1 Kotlin client

Independent Kotlin/JVM example targeting JDK 17+ with Gradle Kotlin DSL.

## Setup and tests

```bash
gradle test
# Or use a locally installed Gradle wrapper/toolchain if your environment provides one.
```

The example reads `CARDKEY_BASE_URL`, `CARDKEY_APP_ID`, and `CARDKEY_APP_SECRET` from the environment. Values in `Config.kt` are placeholders only. The sample `Main.kt` does not call the server.

## API usage

```kotlin
val config = ClientConfig()
val client = CardKeyClient(config)
val encrypted = CardKeyValue.Encrypted(TransportCrypto.encrypt("ABCD-EFGH-JKMN-PQRS", config.appSecret, config.appId))
client.verify(encrypted, "device-001")
client.activate(encrypted, "device-001")
client.consume(encrypted, "device-001", count = 1) // no blind retry
client.query(encrypted, "device-001")
client.unbind(encrypted, "device-001", force = false)
```

`CardKeyClient` exposes all five POST operations and returns a unified `ApiResponse`. Callers must inspect HTTP status at the transport boundary plus `code`, `success`, and `error`; business failures can use HTTP 200. The request JSON is serialized once, and those exact UTF-8 bytes are both signed and sent. If an application opts into a retry for a safe operation, each attempt gets a fresh timestamp, nonce, signature, and request body. `consume` is intentionally not retried because the API has no idempotency key.

Response signatures are checked before JSON parsing using the raw response bytes, `X-Response-Timestamp`, and the original request nonce. Middleware rejection responses may not carry response-signature headers; only a configured error-tolerant caller should disable the strict check.

## Security notes

- Use HTTPS with normal hostname and certificate validation in production. Do not install a trust-all TLS manager.
- Never log, print, bundle, or persist `AppSecret`, and never log complete card keys.
- Transport encryption is HKDF-SHA256(IKM=AppSecret, salt=AppID, info=`cardkey-enc-v1`, length=32), then AES-256-GCM with a fresh 12-byte IV, AppID AAD, a 16-byte tag, and standard Base64 `iv`/`data`/`tag`.
- GCM authentication failures are rejected. The synthetic test vectors are not real credentials.

## Fixed vectors

`ProtocolVectorTest` mirrors `docs/conformance/signature-v1.json` and `transport-v1.json`, and also verifies response signatures over raw response bytes. It uses only synthetic values.
