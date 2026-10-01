# CardKey API v1 Java client

Independent Java 17+ Maven example using `java.net.http.HttpClient`, Jackson, and the JDK cryptography providers.

## Setup and tests

```bash
mvn test
```

Set `CARDKEY_BASE_URL`, `CARDKEY_APP_ID`, and `CARDKEY_APP_SECRET` in the process environment. `src/main/java/com/cardkey/client/ClientConfig.java` contains placeholders only and the example entry point does not call the server.

## API usage

```java
ClientConfig config = ClientConfig.fromEnvironment();
CardKeyClient client = new CardKeyClient(config);
CardKeyValue card = CardKeyValue.encrypted(
    TransportCrypto.encrypt("ABCD-EFGH-JKMN-PQRS", config.appSecret(), config.appId())
);
client.verify(card, "device-001");
client.activate(card, "device-001");
client.consume(card, "device-001", 1); // no blind retry
client.query(card, "device-001");
client.unbind(card, "device-001", false);
```

The five POST methods return the same `ApiResponse`/`ApiErrorCode` model. Callers inspect HTTP status, `code`, and `success` because business failures may use HTTP 200. JSON is serialized once into UTF-8 bytes and those exact bytes are signed and sent. A retry must create a fresh timestamp, nonce, signature, and raw body. `consume` is never retried automatically because the server has no idempotency key.

Response signatures are checked before JSON parsing using the raw response bytes, `X-Response-Timestamp`, and the original request nonce. Missing signatures are rejected by default for successful responses; middleware-level failures may legitimately have no signature, so error-tolerant handling is explicit.

## Security notes

- Use HTTPS and the platform's normal certificate/hostname validation in production. Do not add a trust-all TLS context.
- Never log or persist AppSecret or complete card keys. All configuration values shown here are placeholders.
- Transport encryption is HKDF-SHA256 with AppSecret as IKM, AppID as salt, `cardkey-enc-v1` as info, 32-byte output; AES-256-GCM uses a fresh 12-byte IV, AppID AAD, 16-byte tag, and standard Base64 fields.
- GCM authentication failures are rejected.

## Fixed vectors

`ProtocolVectorTest` verifies the shared request signature, HKDF/AES-GCM transport vector, and response signature over exact raw bytes from the synthetic conformance files.
