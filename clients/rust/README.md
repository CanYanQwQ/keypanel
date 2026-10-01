# CardKey API v1 Rust client

Independent Rust 2021 example using `reqwest`, `serde`, `hmac`, `sha2`, `hkdf`, `aes-gcm`, `rand`, and `base64`.

## Setup and tests

```bash
cargo test
cargo run -- verify ABCD-EFGH-JKMN-PQRS
```

The runnable example reads `CARDKEY_BASE_URL`, `CARDKEY_APP_ID`, and `CARDKEY_APP_SECRET` from the environment. `.env.example` contains only synthetic placeholders.

```rust
let client = CardKeyClient::new(&base_url, &app_id, &secret)?;
let card = encrypt_card_key("ABCD-EFGH-JKMN-PQRS", &secret, &app_id)?;
client.verify(serde_json::json!({"card_key": card, "device_id": "device-001"})).await?;
client.activate(serde_json::json!({"card_key": card, "device_id": "device-001"})).await?;
client.consume(serde_json::json!({"card_key": card, "device_id": "device-001", "count": 1})).await?;
client.query(serde_json::json!({"card_key": card, "device_id": "device-001"})).await?;
client.unbind(serde_json::json!({"card_key": card, "device_id": "device-001", "force": false})).await?;
```

## Protocol and safety

The request JSON is serialized once into `raw_body`; those exact bytes are hashed, signed, and passed to reqwest as the request body. Do not reserialize after signing. A retry must generate a new timestamp, nonce, signature, and body; no automatic retries are provided. Do not blindly retry `consume` after a timeout because the original operation may have completed.

Response signing is checked over raw response bytes using `X-Response-Timestamp` and the original request nonce before deserialization. The client checks HTTP status, `code`, and `success`, including business errors returned with HTTP 200. Use HTTPS in production; reqwest's rustls transport keeps TLS certificate and hostname validation enabled, and only localhost HTTP is allowed by the constructor. AppSecret is held in memory and never logged or put in a URL.

Transport encryption is HKDF-SHA256 with AppSecret as IKM, AppID as salt, `cardkey-enc-v1` as info, and a 32-byte output, followed by AES-256-GCM with a fresh 12-byte IV, AppID AAD, 16-byte tag, and standard Base64 `iv`/`data`/`tag` fields.

The conformance tests use synthetic vectors from `docs/conformance/` only.
