# CardKey API v1 C++/Qt6 client

Independent Qt6 Core/Network and OpenSSL 3 example.

## Build and tests

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The current environment may not have a Qt6 development kit installed; CMake will report that limitation during verification. OpenSSL 3 is required for HKDF, HMAC, SHA-256, and AES-256-GCM.

## API usage

`CardKeyClient` exposes `verify`, `activate`, `consume`, `query`, and `unbind`. It returns a unified `ApiResponse` with `code`, `message`, `success`, `serverTime`, and JSON data. Business failures can still be HTTP 200, so inspect both HTTP status and the response fields.

The request object serializes the compact JSON body once, signs the exact UTF-8 bytes, and sends the same bytes through `QNetworkAccessManager`. Response signatures are verified before JSON parsing using the actual raw response bytes, `X-Response-Timestamp`, and the original request nonce.

## Security notes

- Use HTTPS and Qt's default certificate/hostname validation in production. Do not install an ignore-all SSL configuration.
- Never log AppSecret or complete card keys. `Config` values are placeholders only; use a platform secret store or environment injection.
- Retry only a safe operation with a fresh timestamp, nonce, signature, and body. `consume` is not automatically retried because the API has no idempotency key.
- Transport encryption uses HKDF-SHA256(IKM=AppSecret, salt=AppID, info=`cardkey-enc-v1`, length=32), AES-256-GCM, fresh 12-byte IV, AppID AAD, 16-byte tag, and standard Base64 `iv`/`data`/`tag`.
- GCM authentication failures are rejected.

`tests/protocol_vector_test.cpp` uses only the synthetic shared conformance vectors.
