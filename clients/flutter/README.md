# CardKey API v1 Dart/Flutter client

Independent Dart client code that can be used by a Flutter app. The package is intentionally small and keeps transport protocol code separate from UI code.

## Setup and tests

```bash
dart pub get
dart test
```

If Flutter is installed, `flutter pub get` and `flutter test` are equivalent for this package. The current verification environment may not include Dart/Flutter; in that case the commands are the documented validation path.

Set `CARDKEY_BASE_URL`, `CARDKEY_APP_ID`, and `CARDKEY_APP_SECRET` in the host application or pass `ClientConfig` explicitly. No real credentials are included. The example entry point does not send a network request.

## API usage

```dart
final config = ClientConfig(
  baseUrl: Uri.parse('https://api.example.invalid'),
  appId: 'ak_test_replace_me',
  appSecret: 'sk_test_replace_me',
);
final client = CardKeyClient(config);
final card = CardKeyValue.encrypted(
  TransportCrypto.encrypt('ABCD-EFGH-JKMN-PQRS', config.appSecret, config.appId),
);
await client.verify(card, deviceId: 'device-001');
await client.activate(card, deviceId: 'device-001');
await client.consume(card, deviceId: 'device-001', count: 1); // never blindly retry
await client.query(card, deviceId: 'device-001');
await client.unbind(card, deviceId: 'device-001', force: false);
```

The client serializes the request JSON once as UTF-8, signs those exact bytes, and sends those exact bytes. A retry, if implemented by the caller for a safe operation, must create fresh timestamp, nonce, signature, and raw body. `consume` is not automatically retried because the server has no idempotency key.

Response signatures are checked before JSON parsing from raw response bytes, `X-Response-Timestamp`, and the original request nonce. The response model includes `code`, `message`, `success`, `serverTime`, optional `data`, and the complete shared `ApiErrorCode` mapping. Callers must inspect HTTP status, `code`, and `success`; business failures may be HTTP 200.

## Security notes

- Use HTTPS with normal platform certificate and hostname verification in production. Do not use a trust-all `SecurityContext` or certificate callback.
- Never log, print, bundle, or persist AppSecret or complete card keys.
- Transport encryption is HKDF-SHA256(IKM=AppSecret, salt=AppID, info=`cardkey-enc-v1`, length=32) and AES-256-GCM with a fresh 12-byte IV, AppID AAD, 16-byte tag, and standard Base64 fields.
- GCM authentication failures are rejected. Fixed vectors are synthetic and not production credentials.
