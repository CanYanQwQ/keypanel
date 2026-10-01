# CardKey API v1 JavaScript client

Independent Node.js 20+ ESM example using only built-in `crypto` and `fetch`.

```bash
cp .env.example .env
npm test
```

```js
import { CardKeyClient, encryptCardKey } from './src/index.mjs';

const options = {
  baseUrl: process.env.CARDKEY_BASE_URL,
  appId: process.env.CARDKEY_APP_ID,
  appSecret: process.env.CARDKEY_APP_SECRET,
};
const client = new CardKeyClient(options);
const cardKey = encryptCardKey('ABCD-EFGH-JKMN-PQRS', options.appSecret, options.appId);
await client.verify({ card_key: cardKey, device_id: 'device-001' });
await client.activate({ card_key: cardKey, device_id: 'device-001' });
await client.consume({ card_key: cardKey, device_id: 'device-001', count: 1 });
await client.query({ card_key: cardKey, device_id: 'device-001' });
await client.unbind({ card_key: cardKey, device_id: 'device-001', force: false });
```

The client checks HTTP status, `success`, and every API error `code`, including business failures returned with HTTP 200. It verifies `X-Response-Signature` over response raw bytes with `X-Response-Timestamp` and the original request nonce before parsing JSON.

Security notes:

- JSON is serialized once; exactly those bytes are hashed, signed, and sent.
- Use HTTPS in production. Node fetch keeps TLS certificate and hostname validation enabled; only localhost HTTP is accepted for local examples.
- A retry must generate a new timestamp, nonce, signature, and body. There is no automatic retry. Do not blindly retry `consume` after a timeout.
- Never log or expose `CARDKEY_APP_SECRET`.
- Transport encryption is HKDF-SHA256(AppSecret, salt=AppID, info=`cardkey-enc-v1`, 32 bytes) plus AES-256-GCM with a fresh 12-byte IV, AppID AAD, and Base64 `iv`/`data`/`tag`.

Tests use only synthetic vectors from `docs/conformance/`.
