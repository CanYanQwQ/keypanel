# CardKey API v1 TypeScript client

Independent Node.js 20+ example. It uses only Node's built-in `crypto` and `fetch` at runtime; the package's TypeScript tooling is local to this directory.

## Setup

```bash
cp .env.example .env
npm install
npm test
npm run typecheck
```

No `.env` loader is required by the library. The variables are a deployment example for an application entrypoint.

```ts
import { CardKeyClient, encryptCardKey } from './src/index.ts';

const options = {
  baseUrl: process.env.CARDKEY_BASE_URL!,
  appId: process.env.CARDKEY_APP_ID!,
  appSecret: process.env.CARDKEY_APP_SECRET!,
};
const client = new CardKeyClient(options);
const cardKey = encryptCardKey('ABCD-EFGH-JKMN-PQRS', options.appSecret, options.appId);
await client.verify({ card_key: cardKey, device_id: 'device-001' });
await client.activate({ card_key: cardKey, device_id: 'device-001' });
await client.consume({ card_key: cardKey, device_id: 'device-001', count: 1 });
await client.query({ card_key: cardKey, device_id: 'device-001' });
await client.unbind({ card_key: cardKey, device_id: 'device-001', force: false });
```


## Protocol and safety

- The body is serialized exactly once; the same raw UTF-8 bytes are hashed, signed, and sent. Do not parse and re-stringify it between these steps.
- The request canonical string is `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(raw_body)`. HMAC-SHA256 uses the UTF-8 AppSecret.
- Successful responses must carry `X-Response-Timestamp` and `X-Response-Signature`. The signature is checked against response raw bytes and the original request nonce before JSON parsing.
- Every retry must generate a fresh timestamp, nonce, signature, and body bytes. This example has no automatic retries. Never blindly retry `consume`; a timeout may occur after the server consumed a count.
- HTTPS certificate and hostname verification are left enabled by Node's `fetch`; only `http://localhost` is accepted for local examples.
- Card transport encryption uses HKDF-SHA256 and AES-256-GCM with a fresh 12-byte IV, AppID AAD, and Base64 `iv`/`data`/`tag`.
- `ApiError.code` covers the complete server error-code enum, including business failures returned with HTTP 200.

The fixed tests use only synthetic vectors from `docs/conformance/signature-v1.json` and `docs/conformance/transport-v1.json`.
