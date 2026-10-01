# CardKey API v1 Go client

Independent Go 1.26+ example. The client uses only the standard library, including `net/http`, `crypto/hmac`, `crypto/hkdf`, `crypto/aes`, and `crypto/cipher`.

## Setup and tests

```bash
go test ./...
go run ./cmd/example verify ABCD-EFGH-JKMN-PQRS device-001
```

Set `CARDKEY_BASE_URL`, `CARDKEY_APP_ID`, and `CARDKEY_APP_SECRET` in the environment before running the example. The test vectors use synthetic values from `docs/conformance/` only.

```go
client, _ := cardkey.NewClient(os.Getenv("CARDKEY_BASE_URL"), appID, secret)
card, _ := cardkey.EncryptCardKey("ABCD-EFGH-JKMN-PQRS", secret, appID)
client.Verify(map[string]any{"card_key": card, "device_id": "device-001"})
client.Activate(map[string]any{"card_key": card, "device_id": "device-001"})
client.Consume(map[string]any{"card_key": card, "device_id": "device-001", "count": 1})
client.Query(map[string]any{"card_key": card, "device_id": "device-001"})
client.Unbind(map[string]any{"card_key": card, "device_id": "device-001", "force": false})
```

The exact bytes returned by `json.Marshal` are sent from the same `bytes.Reader` after signing. Do not marshal a second time or use a differently formatted body. A retry must generate a fresh timestamp, nonce, signature, and body. No automatic retries are included; never blindly retry `Consume`, because a timeout can happen after the server has decremented the card.

The HTTP client performs normal TLS certificate and hostname verification. Production URLs must use HTTPS; only localhost HTTP is accepted for local examples. AppSecret is used in memory only and is never logged or put in a URL. Response signatures are checked over raw response bytes with `X-Response-Timestamp` and the original request nonce before JSON decoding. HTTP status, `code`, and `success` are all checked, including business errors returned with HTTP 200.

Transport crypto uses HKDF-SHA256(AppSecret, salt=AppID, info=`cardkey-enc-v1`, length=32), AES-256-GCM, random 12-byte IV, AppID AAD, 16-byte tag, and standard Base64 fields.
