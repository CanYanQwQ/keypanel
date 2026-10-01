# CardKey API v1 Python client

Independent Python 3.10+ example using `requests` and `cryptography`.

## Setup and tests

```bash
python -m venv .venv
.venv\\Scripts\\activate       # Windows
# source .venv/bin/activate      # POSIX
python -m pip install -e .
set PYTHONPATH=src && python -m unittest discover -s tests -v   # Windows cmd
# PYTHONPATH=src python -m unittest discover -s tests -v        # POSIX
```

The package does not load `.env` automatically. Copy `.env.example` into your deployment secret mechanism instead.

```python
from cardkey_client import CardKeyClient, encrypt_card_key

app_id = os.environ["CARDKEY_APP_ID"]
secret = os.environ["CARDKEY_APP_SECRET"]
client = CardKeyClient(os.environ["CARDKEY_BASE_URL"], app_id, secret)
card = encrypt_card_key("ABCD-EFGH-JKMN-PQRS", secret, app_id)
client.verify(card_key=card, device_id="device-001")
client.activate(card_key=card, device_id="device-001")
client.consume(card_key=card, device_id="device-001", count=1)
client.query(card_key=card, device_id="device-001")
client.unbind(card_key=card, device_id="device-001", force=False)
```

## Protocol and safety

The request body is serialized once with compact UTF-8 JSON. The exact bytes are passed through `requests` as `data=raw_body`, not re-encoded through the `json=` parameter. Every timeout retry, if an application chooses to add one, must create a fresh timestamp, nonce, signature, and raw body. This example has no automatic retries; never blindly retry `consume` because the first request may have succeeded.

Responses are verified using the raw `response.content` bytes, `X-Response-Timestamp`, and the original request nonce before JSON parsing. The client checks HTTP status, `code`, and `success`; all server error codes from `ApiErrorCode` are included in `errors.py`, including business failures returned with HTTP 200. Missing response signatures are tolerated only on error responses because the server can reject middleware requests before the signed controller response.

Use HTTPS with normal certificate and hostname verification in production. HTTP is accepted only for localhost examples. Never log, print, or place the AppSecret in a URL. Card transport encryption is HKDF-SHA256 with AppSecret as IKM, AppID as salt, `cardkey-enc-v1` as info, and AES-256-GCM using a fresh 12-byte IV, AppID AAD, and Base64 `iv`/`data`/`tag`.

Tests use only the synthetic fixed vectors under `docs/conformance/`.
