# CardKey API v1 PHP client

Independent PHP 8.2+ example. Runtime dependencies are PHP extensions only: cURL, OpenSSL, hash, and JSON. Composer is used only for PSR-4 autoloading in this directory; it does not depend on the Laravel application.

## Setup and fixed-vector test

```bash
composer install
php tests/conformance.php
```

The current repository environment does not provide Composer, so the command is documented but was not runnable here. The conformance script can be run after installing Composer, or the source can be loaded with an equivalent PSR-4 autoloader.

```php
use CardKey\Client;
use CardKey\TransportCrypto;

$appId = getenv('CARDKEY_APP_ID');
$secret = getenv('CARDKEY_APP_SECRET');
$client = new Client(getenv('CARDKEY_BASE_URL'), $appId, $secret);
$card = TransportCrypto::encrypt('ABCD-EFGH-JKMN-PQRS', $secret, $appId)->toArray();
$client->verify(['card_key' => $card, 'device_id' => 'device-001']);
$client->activate(['card_key' => $card, 'device_id' => 'device-001']);
$client->consume(['card_key' => $card, 'device_id' => 'device-001', 'count' => 1]);
$client->query(['card_key' => $card, 'device_id' => 'device-001']);
$client->unbind(['card_key' => $card, 'device_id' => 'device-001', 'force' => false]);
```

## Protocol and safety

The client calls `json_encode()` exactly once and passes that same raw string to both `Signer::signRequest()` and `CURLOPT_POSTFIELDS`; do not decode/re-encode it between signing and sending. Responses are verified over raw response bytes with `X-Response-Timestamp` and the original request nonce before `json_decode()`.

The client enables cURL TLS certificate and hostname verification. Use HTTPS in production; HTTP is accepted only for localhost examples. Each retry must create fresh timestamp, nonce, signature, and body. No automatic retries are included, and `consume` must not be blindly retried after a timeout. AppSecret is never placed in URLs or logs.

Transport encryption derives a 32-byte HKDF-SHA256 key from AppSecret (IKM), AppID (salt), and `cardkey-enc-v1` (info), then uses AES-256-GCM with a new 12-byte IV, AppID AAD, and 16-byte tag. Payload fields are standard Base64. `ApiException` exposes all server error codes from the enum and is raised for both HTTP errors and business failures returned in HTTP 200.

Only synthetic vectors from `docs/conformance/` are used.
