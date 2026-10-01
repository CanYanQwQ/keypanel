<?php

declare(strict_types=1);

namespace CardKey;

final class Client
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $appId,
        private readonly string $appSecret,
        private readonly int $timeoutSeconds = 15,
        private readonly bool $requireResponseSignature = true,
    ) {
        $url = parse_url($this->baseUrl);
        $scheme = strtolower((string) ($url['scheme'] ?? ''));
        $host = strtolower((string) ($url['host'] ?? ''));
        if ($scheme !== 'https' && !($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true))) {
            throw new \InvalidArgumentException('Use HTTPS in production; HTTP is allowed only for localhost examples');
        }
    }

    /** @param array<string, mixed> $input */
    public function verify(array $input): ApiResponse { return $this->post('verify', $input); }
    /** @param array<string, mixed> $input */
    public function activate(array $input): ApiResponse { return $this->post('activate', $input); }
    /** @param array<string, mixed> $input */
    public function consume(array $input): ApiResponse { return $this->post('consume', $input); }
    /** @param array<string, mixed> $input */
    public function query(array $input): ApiResponse { return $this->post('query', $input); }
    /** @param array<string, mixed> $input */
    public function unbind(array $input): ApiResponse { return $this->post('unbind', $input); }

    /** @param array<string, mixed> $input */
    private function post(string $method, array $input): ApiResponse
    {
        $path = "/api/v1/{$method}";
        // Encode once: the exact raw JSON bytes are hashed, signed, and sent as CURLOPT_POSTFIELDS.
        $rawBody = json_encode($input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $timestamp = (string) time();
        $nonce = Signer::generateNonce();
        $headers = [
            'Accept: application/json',
            'Content-Type: application/json',
            'X-App-Id: '.$this->appId,
            'X-Timestamp: '.$timestamp,
            'X-Nonce: '.$nonce,
            'X-Signature-Version: v1',
            'X-Signature: '.Signer::signRequest($this->appSecret, 'POST', $path, $timestamp, $nonce, $rawBody),
        ];
        $responseHeaders = [];
        $curl = curl_init(rtrim($this->baseUrl, '/').$path);
        if ($curl === false) {
            throw new CardKeyException('Unable to initialize cURL');
        }
        curl_setopt_array($curl, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $rawBody,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders): int {
                $separator = strpos($line, ':');
                if ($separator !== false) {
                    $responseHeaders[strtolower(trim(substr($line, 0, $separator)))] = trim(substr($line, $separator + 1));
                }
                return strlen($line);
            },
            CURLOPT_CONNECTTIMEOUT => $this->timeoutSeconds,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $rawResponseBody = curl_exec($curl);
        $httpStatus = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);
        if ($rawResponseBody === false) {
            throw new CardKeyException('CardKey request failed: '.$curlError);
        }
        $this->verifyResponse($responseHeaders, $rawResponseBody, $nonce, $httpStatus);
        try {
            $payload = json_decode($rawResponseBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new ProtocolException('The API response is not valid JSON', 0, $exception);
        }
        if (!is_array($payload)) {
            throw new ProtocolException('The API response must be a JSON object');
        }
        $result = ApiResponse::fromArray($payload);
        if ($httpStatus < 200 || $httpStatus >= 300 || $result->code !== 0 || !$result->success) {
            throw new ApiException($result->code, $result->message, $httpStatus, $result);
        }
        return $result;
    }

    /** @param array<string, string> $headers */
    private function verifyResponse(array $headers, string $rawBody, string $requestNonce, int $httpStatus): void
    {
        $signature = $headers['x-response-signature'] ?? null;
        $timestamp = $headers['x-response-timestamp'] ?? null;
        if ($signature === null || $timestamp === null) {
            if ($this->requireResponseSignature && $httpStatus >= 200 && $httpStatus < 300) {
                throw new ResponseSignatureException('Missing response signature headers');
            }
            return;
        }
        $expected = Signer::signResponse($this->appSecret, $timestamp, $requestNonce, $rawBody);
        if (!hash_equals($expected, strtolower(trim($signature)))) {
            throw new ResponseSignatureException('Response signature verification failed');
        }
    }
}
