<?php

declare(strict_types=1);

namespace CardKey;

final class Signer
{
    public const VERSION = 'v1';

    public static function normalizePath(string $path): string
    {
        $path = preg_split('/[?#]/', $path, 2)[0] ?? '';
        if ($path === '') {
            return '/';
        }
        $path = preg_replace('#/+#', '/', $path) ?? $path;
        return strlen($path) > 1 ? rtrim($path, '/') : $path;
    }

    public static function canonicalRequest(string $method, string $path, string $timestamp, string $nonce, string $rawBody = ''): string
    {
        return implode("\n", [strtoupper($method), self::normalizePath($path), $timestamp, $nonce, hash('sha256', $rawBody)]);
    }

    public static function signRequest(string $appSecret, string $method, string $path, string $timestamp, string $nonce, string $rawBody = ''): string
    {
        return hash_hmac('sha256', self::canonicalRequest($method, $path, $timestamp, $nonce, $rawBody), $appSecret);
    }

    public static function canonicalResponse(string $responseTimestamp, string $requestNonce, string $rawResponseBody): string
    {
        return implode("\n", [$responseTimestamp, $requestNonce, hash('sha256', $rawResponseBody)]);
    }

    public static function signResponse(string $appSecret, string $responseTimestamp, string $requestNonce, string $rawResponseBody): string
    {
        return hash_hmac('sha256', self::canonicalResponse($responseTimestamp, $requestNonce, $rawResponseBody), $appSecret);
    }

    public static function generateNonce(int $bytes = 16): string
    {
        return bin2hex(random_bytes($bytes));
    }
}
