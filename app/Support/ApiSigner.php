<?php

namespace App\Support;

/**
 * API 请求签名 v1。
 *
 * 规范（所有语言/框架的客户端模板必须完全一致）：
 *
 *   待签名字符串 canonical =
 *       METHOD        + "\n" +
 *       PATH          + "\n" +
 *       TIMESTAMP     + "\n" +
 *       NONCE         + "\n" +
 *       SHA256_HEX(raw_body)
 *
 *   X-Signature = HEX( HMAC-SHA256( key = AppSecret, data = canonical ) )
 *
 * 其中：
 *   METHOD    —— 大写 HTTP 方法，如 POST
 *   PATH      —— 不含查询串的请求路径，如 /api/v1/verify
 *   TIMESTAMP —— Unix 秒级时间戳（十进制字符串）
 *   NONCE     —— 每次请求唯一的随机串（建议 16~32 位，十六进制或 Base64）
 *   raw_body  —— 原始请求体字节；无请求体时为空串 ""
 *
 * 说明：先对 body 求摘要再拼接，可避免 body 中的换行符破坏 canonical 结构。
 */
class ApiSigner
{
    public const VERSION = 'v1';

    public const HEADER_APP_ID = 'X-App-Id';

    public const HEADER_TIMESTAMP = 'X-Timestamp';

    public const HEADER_NONCE = 'X-Nonce';

    public const HEADER_SIGNATURE = 'X-Signature';

    public const HEADER_VERSION = 'X-Signature-Version';

    /**
     * 组装待签名字符串。
     */
    public static function canonicalString(
        string $method,
        string $path,
        string $timestamp,
        string $nonce,
        string $rawBody = '',
    ): string {
        return implode("\n", [
            strtoupper($method),
            self::normalizePath($path),
            (string) $timestamp,
            (string) $nonce,
            hash('sha256', $rawBody),
        ]);
    }

    /**
     * 计算签名。
     */
    public static function sign(string $appSecret, string $canonical): string
    {
        return hash_hmac('sha256', $canonical, $appSecret);
    }

    /**
     * 一步到位：直接由请求要素计算签名。
     */
    public static function signRequest(
        string $appSecret,
        string $method,
        string $path,
        string $timestamp,
        string $nonce,
        string $rawBody = '',
    ): string {
        return self::sign($appSecret, self::canonicalString($method, $path, $timestamp, $nonce, $rawBody));
    }

    /**
     * 常量时间比对签名，避免时序攻击。
     */
    public static function verify(string $appSecret, string $canonical, string $signature): bool
    {
        $expected = self::sign($appSecret, $canonical);

        // 统一小写后比对，兼容客户端输出大写十六进制的情况
        return hash_equals($expected, strtolower(trim($signature)));
    }

    /**
     * 计算响应体签名，供客户端校验服务端返回未被篡改。
     *
     *   X-Response-Signature = HEX(HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + SHA256_HEX(body)))
     */
    public static function signResponse(string $appSecret, string $rawBody, string $timestamp, string $nonce): string
    {
        $canonical = implode("\n", [
            (string) $timestamp,
            (string) $nonce,
            hash('sha256', $rawBody),
        ]);

        return self::sign($appSecret, $canonical);
    }

    /**
     * 生成一个随机 nonce。
     */
    public static function generateNonce(int $bytes = 16): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * 路径归一化：去掉查询串、折叠重复斜杠、去掉末尾斜杠（根路径除外）。
     */
    public static function normalizePath(string $path): string
    {
        // 去掉查询串与 fragment
        $path = preg_split('/[?#]/', $path, 2)[0] ?? '';

        if ($path === '') {
            return '/';
        }

        // 折叠重复斜杠
        $path = preg_replace('#/+#', '/', $path) ?? $path;

        // 去掉末尾斜杠，但保留根路径
        if (strlen($path) > 1) {
            $path = rtrim($path, '/');
        }

        return $path;
    }
}
