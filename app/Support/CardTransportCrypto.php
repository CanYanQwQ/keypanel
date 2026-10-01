<?php

namespace App\Support;

/**
 * 卡密传输加密（客户端 <-> 服务端）。
 *
 * 目的：即使 HTTPS 被降级或中间人代理存在，卡密明文也不会出现在请求体/响应体中。
 *
 * 方案：HKDF-SHA256 从 AppSecret 派生独立的加密密钥（与签名密钥用途隔离），
 *      再用 AES-256-GCM 做认证加密。
 *
 *   加密密钥 = HKDF-SHA256(ikm = AppSecret, salt = AppID, info = "cardkey-enc-v1", L = 32)
 *
 * 载荷统一格式（各语言模板一致）：
 *   {
 *     "iv":   base64(12 字节随机数),
 *     "data": base64(密文),
 *     "tag":  base64(16 字节认证标签)
 *   }
 *
 * AAD（附加认证数据）固定为 AppID，把密文与具体应用绑定，
 * 防止把 A 应用的密文拿到 B 应用重放。
 */
class CardTransportCrypto
{
    public const INFO = 'cardkey-enc-v1';

    public const CIPHER = 'aes-256-gcm';

    public const IV_LENGTH = 12;

    public const TAG_LENGTH = 16;

    public const KEY_LENGTH = 32;

    /**
     * 从 AppSecret 派生传输加密密钥。
     */
    public static function deriveKey(string $appSecret, string $appId): string
    {
        return hash_hkdf('sha256', $appSecret, self::KEY_LENGTH, self::INFO, $appId);
    }

    /**
     * 加密卡密，返回可 JSON 序列化的载荷数组。
     *
     * @return array{iv: string, data: string, tag: string}
     */
    public static function encrypt(string $plaintext, string $key, string $aad): array
    {
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('卡密加密失败：'.openssl_error_string());
        }

        return [
            'iv' => base64_encode($iv),
            'data' => base64_encode($ciphertext),
            'tag' => base64_encode($tag),
        ];
    }

    /**
     * 解密客户端提交的卡密载荷。
     *
     * @param  array{iv?: string, data?: string, tag?: string}  $payload
     *
     * @throws \RuntimeException 载荷格式错误或认证失败（被篡改）
     */
    public static function decrypt(array $payload, string $key, string $aad): string
    {
        $iv = base64_decode((string) ($payload['iv'] ?? ''), true);
        $data = base64_decode((string) ($payload['data'] ?? ''), true);
        $tag = base64_decode((string) ($payload['tag'] ?? ''), true);

        if ($iv === false || $data === false || $tag === false) {
            throw new \RuntimeException('加密载荷不是合法的 base64 编码');
        }

        if (strlen($iv) !== self::IV_LENGTH) {
            throw new \RuntimeException('IV 长度必须为 '.self::IV_LENGTH.' 字节');
        }

        if (strlen($tag) !== self::TAG_LENGTH) {
            throw new \RuntimeException('认证标签长度必须为 '.self::TAG_LENGTH.' 字节');
        }

        $plaintext = openssl_decrypt(
            $data,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
        );

        // GCM 认证失败时返回 false —— 说明密文被篡改或密钥不对
        if ($plaintext === false) {
            throw new \RuntimeException('卡密解密失败：认证标签校验不通过');
        }

        return $plaintext;
    }

    /**
     * 判断请求中的 card_key 字段是否为加密载荷对象。
     */
    public static function isEncryptedPayload(mixed $value): bool
    {
        return is_array($value)
            && isset($value['iv'], $value['data'], $value['tag']);
    }
}
