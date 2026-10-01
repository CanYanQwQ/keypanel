<?php

declare(strict_types=1);

namespace CardKey;

final class TransportCrypto
{
    public const INFO = 'cardkey-enc-v1';
    public const IV_LENGTH = 12;
    public const TAG_LENGTH = 16;
    public const KEY_LENGTH = 32;

    public static function deriveKey(string $appSecret, string $appId): string
    {
        $key = hash_hkdf('sha256', $appSecret, self::KEY_LENGTH, self::INFO, $appId);
        if (strlen($key) !== self::KEY_LENGTH) {
            throw new CardKeyException('HKDF did not return a 32-byte key');
        }
        return $key;
    }

    public static function encrypt(string $plaintext, string $appSecret, string $appId): EncryptedCardKey
    {
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', self::deriveKey($appSecret, $appId), OPENSSL_RAW_DATA, $iv, $tag, $appId, self::TAG_LENGTH);
        if ($ciphertext === false || strlen($tag) !== self::TAG_LENGTH) {
            throw new CardKeyException('CardKey encryption failed');
        }
        return new EncryptedCardKey(base64_encode($iv), base64_encode($ciphertext), base64_encode($tag));
    }

    /** @param array{iv: string, data: string, tag: string} $payload */
    public static function decrypt(array $payload, string $appSecret, string $appId): string
    {
        $iv = self::decode($payload['iv'] ?? '');
        $data = self::decode($payload['data'] ?? '');
        $tag = self::decode($payload['tag'] ?? '');
        if (strlen($iv) !== self::IV_LENGTH || strlen($tag) !== self::TAG_LENGTH) {
            throw new CardKeyException('Invalid CardKey transport payload length');
        }
        $plaintext = openssl_decrypt($data, 'aes-256-gcm', self::deriveKey($appSecret, $appId), OPENSSL_RAW_DATA, $iv, $tag, $appId);
        if ($plaintext === false) {
            throw new CardKeyException('CardKey GCM authentication failed');
        }
        return $plaintext;
    }

    private static function decode(string $value): string
    {
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new CardKeyException('Encrypted CardKey fields must be valid Base64');
        }
        return $decoded;
    }
}
