<?php

namespace App\Support;

use Illuminate\Support\Facades\Crypt;

/**
 * 卡密编解码工具。
 *
 * 存储策略（双列）：
 *   - code_hash      ：SHA-256 摘要，唯一索引，用于 O(1) 检索。不可逆。
 *   - code_encrypted ：AES-256-GCM 密文，供后台反复查看 / 复制 / 导出。
 *
 * 为什么不给 hash 加 salt/pepper：
 *   卡密本身是 16 位、取自 31 字符集的高熵随机串（约 2^79 种可能），
 *   暴力枚举与彩虹表在计算上不可行，因此可直接使用快速摘要以便检索。
 *   而低熵的用户密码则必须用 bcrypt/argon2 —— 两者场景不同。
 */
class CardKeyCodec
{
    /**
     * 卡密字符集：剔除易混淆字符 0/O、1/I/L。
     */
    public const CHARSET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

    public const DEFAULT_GROUPS = 4;

    public const DEFAULT_GROUP_SIZE = 4;

    /**
     * 生成一个卡密明文，例如 ABCD-EFGH-JKMN-PQRS。
     *
     * @param  string|null  $prefix  业务前缀，如 "VIP"，最终形如 VIP-ABCD-EFGH-JKMN-PQRS
     */
    public static function generate(?string $prefix = null, int $groups = self::DEFAULT_GROUPS, int $groupSize = self::DEFAULT_GROUP_SIZE): string
    {
        $charsetMax = strlen(self::CHARSET) - 1;
        $segments = [];

        for ($g = 0; $g < $groups; $g++) {
            $segment = '';

            for ($i = 0; $i < $groupSize; $i++) {
                $segment .= self::CHARSET[random_int(0, $charsetMax)];
            }

            $segments[] = $segment;
        }

        $prefix = $prefix !== null ? self::normalizePrefix($prefix) : null;

        return ($prefix !== null ? $prefix.'-' : '').implode('-', $segments);
    }

    /**
     * 归一化：转大写、去除分隔符与空白，用于哈希与比对。
     * 这样用户输入 "abcd efgh" 或 "ABCD-EFGH" 都能命中同一条记录。
     */
    public static function normalize(string $code): string
    {
        return preg_replace('/[^0-9A-Z]/', '', strtoupper(trim($code))) ?? '';
    }

    /**
     * 归一化前缀（仅保留 A-Z0-9，最长 8 位）。
     */
    public static function normalizePrefix(string $prefix): ?string
    {
        $clean = preg_replace('/[^0-9A-Z]/', '', strtoupper(trim($prefix))) ?? '';

        return $clean === '' ? null : substr($clean, 0, 8);
    }

    /**
     * 计算检索用摘要。
     */
    public static function hash(string $code): string
    {
        return hash('sha256', self::normalize($code));
    }

    /**
     * 把归一化后的卡密按固定长度重新分组，便于展示与复制。
     */
    public static function format(string $code, int $groupSize = self::DEFAULT_GROUP_SIZE): string
    {
        $raw = self::normalize($code);

        if ($raw === '') {
            return '';
        }

        return implode('-', str_split($raw, $groupSize));
    }

    /**
     * 生成掩码，如 ABCD-****-****-PQRS。
     *
     * 安全要求：日志与列表一律使用掩码，绝不落库完整明文。
     */
    public static function mask(string $code): string
    {
        $raw = self::normalize($code);
        $length = strlen($raw);

        if ($length === 0) {
            return '';
        }

        // 过短的卡密（异常情况）只保留首尾各 1 位
        if ($length <= 8) {
            $head = substr($raw, 0, 1);
            $tail = substr($raw, -1);

            return $head.str_repeat('*', max(0, $length - 2)).$tail;
        }

        $groups = str_split($raw, self::DEFAULT_GROUP_SIZE);
        $lastIndex = count($groups) - 1;

        foreach ($groups as $i => $group) {
            if ($i === 0 || $i === $lastIndex) {
                continue;
            }

            $groups[$i] = str_repeat('*', strlen($group));
        }

        return implode('-', $groups);
    }

    /**
     * 提取明文前缀（前 4 位），用于后台模糊搜索。
     */
    public static function prefixOf(string $code): ?string
    {
        $raw = self::normalize($code);

        return $raw === '' ? null : substr($raw, 0, 4);
    }

    /**
     * 加密存储（AES-256-GCM，密钥来自 APP_KEY）。
     */
    public static function encrypt(string $code): string
    {
        return Crypt::encryptString(self::normalize($code));
    }

    /**
     * 解密读取。数据损坏或 APP_KEY 变更时返回 null 而不是抛异常。
     */
    public static function decrypt(?string $payload): ?string
    {
        if (blank($payload)) {
            return null;
        }

        try {
            return Crypt::decryptString($payload);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * 校验卡密格式是否合法（长度与字符集）。
     */
    public static function isWellFormed(string $code): bool
    {
        $raw = self::normalize($code);

        if (strlen($raw) < 8 || strlen($raw) > 64) {
            return false;
        }

        return (bool) preg_match('/^[0-9A-Z]+$/', $raw);
    }
}
