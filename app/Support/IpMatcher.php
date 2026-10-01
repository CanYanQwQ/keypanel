<?php

namespace App\Support;

/**
 * IP 白名单匹配，支持单个 IPv4/IPv6 地址与 CIDR 网段。
 */
class IpMatcher
{
    /**
     * 判断给定 IP 是否命中白名单中的任意一条规则。
     *
     * @param  array<int, string>|null  $whitelist  规则列表，如 ['203.0.113.7', '10.0.0.0/8']
     */
    public static function matches(?string $ip, ?array $whitelist): bool
    {
        // 未配置白名单 = 不限制
        if (empty($whitelist)) {
            return true;
        }

        if ($ip === null || $ip === '') {
            return false;
        }

        foreach ($whitelist as $rule) {
            $rule = trim((string) $rule);

            if ($rule === '') {
                continue;
            }

            // 通配全部
            if ($rule === '*' || $rule === '0.0.0.0/0' || $rule === '::/0') {
                return true;
            }

            if (str_contains($rule, '/')) {
                if (self::inCidr($ip, $rule)) {
                    return true;
                }

                continue;
            }

            if (self::sameAddress($ip, $rule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断 IP 是否落在 CIDR 网段内。同时支持 IPv4 与 IPv6。
     */
    public static function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);

        if ($bits === null || ! is_numeric($bits)) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton((string) $subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // 版本不一致（v4 对 v6）直接不匹配
        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bits = (int) $bits;
        $maxBits = strlen($ipBin) * 8;

        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        // 比较整字节部分
        if ($wholeBytes > 0 && substr($ipBin, 0, $wholeBytes) !== substr($subnetBin, 0, $wholeBytes)) {
            return false;
        }

        // 比较剩余位
        if ($remainingBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainingBits) & 0xFF;

        return (ord($ipBin[$wholeBytes]) & $mask) === (ord($subnetBin[$wholeBytes]) & $mask);
    }

    /**
     * 比较两个 IP 是否等价（自动处理 IPv4-mapped IPv6，如 ::ffff:127.0.0.1）。
     */
    public static function sameAddress(string $a, string $b): bool
    {
        $aBin = @inet_pton($a);
        $bBin = @inet_pton($b);

        if ($aBin === false || $bBin === false) {
            return false;
        }

        return $aBin === $bBin;
    }
}
