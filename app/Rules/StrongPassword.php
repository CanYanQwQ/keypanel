<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Translation\PotentiallyTranslatedString;

/**
 * 强密码校验。
 *
 * 要求：
 *   - 长度不低于配置值（默认 12）
 *   - 至少包含大写字母、小写字母、数字、特殊字符中的三类
 *   - 不在常见弱密码字典中
 *   - 不包含邮箱前缀或用户名
 *   - 不是单一字符重复或连续序列
 */
class StrongPassword implements ValidationRule
{
    /**
     * 常见弱密码片段（小写匹配）。
     *
     * @var array<int, string>
     */
    protected const COMMON_PASSWORDS = [
        'password', 'passw0rd', '123456', '12345678', '123456789', '1234567890',
        'qwerty', 'qwertyuiop', 'abc123', 'admin', 'administrator', 'root',
        'letmein', 'welcome', 'monkey', 'dragon', 'master', 'sunshine',
        'iloveyou', 'princess', 'football', 'baseball', 'starwars',
        'superman', 'trustno1', 'whatever', 'zaq12wsx', 'asdfghjkl',
        '1qaz2wsx', 'qazwsx', 'secret', 'changeme', 'test123', 'p@ssw0rd',
        'cardkey', 'kamisystem', '888888', '666666', '000000', '111111',
    ];

    public function __construct(
        protected ?string $email = null,
        protected ?string $name = null,
        protected ?int $minLength = null,
    ) {
        $this->minLength ??= (int) config('cardkey.settings.security.password_min_length.default', 12);
    }

    /**
     * @param  Closure(string, ?string=): PotentiallyTranslatedString  $fail
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $password = (string) $value;

        if ($password === '') {
            $fail('密码不能为空。');

            return;
        }

        // ---- 长度 ----
        if (mb_strlen($password) < $this->minLength) {
            $fail("密码长度不得少于 {$this->minLength} 位。");

            return;
        }

        if (mb_strlen($password) > 128) {
            $fail('密码长度不得超过 128 位。');

            return;
        }

        // ---- 字符种类：至少 3 类 ----
        $classes = 0;
        $classes += preg_match('/[a-z]/', $password) ? 1 : 0;
        $classes += preg_match('/[A-Z]/', $password) ? 1 : 0;
        $classes += preg_match('/[0-9]/', $password) ? 1 : 0;
        $classes += preg_match('/[^a-zA-Z0-9]/', $password) ? 1 : 0;

        if ($classes < 3) {
            $fail('密码必须同时包含大写字母、小写字母、数字、特殊字符中的至少三类。');

            return;
        }

        // ---- 弱密码字典 ----
        $lower = mb_strtolower($password);

        foreach (self::COMMON_PASSWORDS as $common) {
            if (str_contains($lower, $common)) {
                $fail('密码包含常见的弱密码片段，请更换。');

                return;
            }
        }

        // ---- 不得包含账号信息 ----
        foreach ([$this->email, $this->name] as $personal) {
            if (blank($personal)) {
                continue;
            }

            $localPart = str_contains((string) $personal, '@')
                ? strstr((string) $personal, '@', true)
                : (string) $personal;

            if (mb_strlen($localPart) >= 3 && str_contains($lower, mb_strtolower($localPart))) {
                $fail('密码不得包含邮箱或用户名。');

                return;
            }
        }

        // ---- 不得为单一字符重复 ----
        if (preg_match('/^(.)\1+$/u', $password)) {
            $fail('密码不能是重复的单一字符。');

            return;
        }

        // ---- 不得为连续序列 ----
        if ($this->isSequential($password)) {
            $fail('密码不能是连续的数字或字母序列。');

            return;
        }
    }

    /**
     * 检测整串是否为连续递增/递减序列（如 abcdefgh、98765432）。
     */
    protected function isSequential(string $password): bool
    {
        $length = strlen($password);

        if ($length < 4) {
            return false;
        }

        $ascending = true;
        $descending = true;

        for ($i = 1; $i < $length; $i++) {
            $delta = ord($password[$i]) - ord($password[$i - 1]);

            if ($delta !== 1) {
                $ascending = false;
            }

            if ($delta !== -1) {
                $descending = false;
            }
        }

        return $ascending || $descending;
    }
}
