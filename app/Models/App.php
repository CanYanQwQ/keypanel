<?php

namespace App\Models;

use App\Enums\AppStatus;
use App\Support\IpMatcher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

/**
 * 接入应用。每个应用持有独立的 AppID / AppSecret。
 */
class App extends Model
{
    protected $fillable = [
        'name',
        'app_id',
        'app_secret',
        'app_secret_encrypted',
        'secret_prefix',
        'secret_rotated_at',
        'status',
        'description',
        'ip_whitelist',
        'rate_limit_per_minute',
        'daily_quota',
        'timestamp_tolerance',
        'require_encrypted_card',
        'last_used_at',
    ];

    protected $hidden = [
        'app_secret',
        'app_secret_encrypted',
    ];

    protected function casts(): array
    {
        return [
            'status' => AppStatus::class,
            'ip_whitelist' => 'array',
            'secret_rotated_at' => 'datetime',
            'last_used_at' => 'datetime',
            'require_encrypted_card' => 'boolean',
            'rate_limit_per_minute' => 'integer',
            'daily_quota' => 'integer',
            'timestamp_tolerance' => 'integer',
        ];
    }

    // ------------------------------------------------------------------
    // 密钥：数据库内为 AES-256-GCM 密文，通过 app_secret 虚拟属性读写
    // ------------------------------------------------------------------

    /**
     * 读取 AppSecret 明文（仅服务端验签与后台「查看密钥」时使用）。
     */
    public function getAppSecretAttribute(): ?string
    {
        $payload = $this->attributes['app_secret_encrypted'] ?? null;

        if (blank($payload)) {
            return null;
        }

        try {
            return Crypt::decryptString($payload);
        } catch (\Throwable) {
            // APP_KEY 变更或数据损坏时不应让整个后台崩溃
            return null;
        }
    }

    public function setAppSecretAttribute(?string $plain): void
    {
        $this->attributes['app_secret_encrypted'] = blank($plain)
            ? null
            : Crypt::encryptString($plain);

        if (filled($plain)) {
            $this->attributes['secret_prefix'] = Str::substr($plain, 0, 12).'…';
        }
    }

    /**
     * 常量时间比对 AppSecret，避免时序侧信道。
     */
    public function verifySecret(?string $plain): bool
    {
        $actual = $this->app_secret;

        if (blank($actual) || blank($plain)) {
            return false;
        }

        return hash_equals($actual, $plain);
    }

    /**
     * 重置密钥，返回新的明文（仅此一次可完整获取，之后仍可在后台查看）。
     */
    public function rotateSecret(): string
    {
        $plain = self::generateSecret();

        $this->app_secret = $plain;
        $this->secret_rotated_at = now();
        $this->save();

        return $plain;
    }

    // ------------------------------------------------------------------
    // 生成器
    // ------------------------------------------------------------------

    public static function generateAppId(): string
    {
        do {
            $appId = 'ak_'.bin2hex(random_bytes(8));
        } while (self::where('app_id', $appId)->exists());

        return $appId;
    }

    /**
     * 生成 256 位熵的 AppSecret。
     */
    public static function generateSecret(): string
    {
        return 'sk_'.bin2hex(random_bytes(32));
    }

    // ------------------------------------------------------------------
    // 状态与权限判断
    // ------------------------------------------------------------------

    public function isEnabled(): bool
    {
        return $this->status === AppStatus::Enabled;
    }

    public function isIpAllowed(?string $ip): bool
    {
        return IpMatcher::matches($ip, $this->ip_whitelist);
    }

    public function hasIpWhitelist(): bool
    {
        return ! empty(array_filter((array) $this->ip_whitelist));
    }

    // ------------------------------------------------------------------
    // 关联
    // ------------------------------------------------------------------

    public function cardKeys(): HasMany
    {
        return $this->hasMany(CardKey::class);
    }

    public function batches(): HasMany
    {
        return $this->hasMany(CardKeyBatch::class);
    }

    public function verificationLogs(): HasMany
    {
        return $this->hasMany(VerificationLog::class);
    }

    public function dailyUsages(): HasMany
    {
        return $this->hasMany(AppDailyUsage::class, 'app_id', 'app_id');
    }

    public function scopeEnabled(Builder $query): Builder
    {
        return $query->where('status', AppStatus::Enabled->value);
    }

    /**
     * 后台列表展示用的名称（附带 AppID）。
     */
    public function getDisplayNameAttribute(): string
    {
        return "{$this->name} ({$this->app_id})";
    }
}
