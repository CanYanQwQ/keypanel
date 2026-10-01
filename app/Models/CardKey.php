<?php

namespace App\Models;

use App\Enums\CardStatus;
use App\Enums\CardType;
use App\Enums\DurationUnit;
use App\Support\CardKeyCodec;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * 卡密。
 *
 * 安全设计：
 *   - 明文永不落库；code_hash 用于检索，code_encrypted 用于后台查看/导出。
 *   - 日志中只出现 code_masked。
 */
class CardKey extends Model
{
    use HasFactory;

    protected $fillable = [
        'app_id',
        'batch_id',
        'code_hash',
        'code_encrypted',
        'code_masked',
        'code_prefix',
        'type',
        'status',
        'duration_value',
        'duration_unit',
        'max_uses',
        'used_count',
        'activated_at',
        'expires_at',
        'device_id',
        'device_bound_at',
        'bind_count',
        'max_devices',
        'last_verified_at',
        'last_verify_ip',
        'disabled_at',
        'disabled_reason',
        'note',
        'created_by',
    ];

    protected $hidden = [
        'code_hash',
        'code_encrypted',
    ];

    protected function casts(): array
    {
        return [
            'type' => CardType::class,
            'status' => CardStatus::class,
            'duration_unit' => DurationUnit::class,
            'duration_value' => 'integer',
            'max_uses' => 'integer',
            'used_count' => 'integer',
            'bind_count' => 'integer',
            'max_devices' => 'integer',
            'activated_at' => 'datetime',
            'expires_at' => 'datetime',
            'device_bound_at' => 'datetime',
            'last_verified_at' => 'datetime',
            'disabled_at' => 'datetime',
        ];
    }

    // ==================================================================
    // 卡密明文的读写
    // ==================================================================

    /**
     * 设置卡密明文：自动派生 hash / 密文 / 掩码 / 前缀。
     */
    public function setCodeAttribute(string $code): void
    {
        $this->attributes['code_hash'] = CardKeyCodec::hash($code);
        $this->attributes['code_encrypted'] = CardKeyCodec::encrypt($code);
        $this->attributes['code_masked'] = CardKeyCodec::mask($code);
        $this->attributes['code_prefix'] = CardKeyCodec::prefixOf($code);
    }

    /**
     * 读取卡密明文（后台查看 / 复制 / 导出）。
     */
    public function getCodeAttribute(): ?string
    {
        return CardKeyCodec::decrypt($this->attributes['code_encrypted'] ?? null);
    }

    /**
     * 带分组的展示形式，如 ABCD-EFGH-JKMN-PQRS。
     */
    public function getDisplayCodeAttribute(): string
    {
        $code = $this->code;

        return $code === null ? ($this->code_masked ?? '—') : CardKeyCodec::format($code);
    }

    /**
     * 按明文查找卡密（O(1)，走 code_hash 唯一索引）。
     */
    public static function findByCode(string $code): ?self
    {
        return static::where('code_hash', CardKeyCodec::hash($code))->first();
    }

    // ==================================================================
    // 状态与权益
    // ==================================================================

    /**
     * 依据当前时间与用量推导出的真实状态（不落库）。
     */
    public function resolveStatus(): CardStatus
    {
        // 管理员禁用优先级最高，不会被自动状态覆盖
        if ($this->status === CardStatus::Disabled) {
            return CardStatus::Disabled;
        }

        if ($this->expires_at !== null && $this->expires_at->isPast()) {
            return CardStatus::Expired;
        }

        if ($this->isDepleted()) {
            return CardStatus::Depleted;
        }

        if ($this->activated_at !== null) {
            return CardStatus::Activated;
        }

        return CardStatus::Unused;
    }

    /**
     * 把推导出的状态写回数据库（由定时任务批量调用）。
     */
    public function syncStatus(): bool
    {
        $resolved = $this->resolveStatus();

        if ($resolved === $this->status) {
            return false;
        }

        $this->status = $resolved;
        $this->save();

        return true;
    }

    public function isDepleted(): bool
    {
        return $this->type === CardType::Count
            && $this->max_uses !== null
            && $this->used_count >= $this->max_uses;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * 当前是否可以被正常使用。
     */
    public function isUsable(): bool
    {
        return $this->resolveStatus()->isUsable();
    }

    /**
     * 剩余次数。永久卡与时间卡返回 null（表示不限次）。
     */
    public function remainingUses(): ?int
    {
        if ($this->type !== CardType::Count || $this->max_uses === null) {
            return null;
        }

        return max(0, $this->max_uses - $this->used_count);
    }

    /**
     * 计算激活后的到期时间。永久卡与次数卡返回 null。
     */
    public function computeExpiresAt(?CarbonInterface $from = null): ?CarbonInterface
    {
        if (! $this->type->expiresAfterActivation()) {
            return null;
        }

        if ($this->duration_value === null || $this->duration_unit === null) {
            return null;
        }

        return $this->duration_unit->addTo($from ?? now(), $this->duration_value);
    }

    /**
     * 距离到期还有多少秒（已过期或永久卡返回 null）。
     */
    public function secondsUntilExpiry(): ?int
    {
        if ($this->expires_at === null) {
            return null;
        }

        return max(0, (int) now()->diffInSeconds($this->expires_at, false));
    }

    public function isBound(): bool
    {
        return filled($this->device_id);
    }

    /**
     * 判断某个设备是否可以继续使用本卡密。
     */
    public function deviceMatches(?string $deviceId): bool
    {
        // 未绑定设备时不做设备校验（是否强制绑定由调用方决定）
        if (! $this->isBound()) {
            return true;
        }

        if (blank($deviceId)) {
            return false;
        }

        return hash_equals((string) $this->device_id, (string) $deviceId);
    }

    // ==================================================================
    // 展示辅助
    // ==================================================================

    public function getEntitlementLabelAttribute(): string
    {
        return match (true) {
            $this->type === CardType::Permanent => '永久有效',
            $this->type === CardType::Count => "{$this->used_count} / {$this->max_uses} 次",
            $this->duration_value !== null && $this->duration_unit !== null
                => $this->duration_value.' '.$this->duration_unit->shortLabel(),
            default => '—',
        };
    }

    public function getRemainingDaysAttribute(): ?int
    {
        if ($this->expires_at === null) {
            return null;
        }

        return (int) now()->diffInDays($this->expires_at, false);
    }

    // ==================================================================
    // 关联
    // ==================================================================

    public function app(): BelongsTo
    {
        return $this->belongsTo(App::class);
    }

    public function batch(): BelongsTo
    {
        return $this->belongsTo(CardKeyBatch::class, 'batch_id');
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function verificationLogs(): HasMany
    {
        return $this->hasMany(VerificationLog::class);
    }

    // ==================================================================
    // 查询作用域
    // ==================================================================

    public function scopeUsable(Builder $query): Builder
    {
        return $query->whereIn('status', [CardStatus::Unused->value, CardStatus::Activated->value])
            ->where(fn (Builder $q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()));
    }

    public function scopeExpiringSoon(Builder $query, int $days = 7): Builder
    {
        return $query->where('status', CardStatus::Activated->value)
            ->whereNotNull('expires_at')
            ->whereBetween('expires_at', [now(), now()->addDays($days)]);
    }

    public function scopeOfStatus(Builder $query, CardStatus $status): Builder
    {
        return $query->where('status', $status->value);
    }

    public function scopeOfType(Builder $query, CardType $type): Builder
    {
        return $query->where('type', $type->value);
    }
}
