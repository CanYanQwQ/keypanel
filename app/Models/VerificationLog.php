<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * 卡密验证日志（追加写，不更新）。
 *
 * 安全要求：本表绝不写入完整卡密明文，只记录 code_masked。
 */
class VerificationLog extends Model
{
    public const UPDATED_AT = null;

    protected $fillable = [
        'app_id',
        'card_key_id',
        'code_masked',
        'action',
        'result',
        'message',
        'ip',
        'device_id',
        'user_agent',
        'request_id',
        'meta',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'meta' => 'array',
            'created_at' => 'datetime',
        ];
    }

    public function app(): BelongsTo
    {
        return $this->belongsTo(App::class);
    }

    public function cardKey(): BelongsTo
    {
        return $this->belongsTo(CardKey::class);
    }

    public function isSuccess(): bool
    {
        return $this->result === 'success';
    }

    public function scopeSuccessful(Builder $query): Builder
    {
        return $query->where('result', 'success');
    }

    public function scopeFailed(Builder $query): Builder
    {
        return $query->where('result', '!=', 'success');
    }

    public function scopeToday(Builder $query): Builder
    {
        return $query->where('created_at', '>=', now()->startOfDay());
    }

    public function scopeThisMonth(Builder $query): Builder
    {
        return $query->where('created_at', '>=', now()->startOfMonth());
    }
}
