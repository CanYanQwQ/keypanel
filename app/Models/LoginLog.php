<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * 管理员登录日志（追加写）。
 */
class LoginLog extends Model
{
    public const UPDATED_AT = null;

    protected $fillable = [
        'user_id',
        'email',
        'result',
        'message',
        'ip',
        'user_agent',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'created_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function isSuccess(): bool
    {
        return $this->result === 'success';
    }

    public function getResultLabelAttribute(): string
    {
        return match ($this->result) {
            'success' => '登录成功',
            'logout' => '退出登录',
            'failed_password' => '密码错误',
            'failed_2fa' => '双因素认证失败',
            'locked' => '账号已锁定',
            'blocked' => '账号已停用',
            default => $this->result,
        };
    }

    public function getResultColorAttribute(): string
    {
        return match ($this->result) {
            'success' => 'success',
            'logout' => 'gray',
            'locked', 'blocked' => 'danger',
            default => 'warning',
        };
    }
}
