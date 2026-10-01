<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * 已使用的 API nonce，用于防重放。
 *
 * 依赖 (app_id, nonce) 唯一索引：并发重放时只有一条能插入成功，
 * 因此判断依据是「插入是否成功」而不是「是否已存在」，天然避免竞态。
 */
class ApiNonce extends Model
{
    public const UPDATED_AT = null;

    protected $fillable = [
        'app_id',
        'nonce',
        'expires_at',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'created_at' => 'datetime',
        ];
    }
}
