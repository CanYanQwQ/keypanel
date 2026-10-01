<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * 按应用 + 日期聚合的调用计数，用于每日配额与统计。
 */
class AppDailyUsage extends Model
{
    protected $fillable = [
        'app_id',
        'date',
        'total_calls',
        'success_calls',
        'failed_calls',
    ];

    // The 'date' column stores plain 'Y-m-d' strings (not Carbon).
    // Casting to 'date' causes SQLite to serialize "2026-09-28 00:00:00",
    // which breaks firstOrCreate lookups and triggers UNIQUE violations.
    protected function casts(): array
    {
        return [
            'total_calls' => 'integer',
            'success_calls' => 'integer',
            'failed_calls' => 'integer',
        ];
    }
}
