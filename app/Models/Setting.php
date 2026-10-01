<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * 系统设置（键值对）。读取统一走 SettingsService（带缓存）。
 */
class Setting extends Model
{
    protected $fillable = [
        'key',
        'value',
        'type',
        'group',
    ];

    /**
     * 按存储类型还原为 PHP 值。
     */
    public function toValue(): mixed
    {
        return match ($this->type) {
            'integer' => $this->value === null ? null : (int) $this->value,
            'boolean' => filter_var($this->value, FILTER_VALIDATE_BOOLEAN),
            'json' => $this->value === null ? null : json_decode($this->value, true),
            default => $this->value,
        };
    }

    /**
     * 把 PHP 值序列化为存储字符串。
     */
    public static function serializeValue(mixed $value, string $type): ?string
    {
        if ($value === null) {
            return null;
        }

        return match ($type) {
            'boolean' => $value ? '1' : '0',
            'json' => json_encode($value, JSON_UNESCAPED_UNICODE),
            default => (string) $value,
        };
    }
}
