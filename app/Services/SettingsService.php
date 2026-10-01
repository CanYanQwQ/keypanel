<?php

namespace App\Services;

use App\Models\Setting;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;

/**
 * 系统设置服务：以 config/cardkey.php 的 settings 定义为单一事实来源，
 * 数据库覆盖默认值，读取结果带缓存，写入时自动失效。
 */
class SettingsService
{
    public const CACHE_KEY = 'cardkey.settings.v1';

    protected static ?array $memo = null;

    protected static ?bool $tableExists = null;

    /**
     * 全部可配置项定义（key => [type, default, group, label, help]）。
     */
    public static function definitions(): array
    {
        return config('cardkey.settings', []);
    }

    public static function definition(string $key): ?array
    {
        return static::definitions()[$key] ?? null;
    }

    /**
     * 数据库中的原始值（key => 存储字符串）。
     */
    protected static function stored(): array
    {
        if (static::$memo !== null) {
            return static::$memo;
        }

        if (! static::tableAvailable()) {
            return static::$memo = [];
        }

        return static::$memo = Cache::rememberForever(static::CACHE_KEY, function (): array {
            return Setting::query()->pluck('value', 'key')->all();
        });
    }

    protected static function tableAvailable(): bool
    {
        if (static::$tableExists !== null) {
            return static::$tableExists;
        }

        try {
            return static::$tableExists = Schema::hasTable('settings');
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * 读取单个设置项；未在库中时使用定义默认值，再退化为 $fallback。
     */
    public static function get(string $key, mixed $fallback = null): mixed
    {
        $definition = static::definition($key);
        $type = $definition['type'] ?? 'string';
        $stored = static::stored();

        $value = array_key_exists($key, $stored)
            ? $stored[$key]
            : ($definition['default'] ?? $fallback);

        return static::cast($value, $type);
    }

    public static function getInt(string $key, int $fallback = 0): int
    {
        return (int) static::get($key, $fallback);
    }

    public static function getBool(string $key, bool $fallback = false): bool
    {
        return (bool) static::get($key, $fallback);
    }

    public static function getString(string $key, string $fallback = ''): string
    {
        return (string) static::get($key, $fallback);
    }

    /**
     * 全部设置项（已应用默认值与类型转换）。
     *
     * @return array<string, mixed>
     */
    public static function all(): array
    {
        $out = [];

        foreach (static::definitions() as $key => $definition) {
            $out[$key] = static::get($key);
        }

        return $out;
    }

    /**
     * 按分组返回定义（供后台设置页渲染表单）。
     *
     * @return array<string, array<string, array<string, mixed>>>
     */
    public static function groupedDefinitions(): array
    {
        $grouped = [];

        foreach (static::definitions() as $key => $definition) {
            $group = $definition['group'] ?? 'general';
            $grouped[$group][$key] = $definition;
        }

        ksort($grouped);

        return $grouped;
    }

    /**
     * 写入单个设置项（未定义的键会被忽略，防止任意键注入）。
     */
    public static function set(string $key, mixed $value): bool
    {
        $definition = static::definition($key);

        if ($definition === null) {
            return false;
        }

        Setting::updateOrCreate(
            ['key' => $key],
            [
                'value' => Setting::serializeValue($value, $definition['type'] ?? 'string'),
                'type' => $definition['type'] ?? 'string',
                'group' => $definition['group'] ?? 'general',
            ],
        );

        static::flush();

        return true;
    }

    /**
     * 批量写入（只接受定义中存在的键）。
     *
     * @param  array<string, mixed>  $values
     */
    public static function setMany(array $values): void
    {
        foreach ($values as $key => $value) {
            static::set($key, $value);
        }
    }

    /**
     * 清空进程内与缓存中的设置，下次读取时重新查询。
     */
    public static function flush(): void
    {
        static::$memo = null;
        static::$tableExists = null;
        Cache::forget(static::CACHE_KEY);
    }

    /**
     * 按类型把存储字符串还原为 PHP 值。
     */
    protected static function cast(mixed $value, string $type): mixed
    {
        if ($value === null) {
            return null;
        }

        return match ($type) {
            'integer' => (int) $value,
            'boolean' => filter_var($value, FILTER_VALIDATE_BOOLEAN),
            'json' => is_array($value) ? $value : json_decode((string) $value, true),
            default => (string) $value,
        };
    }
}
