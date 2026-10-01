<?php

namespace App\Enums;

use Filament\Support\Contracts\HasLabel;

/**
 * 时间卡 / 试用卡的有效时长单位。
 */
enum DurationUnit: string implements HasLabel
{
    case Minute = 'minute';
    case Hour = 'hour';
    case Day = 'day';
    case Month = 'month';

    public function getLabel(): string
    {
        return match ($this) {
            self::Minute => '分钟',
            self::Hour => '小时',
            self::Day => '天',
            self::Month => '个月',
        };
    }

    /**
     * 用于后台表单的「数值 + 单位」后缀。
     */
    public function shortLabel(): string
    {
        return match ($this) {
            self::Minute => '分钟',
            self::Hour => '小时',
            self::Day => '天',
            self::Month => '月',
        };
    }

    /**
     * 把 (数值, 单位) 换算为到期时间。
     */
    public function addTo(\DateTimeInterface $from, int $value): \Carbon\CarbonInterface
    {
        $carbon = \Carbon\Carbon::instance($from)->copy();

        return match ($this) {
            self::Minute => $carbon->addMinutes($value),
            self::Hour => $carbon->addHours($value),
            self::Day => $carbon->addDays($value),
            self::Month => $carbon->addMonths($value),
        };
    }

    /**
     * @return array<string, string>
     */
    public static function options(): array
    {
        return collect(self::cases())
            ->mapWithKeys(fn (self $u) => [$u->value => $u->getLabel()])
            ->all();
    }
}
