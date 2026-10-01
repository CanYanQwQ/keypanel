<?php

namespace App\Enums;

use Filament\Support\Contracts\HasColor;
use Filament\Support\Contracts\HasLabel;

/**
 * 卡密类型。
 */
enum CardType: string implements HasColor, HasLabel
{
    case Time = 'time';           // 时间卡：激活后按时长计时
    case Count = 'count';         // 次数卡：按次数扣减
    case Permanent = 'permanent'; // 永久卡：不限时、不限次
    case Trial = 'trial';         // 试用卡：短时试用，通常限单设备

    public function getLabel(): string
    {
        return match ($this) {
            self::Time => '时间卡',
            self::Count => '次数卡',
            self::Permanent => '永久卡',
            self::Trial => '试用卡',
        };
    }

    public function getColor(): string
    {
        return match ($this) {
            self::Time => 'info',
            self::Count => 'warning',
            self::Permanent => 'success',
            self::Trial => 'gray',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::Time => '首次激活后开始计时，到期自动失效。',
            self::Count => '每调用一次扣减一次，扣完自动失效。',
            self::Permanent => '激活后永久有效，不限次数。',
            self::Trial => '短期试用，适合体验用户，建议限制单设备。',
        };
    }

    /** 是否需要配置时长 */
    public function requiresDuration(): bool
    {
        return in_array($this, [self::Time, self::Trial], true);
    }

    /** 是否需要配置次数 */
    public function requiresUses(): bool
    {
        return $this === self::Count;
    }

    /** 激活后是否会过期 */
    public function expiresAfterActivation(): bool
    {
        return $this->requiresDuration();
    }

    /**
     * 供后台 Select 使用的选项数组。
     *
     * @return array<string, string>
     */
    public static function options(): array
    {
        return collect(self::cases())
            ->mapWithKeys(fn (self $t) => [$t->value => $t->getLabel()])
            ->all();
    }
}
