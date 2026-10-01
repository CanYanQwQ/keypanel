<?php

namespace App\Enums;

use Filament\Support\Contracts\HasColor;
use Filament\Support\Contracts\HasLabel;

/**
 * 卡密状态。
 *
 * 状态流转：
 *   unused ──激活──> activated ──到期──> expired
 *                      │  └──扣完──> depleted
 *   任意状态 ──管理员禁用──> disabled ──启用──> 回到原状态
 */
enum CardStatus: string implements HasColor, HasLabel
{
    case Unused = 'unused';         // 未使用
    case Activated = 'activated';   // 已激活
    case Expired = 'expired';       // 已过期
    case Disabled = 'disabled';     // 已禁用
    case Depleted = 'depleted';     // 已用完

    public function getLabel(): string
    {
        return match ($this) {
            self::Unused => '未使用',
            self::Activated => '已激活',
            self::Expired => '已过期',
            self::Disabled => '已禁用',
            self::Depleted => '已用完',
        };
    }

    public function getColor(): string
    {
        return match ($this) {
            self::Unused => 'gray',
            self::Activated => 'success',
            self::Expired => 'warning',
            self::Disabled => 'danger',
            self::Depleted => 'info',
        };
    }

    /** 是否可以被正常验证/激活 */
    public function isUsable(): bool
    {
        return in_array($this, [self::Unused, self::Activated], true);
    }

    /**
     * @return array<string, string>
     */
    public static function options(): array
    {
        return collect(self::cases())
            ->mapWithKeys(fn (self $s) => [$s->value => $s->getLabel()])
            ->all();
    }
}
