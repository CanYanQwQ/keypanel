<?php

namespace App\Enums;

use Filament\Support\Contracts\HasColor;
use Filament\Support\Contracts\HasLabel;

/**
 * 应用状态。
 */
enum AppStatus: string implements HasColor, HasLabel
{
    case Enabled = 'enabled';
    case Disabled = 'disabled';

    public function getLabel(): string
    {
        return match ($this) {
            self::Enabled => '已启用',
            self::Disabled => '已禁用',
        };
    }

    public function getColor(): string
    {
        return match ($this) {
            self::Enabled => 'success',
            self::Disabled => 'danger',
        };
    }

    public function isEnabled(): bool
    {
        return $this === self::Enabled;
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
