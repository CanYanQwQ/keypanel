<?php

namespace App\Filament\Widgets;

use App\Enums\CardStatus;
use App\Models\CardKey;
use App\Models\VerificationLog;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class DashboardStats extends BaseWidget
{
    protected ?string $pollingInterval = '30s';

    protected function getStats(): array
    {
        return [
            Stat::make('卡密总数', CardKey::count())
                ->description('已激活 '.CardKey::where('status', CardStatus::Activated->value)->count().' 张')
                ->icon('heroicon-o-ticket')
                ->color('primary'),

            Stat::make('未使用', CardKey::where('status', CardStatus::Unused->value)->count())
                ->description('可用库存')
                ->icon('heroicon-o-inbox')
                ->color('gray'),

            Stat::make('已过期', CardKey::where('status', CardStatus::Expired->value)->count())
                ->description('含即将过期')
                ->icon('heroicon-o-clock')
                ->color('warning'),

            Stat::make('今日验证', VerificationLog::whereDate('created_at', today())->count())
                ->description('成功 '.VerificationLog::whereDate('created_at', today())->where('result', 'success')->count().' 次')
                ->icon('heroicon-o-shield-check')
                ->color('success'),
        ];
    }
}