<?php

namespace App\Filament\Pages;

use App\Filament\Widgets\ApiOperationsTrendChart;
use App\Filament\Widgets\AppUsageRankingChart;
use App\Filament\Widgets\CardStatusChart;
use App\Filament\Widgets\DashboardStats;
use Filament\Pages\Dashboard as BaseDashboard;

class Dashboard extends BaseDashboard
{
    public function getWidgets(): array
    {
        return [
            DashboardStats::class,
            ApiOperationsTrendChart::class,
            CardStatusChart::class,
            AppUsageRankingChart::class,
        ];
    }
}