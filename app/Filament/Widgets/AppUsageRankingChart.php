<?php

namespace App\Filament\Widgets;

use App\Models\App as AppModel;
use App\Models\AppDailyUsage;
use Filament\Widgets\ChartWidget;

class AppUsageRankingChart extends ChartWidget
{
    protected ?string $heading = '近 7 天业务调用排行';

    protected ?string $description = '统计已进入业务层的调用，不含签名失败、限流和配额拦截';

    protected ?string $pollingInterval = null;

    protected ?string $maxHeight = '290px';

    protected int|string|array $columnSpan = 1;

    protected function getType(): string
    {
        return 'bar';
    }

    protected function getData(): array
    {
        $rows = AppDailyUsage::query()
            ->where('date', '>=', now()->subDays(6)->toDateString())
            ->selectRaw('app_id, sum(total_calls) as aggregate')
            ->groupBy('app_id')
            ->orderByDesc('aggregate')
            ->limit(10)
            ->get();

        $names = AppModel::query()
            ->whereIn('app_id', $rows->pluck('app_id'))
            ->pluck('name', 'app_id');

        return [
            'labels' => $rows->map(fn ($row): string => (string) ($names[$row->app_id] ?? $row->app_id))->all(),
            'datasets' => [[
                'label' => '业务调用量',
                'data' => $rows->map(fn ($row): int => (int) $row->aggregate)->all(),
                'backgroundColor' => '#4f46e5',
                'borderRadius' => 3,
                'barThickness' => 18,
            ]],
        ];
    }

    protected function getOptions(): array
    {
        return [
            'indexAxis' => 'y',
            'plugins' => [
                'legend' => ['display' => false],
            ],
            'scales' => [
                'x' => ['beginAtZero' => true, 'ticks' => ['precision' => 0]],
            ],
        ];
    }
}
