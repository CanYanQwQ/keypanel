<?php

namespace App\Filament\Widgets;

use App\Enums\CardStatus;
use App\Models\CardKey;
use Filament\Widgets\ChartWidget;

class CardStatusChart extends ChartWidget
{
    protected ?string $heading = '卡密状态分布';

    protected ?string $description = '按最近一次状态同步结果统计';

    protected ?string $pollingInterval = null;

    protected ?string $maxHeight = '290px';

    protected int|string|array $columnSpan = 1;

    protected function getType(): string
    {
        return 'doughnut';
    }

    protected function getData(): array
    {
        $counts = CardKey::query()
            ->selectRaw('status, count(*) as aggregate')
            ->groupBy('status')
            ->pluck('aggregate', 'status');

        $statuses = CardStatus::cases();

        return [
            'labels' => array_map(fn (CardStatus $status): string => $status->getLabel(), $statuses),
            'datasets' => [[
                'label' => '卡密数量',
                'data' => array_map(fn (CardStatus $status): int => (int) ($counts[$status->value] ?? 0), $statuses),
                'backgroundColor' => ['#9ca3af', '#16a34a', '#d97706', '#dc2626', '#0284c7'],
                'borderWidth' => 0,
            ]],
        ];
    }

    protected function getOptions(): array
    {
        return [
            'plugins' => [
                'legend' => ['position' => 'bottom'],
            ],
            'cutout' => '62%',
        ];
    }
}
