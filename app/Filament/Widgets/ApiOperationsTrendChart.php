<?php

namespace App\Filament\Widgets;

use App\Models\VerificationLog;
use Carbon\Carbon;
use Filament\Widgets\ChartWidget;

class ApiOperationsTrendChart extends ChartWidget
{
    protected ?string $heading = '近 7 天 API 操作趋势';

    protected ?string $description = '按卡密 API 操作日志统计成功与失败次数';

    protected ?string $pollingInterval = null;

    protected ?string $maxHeight = '300px';

    protected int|string|array $columnSpan = 'full';

    protected function getType(): string
    {
        return 'line';
    }

    protected function getData(): array
    {
        $start = now()->subDays(6)->startOfDay();
        $end = now()->addDay()->startOfDay();
        $days = collect(range(0, 6))
            ->map(fn (int $offset): Carbon => $start->copy()->addDays($offset))
            ->keyBy(fn (Carbon $day): string => $day->toDateString());

        $rows = VerificationLog::query()
            ->where('created_at', '>=', $start)
            ->where('created_at', '<', $end)
            ->selectRaw("date(created_at) as day, result, count(*) as aggregate")
            ->groupBy('day', 'result')
            ->get();

        $counts = [
            'success' => array_fill_keys($days->keys()->all(), 0),
            'failed' => array_fill_keys($days->keys()->all(), 0),
        ];

        foreach ($rows as $row) {
            $day = (string) $row->day;

            if (! array_key_exists($day, $days->all())) {
                continue;
            }

            $counts[$row->result === 'success' ? 'success' : 'failed'][$day] += (int) $row->aggregate;
        }

        return [
            'labels' => $days->map(fn (Carbon $day): string => $day->format('m-d'))->values()->all(),
            'datasets' => [
                [
                    'label' => '成功',
                    'data' => array_values($counts['success']),
                    'borderColor' => '#16a34a',
                    'backgroundColor' => '#16a34a',
                    'pointRadius' => 3,
                    'tension' => 0.25,
                    'fill' => false,
                ],
                [
                    'label' => '失败',
                    'data' => array_values($counts['failed']),
                    'borderColor' => '#dc2626',
                    'backgroundColor' => '#dc2626',
                    'pointRadius' => 3,
                    'tension' => 0.25,
                    'fill' => false,
                ],
            ],
        ];
    }

    protected function getOptions(): array
    {
        return [
            'plugins' => [
                'legend' => ['position' => 'bottom'],
            ],
            'scales' => [
                'y' => ['beginAtZero' => true, 'ticks' => ['precision' => 0]],
            ],
        ];
    }
}
