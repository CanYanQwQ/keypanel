<?php

namespace App\Filament\Resources\LoginLogs\Pages;

use App\Filament\Resources\LoginLogResource;
use Filament\Actions\Action;
use Filament\Resources\Pages\ListRecords;

class ListLoginLogs extends ListRecords
{
    protected static string $resource = LoginLogResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('cleanup')
                ->label('清理过期日志')
                ->icon('heroicon-o-trash')
                ->color('danger')
                ->requiresConfirmation()
                ->modalHeading('确认清理过期日志？')
                ->action(function (): void {
                    $days = \App\Services\SettingsService::getInt('log.login_retention_days');

                    if ($days <= 0) {
                        \Filament\Notifications\Notification::make()
                            ->title('日志保留天数设置为 0（永久保留），无需清理')
                            ->send();

                        return;
                    }

                    $count = \App\Models\LoginLog::where('created_at', '<', now()->subDays($days))->delete();

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'log.cleaned',
                        'description' => "清理登录日志，删除了 {$count} 条",
                        'ip' => request()->ip(),
                    ]);

                    \Filament\Notifications\Notification::make()
                        ->title("已清理 {$count} 条过期登录日志")
                        ->success()
                        ->send();
                }),
        ];
    }
}