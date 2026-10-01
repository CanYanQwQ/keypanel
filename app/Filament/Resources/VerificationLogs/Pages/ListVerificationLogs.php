<?php

namespace App\Filament\Resources\VerificationLogs\Pages;

use App\Filament\Resources\VerificationLogResource;
use App\Services\SettingsService;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;

class ListVerificationLogs extends ListRecords
{
    protected static string $resource = VerificationLogResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Action::make('cleanup')
                ->label('清理过期日志')
                ->icon('heroicon-o-trash')
                ->color('danger')
                ->requiresConfirmation()
                ->action(function (): void {
                    $days = SettingsService::getInt('log.verification_retention_days');

                    if ($days <= 0) {
                        Notification::make()->title('日志保留天数设置为 0，无需清理')->send();

                        return;
                    }

                    $count = \App\Models\VerificationLog::where('created_at', '<', now()->subDays($days))->delete();

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'log.cleaned',
                        'description' => "清理验证日志，删除了 {$count} 条",
                        'ip' => request()->ip(),
                    ]);

                    Notification::make()->title("已清理 {$count} 条过期验证日志")->success()->send();
                }),
        ];
    }
}