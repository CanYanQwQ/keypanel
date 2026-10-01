<?php

namespace App\Filament\Resources\Apps\Pages;

use App\Filament\Resources\Apps\AppResource;
use App\Models\App as AppModel;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\CreateRecord;

class CreateApp extends CreateRecord
{
    protected static string $resource = AppResource::class;

    protected function mutateFormDataBeforeCreate(array $data): array
    {
        $secret = AppModel::generateSecret();

        $data['app_id'] = AppModel::generateAppId();
        $data['app_secret'] = $secret;
        $this->_newSecret = $secret;

        return $data;
    }

    protected function getCreatedNotification(): ?Notification
    {
        return null; // 使用自定义通知
    }

    protected function afterCreate(): void
    {
        \App\Models\AdminOperationLog::create([
            'user_id' => auth()->id(),
            'admin_name' => auth()->user()->name,
            'action' => 'app.created',
            'description' => "创建了应用【{$this->record->name}】",
            'target_type' => 'app',
            'target_id' => (string) $this->record->id,
            'ip' => request()->ip(),
        ]);

        Notification::make()
            ->title('应用创建成功')
            ->body(
                "AppID:  {$this->record->app_id}\n"
                ."Secret: {$this->_newSecret}\n\n"
                .'密钥仅显示一次，请立即复制保存。'
            )
            ->icon('heroicon-o-key')
            ->persistent()
            ->seconds(0)
            ->send();
    }

    private ?string $_newSecret = null;
}