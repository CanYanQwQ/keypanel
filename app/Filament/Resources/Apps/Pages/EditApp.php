<?php

namespace App\Filament\Resources\Apps\Pages;

use App\Filament\Resources\Apps\AppResource;
use App\Models\App as AppModel;
use Filament\Actions\DeleteAction;
use Filament\Actions\Action;
use Filament\Actions\Contracts\HasActions;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\EditRecord;
use Filament\Support\Enums\Width;
use Illuminate\Support\Js;

class EditApp extends EditRecord
{
    protected static string $resource = AppResource::class;

    protected function getRedirectUrl(): string
    {
        return $this->getResourceUrl();
    }

    protected function getHeaderActions(): array
    {
        return [
            Action::make('view_secret')
                ->label('查看密钥')
                ->icon('heroicon-o-eye')
                ->color('gray')
                ->requiresConfirmation()
                ->modalHeading('查看 AppSecret')
                ->modalDescription('请再次输入管理员密码以查看密钥明文（此操作会记录审计日志）')
                ->form([
                    TextInput::make('password')
                        ->label('管理员密码')
                        ->password()
                        ->required(),
                ])
                ->registerModalActions([
                    Action::make('show_secret')
                        ->modalHeading('应用密钥')
                        ->modalDescription('请使用字段右侧的复制按钮保存密钥。关闭弹窗后不会再次显示明文。')
                        ->modalWidth(Width::Large)
                        ->schema(fn (array $arguments): array => [
                            TextInput::make('app_id')
                                ->label('App ID')
                                ->default($arguments['app_id'] ?? '')
                                ->readOnly()
                                ->copyable(copyMessage: 'App ID 已复制')
                                ->extraInputAttributes(['class' => 'font-mono']),
                            TextInput::make('app_secret')
                                ->label('AppSecret')
                                ->default($arguments['app_secret'] ?? '')
                                ->readOnly()
                                ->copyable(copyMessage: 'AppSecret 已复制')
                                ->extraInputAttributes(['class' => 'font-mono']),
                        ])
                        ->modalSubmitAction(false)
                        ->modalCancelActionLabel('关闭')
                        ->cancelParentActions()
                        ->cancelParentActionsOnClose()
                        ->closeModalByClickingAway(false)
                        ->closeModalByEscaping(false),
                ])
                ->action(function (array $data, HasActions $livewire): void {
                    if (! \Illuminate\Support\Facades\Hash::check($data['password'], auth()->user()->password)) {
                        Notification::make()
                            ->title('密码错误')
                            ->danger()
                            ->send();

                        return;
                    }

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'app.secret_viewed',
                        'description' => "查看了应用【{$this->record->name}】的密钥",
                        'target_type' => 'app',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);

                    $livewire->mountAction('show_secret', arguments: [
                        'app_id' => $this->record->app_id,
                        'app_secret' => $this->record->app_secret,
                    ]);
                }),

            Action::make('rotate_secret')
                ->label('重置密钥')
                ->icon('heroicon-o-arrow-path')
                ->color('warning')
                ->requiresConfirmation()
                ->modalHeading('确认重置密钥？')
                ->modalDescription('重置后旧密钥立即失效，所有客户端必须更换新密钥。新密钥仅显示一次。')
                ->action(function (): void {
                    $newSecret = $this->record->rotateSecret();

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'app.secret_rotated',
                        'description' => "重置了应用【{$this->record->name}】的密钥",
                        'target_type' => 'app',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);

                    Notification::make()
                        ->title('密钥已重置')
                        ->body("新密钥已生成，仅显示一次，请立即复制保存：\n{$newSecret}")
                        ->icon('heroicon-o-key')
                        ->persistent()
                        ->seconds(0)
                        ->send();
                }),

            DeleteAction::make()
                ->label('删除应用')
                ->requiresConfirmation()
                ->modalHeading('确认删除应用？')
                ->modalDescription('删除后相关卡密将变为无归属（通用卡密），此操作不可撤销。'),
        ];
    }
}