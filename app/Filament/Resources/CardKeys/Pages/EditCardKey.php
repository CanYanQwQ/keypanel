<?php

namespace App\Filament\Resources\CardKeys\Pages;

use App\Enums\DurationUnit;
use App\Filament\Resources\CardKeys\CardKeyResource;
use App\Services\CardKeyService;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\EditRecord;

class EditCardKey extends EditRecord
{
    protected static string $resource = CardKeyResource::class;

    protected function getRedirectUrl(): string
    {
        return $this->getResourceUrl();
    }

    protected function getHeaderActions(): array
    {
        return [
            Action::make('copy_code')
                ->label('复制卡密')
                ->icon('heroicon-o-clipboard')
                ->color('gray')
                ->modalHeading('复制卡密')
                ->modalDescription('点击下方输入框内容后按 Ctrl+C 复制')
                ->form([
                    Textarea::make('code')
                        ->label('卡密明文')
                        ->default(fn () => $this->record->code ?? $this->record->code_masked)
                        ->readOnly()
                        ->rows(2)
                        ->extraInputAttributes(['x-ref' => 'codeToCopy', 'onfocus' => '$refs.codeToCopy.select()']),
                ])
                ->action(function (): void {
                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'card.code_viewed',
                        'description' => "查看了卡密 {$this->record->code_masked}",
                        'target_type' => 'card_key',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);
                }),

            Action::make('disable')
                ->label(fn (): string => $this->record->status === \App\Enums\CardStatus::Disabled ? '启用卡密' : '禁用卡密')
                ->icon(fn (): string => $this->record->status === \App\Enums\CardStatus::Disabled ? 'heroicon-o-check-circle' : 'heroicon-o-x-circle')
                ->color(fn (): string => $this->record->status === \App\Enums\CardStatus::Disabled ? 'success' : 'danger')
                ->requiresConfirmation()
                ->modalHeading(fn (): string => $this->record->status === \App\Enums\CardStatus::Disabled ? '确认启用卡密？' : '确认禁用卡密？')
                ->modalDescription(fn (): string => $this->record->status === \App\Enums\CardStatus::Disabled ? '启用后卡密将恢复可用。' : '禁用后客户端将无法使用该卡密。')
                ->form([
                    TextInput::make('reason')
                        ->label('原因')
                        ->nullable()
                        ->maxLength(255),
                ])
                ->action(function (array $data): void {
                    $disable = $this->record->status !== \App\Enums\CardStatus::Disabled;
                    app(CardKeyService::class)->setDisabled($this->record, $disable, $data['reason'] ?? null);

                    $action = $disable ? 'card.disabled' : 'card.enabled';
                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => $action,
                        'description' => ($disable ? '禁用了' : '启用了')."卡密 {$this->record->code_masked}",
                        'target_type' => 'card_key',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);

                    Notification::make()
                        ->title($disable ? '卡密已禁用' : '卡密已启用')
                        ->success()
                        ->send();
                }),

            Action::make('extend')
                ->label('延长有效期')
                ->icon('heroicon-o-clock')
                ->color('warning')
                ->requiresConfirmation()
                ->modalHeading('确认延长有效期？')
                ->modalDescription('将以当前到期时间（已过期则从当前时间）为基准延长。')
                ->form([
                    TextInput::make('value')
                        ->label('延长数值')
                        ->numeric()
                        ->minValue(1)
                        ->default(30)
                        ->required(),
                    Select::make('unit')
                        ->label('单位')
                        ->options(DurationUnit::options())
                        ->default(DurationUnit::Day->value)
                        ->required()
                        ->native(false),
                ])
                ->action(function (array $data): void {
                    app(CardKeyService::class)->extend(
                        $this->record,
                        (int) $data['value'],
                        DurationUnit::from($data['unit']),
                    );

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'card.extended',
                        'description' => "延长了卡密 {$this->record->code_masked} 有效期",
                        'target_type' => 'card_key',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);

                    Notification::make()->title('有效期已延长')->success()->send();
                })
                ->visible(fn (): bool => $this->record->type !== \App\Enums\CardType::Permanent),

            Action::make('reset_uses')
                ->label('重置次数')
                ->icon('heroicon-o-arrow-uturn-left')
                ->color('warning')
                ->requiresConfirmation()
                ->modalHeading('确认重置次数？')
                ->modalDescription('将已使用次数清零。可选重新设置总次数。')
                ->form([
                    TextInput::make('new_max')
                        ->label('新的总次数')
                        ->helperText('留空表示仅清零已使用次数')
                        ->nullable()
                        ->numeric()
                        ->minValue(1),
                ])
                ->action(function (array $data): void {
                    app(CardKeyService::class)->resetUses(
                        $this->record,
                        isset($data['new_max']) ? (int) $data['new_max'] : null,
                    );

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'card.uses_reset',
                        'description' => "重置了卡密 {$this->record->code_masked} 次数",
                        'target_type' => 'card_key',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);

                    Notification::make()->title('次数已重置')->success()->send();
                })
                ->visible(fn (): bool => $this->record->type === \App\Enums\CardType::Count),

            Action::make('unbind')
                ->label('重置绑定')
                ->icon('heroicon-o-link-slash')
                ->color('danger')
                ->requiresConfirmation()
                ->modalHeading('确认解除设备绑定？')
                ->modalDescription('解除后卡密将可绑定到其他设备。')
                ->action(function (): void {
                    app(CardKeyService::class)->resetBinding($this->record);

                    \App\Models\AdminOperationLog::create([
                        'user_id' => auth()->id(),
                        'admin_name' => auth()->user()->name,
                        'action' => 'card.binding_reset',
                        'description' => "重置了卡密 {$this->record->code_masked} 设备绑定",
                        'target_type' => 'card_key',
                        'target_id' => (string) $this->record->id,
                        'ip' => request()->ip(),
                    ]);

                    Notification::make()->title('设备绑定已重置')->success()->send();
                })
                ->visible(fn (): bool => $this->record->isBound()),

            DeleteAction::make()
                ->label('删除'),
        ];
    }
}