<?php

namespace App\Filament\Pages;

use App\Services\SettingsService;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Schemas\Components\Actions;
use Filament\Schemas\Components\EmbeddedSchema;
use Filament\Schemas\Components\Form;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Tabs;
use Filament\Schemas\Components\Tabs\Tab;
use Filament\Schemas\Schema;
use Illuminate\Support\Arr;
use UnitEnum;

class SettingsPage extends Page
{
    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-cog';

    protected static string|UnitEnum|null $navigationGroup = '系统';

    protected static ?string $navigationLabel = '系统设置';

    public function getView(): string
    {
        return 'filament.pages.settings';
    }

    public array $data = [];

    public function mount(): void
    {
        $this->form->fill(SettingsService::all());
    }

    public function submit(): void
    {
        $data = Arr::dot($this->form->getState());

        SettingsService::setMany($data);

        \App\Models\AdminOperationLog::create([
            'user_id' => auth()->id(),
            'admin_name' => auth()->user()->name,
            'action' => 'settings.updated',
            'description' => '修改了系统设置',
            'ip' => request()->ip(),
        ]);

        Notification::make()
            ->title('设置已保存')
            ->success()
            ->send();
    }

    public static function form(Schema $schema): Schema
    {
        return $schema
            ->statePath('data')
            ->schema([
                Tabs::make('系统设置')
                    ->key('settings-tabs')
                    ->contained(false)
                    ->tabs([
                        Tab::make('日志与 API')
                            ->schema([
                                Section::make('日志保留策略')
                                    ->schema([
                                        Grid::make(1)->schema([
                                            TextInput::make('log.verification_retention_days')
                                                ->label('验证日志（天）')
                                                ->numeric()->minValue(0)->default(30)
                                                ->helperText('0 = 永久'),
                                            TextInput::make('log.operation_retention_days')
                                                ->label('操作日志（天）')
                                                ->numeric()->minValue(0)->default(90),
                                            TextInput::make('log.login_retention_days')
                                                ->label('登录日志（天）')
                                                ->numeric()->minValue(0)->default(90),
                                            TextInput::make('log.nonce_retention_hours')
                                                ->label('防重放记录（小时）')
                                                ->numeric()->minValue(1)->default(24),
                                        ]),
                                    ])
                                    ->contained(false),

                                Section::make('API 安全参数')
                                    ->schema([
                                        Grid::make(1)->schema([
                                            TextInput::make('api.timestamp_tolerance')
                                                ->label('时间戳容忍偏移（秒）')
                                                ->numeric()->minValue(10)->maxValue(86400)->default(300),
                                            TextInput::make('api.nonce_ttl')
                                                ->label('Nonce 有效期（秒）')
                                                ->numeric()->minValue(60)->default(600),
                                            TextInput::make('api.rate_limit_per_minute')
                                                ->label('默认每分钟上限')
                                                ->numeric()->minValue(1)->default(60),
                                            TextInput::make('api.default_daily_quota')
                                                ->label('默认日配额')
                                                ->numeric()->minValue(0)->default(0)
                                                ->helperText('0 = 不限'),
                                            Toggle::make('api.require_encrypted_card')
                                                ->label('强制密文传输'),
                                            Toggle::make('api.response_signature')
                                                ->label('响应附带签名'),
                                        ]),
                                    ])
                                    ->contained(false),
                            ]),

                        Tab::make('安全与卡密')
                            ->schema([
                                Section::make('登录安全')
                                    ->schema([
                                        Grid::make(1)->schema([
                                            TextInput::make('security.max_login_attempts')
                                                ->label('失败次数上限')
                                                ->numeric()->minValue(1)->default(5),
                                            TextInput::make('security.lockout_minutes')
                                                ->label('锁定时长（分钟）')
                                                ->numeric()->minValue(1)->default(15),
                                            TextInput::make('security.session_idle_minutes')
                                                ->label('空闲超时（分钟）')
                                                ->numeric()->minValue(0)->default(30),
                                            TextInput::make('security.password_min_length')
                                                ->label('最小密码长度')
                                                ->numeric()->minValue(8)->default(12),
                                            TextInput::make('security.password_expiry_days')
                                                ->label('密码有效期（天）')
                                                ->numeric()->minValue(0)->default(0),
                                            Toggle::make('security.require_2fa')
                                                ->label('强制双因素认证'),
                                            Toggle::make('security.force_https')
                                                ->label('强制 HTTPS'),
                                            TextInput::make('api.trusted_proxies')
                                                ->label('可信代理')
                                                ->placeholder('127.0.0.1,*'),
                                        ]),
                                    ])
                                    ->contained(false),

                                Section::make('卡密策略')
                                    ->schema([
                                        Grid::make(1)->schema([
                                            TextInput::make('card.default_max_devices')
                                                ->label('默认可绑定设备数')
                                                ->numeric()->minValue(1)->default(1),
                                            TextInput::make('card.expiring_soon_days')
                                                ->label('即将过期提醒天数')
                                                ->numeric()->minValue(1)->default(7),
                                            Toggle::make('card.auto_disable_expired')
                                                ->label('自动禁用过期卡密'),
                                        ]),
                                    ])
                                    ->contained(false),

                                Section::make('备份')
                                    ->schema([
                                        Grid::make(1)->schema([
                                            Toggle::make('backup.enabled')
                                                ->label('启用自动备份'),
                                            TextInput::make('backup.retention_days')
                                                ->label('备份保留天数')
                                                ->numeric()->minValue(1)->default(7),
                                        ]),
                                    ])
                                    ->contained(false),
                            ]),
                        Tab::make('界面')
                            ->schema([
                                Section::make('系统外观')
                                    ->schema([
                                        Grid::make(1)->schema([
                                            TextInput::make('app.brand_name')
                                                ->label('左上角品牌名称')
                                                ->required()
                                                ->maxLength(80)
                                                ->helperText('保存后显示在后台左上角和页面标题中。'),
                                        ]),
                                    ])
                                    ->contained(false),
                            ]),
                    ]),
            ]);
    }

    public function content(Schema $schema): Schema
    {
        return $schema
            ->components([
                Form::make([
                    EmbeddedSchema::make('form'),
                ])
                    ->id('settings-form')
                    ->livewireSubmitHandler('submit')
                    ->footer([
                        Actions::make([
                            Action::make('submit')
                                ->label('保存设置')
                                ->submit('submit'),
                        ]),
                    ]),
            ]);
    }
}