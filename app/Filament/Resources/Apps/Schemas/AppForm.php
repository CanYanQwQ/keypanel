<?php

namespace App\Filament\Resources\Apps\Schemas;

use App\Enums\AppStatus;
use App\Services\SettingsService;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TagsInput;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\Toggle;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class AppForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->columns(1)
            ->extraAttributes(['class' => 'app-form-layout'])
            ->components([
                Section::make('基本信息')
                    ->schema([
                        TextInput::make('name')
                            ->label('应用名称')
                            ->required()
                            ->maxLength(255),

                        Select::make('status')
                            ->label('状态')
                            ->options(AppStatus::options())
                            ->default(AppStatus::Enabled->value)
                            ->required()
                            ->native(false),

                        Textarea::make('description')
                            ->label('备注')
                            ->rows(3),
                    ])
                    ->contained(false)
                    ->columns(1),

                Section::make('密钥')
                    ->description('密钥信息不会在编辑表单中展示，仅可通过右上角「查看密钥」并完成管理员密码确认后查看。')
                    ->schema([])
                    ->contained(false)
                    ->columns(1),

                Section::make('安全配置')
                    ->schema([
                        Toggle::make('require_encrypted_card')
                            ->label('强制卡密密文传输')
                            ->helperText('开启后客户端必须用 AES-256-GCM 加密卡密后提交')
                            ->default(true),

                        TextInput::make('rate_limit_per_minute')
                            ->label('每分钟请求上限')
                            ->numeric()
                            ->minValue(1)
                            ->maxValue(10000)
                            ->default(fn (): int => SettingsService::getInt('api.rate_limit_per_minute', 60)),

                        TextInput::make('daily_quota')
                            ->label('每日调用配额')
                            ->helperText('0 表示不限制')
                            ->numeric()
                            ->minValue(0)
                            ->default(fn (): int => SettingsService::getInt('api.default_daily_quota', 0)),

                        TextInput::make('timestamp_tolerance')
                            ->label('时间戳容忍偏移（秒）')
                            ->numeric()
                            ->minValue(10)
                            ->maxValue(86400)
                            ->default(300),

                        TagsInput::make('ip_whitelist')
                            ->label('IP 白名单')
                            ->helperText('输入 IP 或 CIDR 网段后按回车添加。留空表示不限制。')
                            ->placeholder('203.0.113.7')
                            ->splitKeys(['Enter', ',', ' ']),
                    ])
                    ->contained(false)
                    ->columns(1),
            ]);
    }
}