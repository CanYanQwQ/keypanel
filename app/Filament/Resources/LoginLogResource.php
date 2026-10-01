<?php

namespace App\Filament\Resources;

use App\Filament\Resources\LoginLogs\Pages\ListLoginLogs;
use App\Models\LoginLog;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use UnitEnum;

class LoginLogResource extends Resource
{
    protected static ?string $model = LoginLog::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldCheck;

    protected static string|UnitEnum|null $navigationGroup = '日志';

    protected static ?string $navigationLabel = '登录日志';

    protected static ?string $modelLabel = '登录日志';

    protected static ?string $pluralModelLabel = '登录日志';

    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('created_at', 'desc')
            ->columns([
                TextColumn::make('email')->label('邮箱')->searchable(),
                TextColumn::make('result_label')->label('结果')->badge()->color(fn ($record) => $record->result_color),
                TextColumn::make('message')->label('信息')->limit(60)->toggleable(),
                TextColumn::make('ip')->label('IP')->copyable()->toggleable(),
                TextColumn::make('user_agent')->label('User Agent')->limit(40)->toggleable(isToggledHiddenByDefault: true),
                TextColumn::make('created_at')->label('时间')->dateTime('Y-m-d H:i:s')->sortable(),
            ])
            ->filters([
                SelectFilter::make('result')->label('结果')->options([
                    'success' => '登录成功',
                    'logout' => '退出登录',
                    'failed_password' => '密码错误',
                    'failed_2fa' => '双因素认证失败',
                    'locked' => '已锁定',
                ]),
            ])
            ->actions([])
            ->bulkActions([]);
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListLoginLogs::route('/'),
        ];
    }
}