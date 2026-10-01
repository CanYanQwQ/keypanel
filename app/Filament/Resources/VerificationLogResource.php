<?php

namespace App\Filament\Resources;

use App\Models\VerificationLog;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use UnitEnum;

class VerificationLogResource extends Resource
{
    protected static ?string $model = VerificationLog::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedClipboardDocumentList;

    protected static string|UnitEnum|null $navigationGroup = '日志';

    protected static ?string $navigationLabel = '验证日志';

    protected static ?string $modelLabel = '验证日志';

    protected static ?string $pluralModelLabel = '验证日志';

    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('created_at', 'desc')
            ->columns([
                TextColumn::make('action')->label('操作')->badge()
                    ->formatStateUsing(fn (string $state): string => match ($state) {
                        'verify' => '验证',
                        'activate' => '激活',
                        'consume' => '扣次',
                        'query' => '查询',
                        'unbind' => '解绑',
                        default => $state,
                    }),
                TextColumn::make('code_masked')->label('卡密')->fontFamily('mono'),
                TextColumn::make('result')->label('结果')->badge()
                    ->color(fn (string $state): string => $state === 'success' ? 'success' : 'danger'),
                TextColumn::make('message')->label('信息')->limit(40)->toggleable(),
                TextColumn::make('app.name')->label('应用')->placeholder('—'),
                TextColumn::make('ip')->label('IP')->copyable()->toggleable(),
                TextColumn::make('device_id')->label('设备')->limit(20)->toggleable(isToggledHiddenByDefault: true),
                TextColumn::make('created_at')->label('时间')->dateTime('Y-m-d H:i:s')->sortable(),
            ])
            ->filters([
                SelectFilter::make('action')->label('操作')->options([
                    'verify' => '验证',
                    'activate' => '激活',
                    'consume' => '扣次',
                    'query' => '查询',
                    'unbind' => '解绑',
                ]),
                SelectFilter::make('result')->label('结果')->options([
                    'success' => '成功',
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
            'index' => \App\Filament\Resources\VerificationLogs\Pages\ListVerificationLogs::route('/'),
        ];
    }
}