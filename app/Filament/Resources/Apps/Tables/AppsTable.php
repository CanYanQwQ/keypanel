<?php

namespace App\Filament\Resources\Apps\Tables;

use App\Enums\AppStatus;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class AppsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('name')
                    ->label('应用名称')
                    ->searchable()
                    ->sortable(),

                TextColumn::make('app_id')
                    ->label('App ID')
                    ->copyable()
                    ->searchable()
                    ->fontFamily('mono'),

                TextColumn::make('secret_prefix')
                    ->label('密钥标识')
                    ->searchable()
                    ->fontFamily('mono'),

                TextColumn::make('status')
                    ->label('状态')
                    ->badge()
                    ->sortable(),

                IconColumn::make('require_encrypted_card')
                    ->label('加密传输')
                    ->boolean(),

                TextColumn::make('rate_limit_per_minute')
                    ->label('每分钟上限')
                    ->numeric()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('daily_quota')
                    ->label('日配额')
                    ->numeric()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('last_used_at')
                    ->label('最近调用')
                    ->dateTime('Y-m-d H:i')
                    ->sortable(),

                TextColumn::make('created_at')
                    ->label('创建时间')
                    ->dateTime('Y-m-d H:i')
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('status')
                    ->label('状态')
                    ->options(AppStatus::options()),
            ])
            ->recordActions([
                EditAction::make(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make()
                        ->label('批量删除')
                        ->requiresConfirmation()
                        ->modalHeading('确认删除选中的应用？')
                        ->modalDescription('删除后相关卡密将变为无归属（通用卡密），此操作不可撤销。'),
                ]),
            ]);
    }
}