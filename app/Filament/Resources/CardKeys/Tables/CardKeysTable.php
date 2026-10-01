<?php

namespace App\Filament\Resources\CardKeys\Tables;

use App\Enums\CardStatus;
use App\Enums\CardType;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class CardKeysTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->defaultSort('created_at', 'desc')
            ->columns([
                TextColumn::make('code_masked')
                    ->label('卡密')
                    ->searchable(query: function ($query, $search) {
                        return $query->where('code_prefix', 'like', strtoupper($search).'%');
                    })
                    ->copyable()
                    ->fontFamily('mono'),

                TextColumn::make('type')
                    ->label('类型')
                    ->badge()
                    ->sortable(),

                TextColumn::make('status')
                    ->label('状态')
                    ->badge()
                    ->sortable(),

                TextColumn::make('app.name')
                    ->label('所属应用')
                    ->placeholder('-')
                    ->sortable(),

                TextColumn::make('entitlement_label')
                    ->label('权益')
                    ->sortable(query: function ($query, $direction) {
                        return $query->orderBy('duration_value', $direction);
                    }),

                TextColumn::make('device_id')
                    ->label('绑定设备')
                    ->placeholder('未绑定')
                    ->toggleable(),

                TextColumn::make('activated_at')
                    ->label('激活时间')
                    ->dateTime('Y-m-d H:i')
                    ->sortable()
                    ->toggleable(),

                TextColumn::make('expires_at')
                    ->label('到期时间')
                    ->dateTime('Y-m-d H:i')
                    ->sortable()
                    ->toggleable(),

                TextColumn::make('last_verified_at')
                    ->label('最近验证')
                    ->dateTime('Y-m-d H:i')
                    ->sortable()
                    ->toggleable(),

                TextColumn::make('created_at')
                    ->label('创建时间')
                    ->dateTime('Y-m-d H:i')
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('type')
                    ->label('类型')
                    ->options(CardType::options()),

                SelectFilter::make('status')
                    ->label('状态')
                    ->options(CardStatus::options()),

                SelectFilter::make('app_id')
                    ->label('应用')
                    ->relationship('app', 'name'),
            ])
            ->headerActions([
                \pxlrbt\FilamentExcel\Actions\ExportAction::make()
                    ->label('导出 Excel'),
            ])
            ->actions([
                EditAction::make(),
            ])
            ->bulkActions([
                BulkActionGroup::make([
                    \pxlrbt\FilamentExcel\Actions\ExportBulkAction::make()
                        ->label('导出所选'),
                    DeleteBulkAction::make()
                        ->label('批量删除')
                        ->requiresConfirmation(),
                ]),
            ]);
    }
}