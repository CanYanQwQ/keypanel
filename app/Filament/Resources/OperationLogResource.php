<?php

namespace App\Filament\Resources;

use App\Models\AdminOperationLog;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use UnitEnum;

class OperationLogResource extends Resource
{
    protected static ?string $model = AdminOperationLog::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedDocumentText;

    protected static string|UnitEnum|null $navigationGroup = '日志';

    protected static ?string $navigationLabel = '操作日志';

    protected static ?string $modelLabel = '操作日志';

    protected static ?string $pluralModelLabel = '操作日志';

    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('created_at', 'desc')
            ->columns([
                TextColumn::make('action_label')->label('操作类型')->badge(),
                TextColumn::make('description')->label('描述')->searchable()->limit(60),
                TextColumn::make('admin_name')->label('操作人')->default('—'),
                TextColumn::make('ip')->label('IP')->copyable()->toggleable(),
                TextColumn::make('created_at')->label('时间')->dateTime('Y-m-d H:i:s')->sortable(),
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
            'index' => \App\Filament\Resources\OperationLogs\Pages\ListOperationLogs::route('/'),
        ];
    }
}