<?php

namespace App\Filament\Resources\CardKeys;

use App\Filament\Resources\CardKeys\Pages\CreateCardKey;
use App\Filament\Resources\CardKeys\Pages\EditCardKey;
use App\Filament\Resources\CardKeys\Pages\ListCardKeys;
use App\Filament\Resources\CardKeys\Schemas\CardKeyForm;
use App\Filament\Resources\CardKeys\Schemas\BatchGenerateForm;
use App\Filament\Resources\CardKeys\Tables\CardKeysTable;
use App\Models\CardKey;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;
use UnitEnum;

class CardKeyResource extends Resource
{
    protected static ?string $model = CardKey::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedTicket;

    protected static string|UnitEnum|null $navigationGroup = '管理';

    protected static ?string $navigationLabel = '卡密管理';

    protected static ?string $modelLabel = '卡密';

    protected static ?string $pluralModelLabel = '卡密管理';

    public static function form(Schema $schema): Schema
    {
        return CardKeyForm::configure($schema);
    }

    public static function table(Table $table): Table
    {
        return CardKeysTable::configure($table);
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListCardKeys::route('/'),
            'create' => CreateCardKey::route('/create'),
            'edit' => EditCardKey::route('/{record}/edit'),
        ];
    }
}