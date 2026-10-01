<?php

namespace App\Filament\Resources\Apps;

use App\Enums\AppStatus;
use App\Filament\Resources\Apps\Pages\CreateApp;
use App\Filament\Resources\Apps\Pages\EditApp;
use App\Filament\Resources\Apps\Pages\ListApps;
use App\Filament\Resources\Apps\Schemas\AppForm;
use App\Filament\Resources\Apps\Tables\AppsTable;
use App\Models\App;
use BackedEnum;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Table;
use UnitEnum;

class AppResource extends Resource
{
    protected static ?string $model = App::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedSquares2x2;

    protected static string|UnitEnum|null $navigationGroup = '管理';

    protected static ?string $navigationLabel = '应用管理';

    protected static ?string $modelLabel = '应用';

    protected static ?string $pluralModelLabel = '应用管理';

    public static function form(Schema $schema): Schema
    {
        return AppForm::configure($schema);
    }

    public static function table(Table $table): Table
    {
        return AppsTable::configure($table);
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListApps::route('/'),
            'create' => CreateApp::route('/create'),
            'edit' => EditApp::route('/{record}/edit'),
        ];
    }
}