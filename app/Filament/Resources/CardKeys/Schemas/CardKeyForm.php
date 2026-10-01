<?php

namespace App\Filament\Resources\CardKeys\Schemas;

use App\Enums\AppStatus;
use App\Enums\CardStatus;
use App\Enums\CardType;
use App\Models\App;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;

class CardKeyForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema
            ->components([
                Section::make('基本信息')
                    ->schema([
                        Select::make('app_id')
                            ->label('所属应用')
                            ->options(fn () => App::pluck('name', 'id')->toArray())
                            ->placeholder('不限制（通用卡密）')
                            ->nullable()
                            ->native(false),

                        Select::make('status')
                            ->label('状态')
                            ->options(CardStatus::options())
                            ->required()
                            ->native(false),

                        Textarea::make('note')
                            ->label('备注')
                            ->rows(3),
                    ])
                    ->contained(false)
                    ->columns(1),
            ]);
    }
}