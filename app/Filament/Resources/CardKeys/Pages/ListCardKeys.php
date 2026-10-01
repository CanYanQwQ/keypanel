<?php

namespace App\Filament\Resources\CardKeys\Pages;

use App\Filament\Resources\CardKeys\CardKeyResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ListRecords;

class ListCardKeys extends ListRecords
{
    protected static string $resource = CardKeyResource::class;

    protected function getHeaderActions(): array
    {
        return [
            CreateAction::make()
                ->label('批量生成卡密'),
        ];
    }
}