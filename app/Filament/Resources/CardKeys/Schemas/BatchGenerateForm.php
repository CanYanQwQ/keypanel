<?php

namespace App\Filament\Resources\CardKeys\Schemas;

use App\Enums\CardType;
use App\Enums\DurationUnit;
use App\Models\App;
use Closure;
use Filament\Forms\Components\Hidden;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Wizard;

class BatchGenerateForm
{
    public static function schema(): array
    {
        return [
            Wizard::make([
                Wizard\Step::make('类型与数量')
                    ->schema([
                        Select::make('type')
                            ->label('卡密类型')
                            ->options(CardType::options())
                            ->default(CardType::Time->value)
                            ->live()
                            ->required(),

                        TextInput::make('quantity')
                            ->label('生成数量')
                            ->numeric()
                            ->minValue(1)
                            ->maxValue((int) config('cardkey.card.max_batch_size', 10000))
                            ->default(10)
                            ->required(),

                        Select::make('app_id')
                            ->label('所属应用')
                            ->options(fn () => App::pluck('name', 'id')->toArray())
                            ->placeholder('不限制（通用卡密）')
                            ->nullable()
                            ->native(false),

                        TextInput::make('code_prefix')
                            ->label('卡密前缀')
                            ->helperText('可选，如 VIP、GOLD，仅限大写字母与数字，最长 8 位')
                            ->nullable()
                            ->maxLength(8),
                    ]),

                Wizard\Step::make('权益配置')
                    ->schema([
                        Grid::make(1)->schema([
                            Select::make('duration_unit')
                                ->label('时长单位')
                                ->options(DurationUnit::options())
                                ->default(DurationUnit::Day->value)
                                ->hidden(fn (Closure $get): bool => ! in_array($get('type'), [CardType::Time->value, CardType::Trial->value]))
                                ->native(false),

                            TextInput::make('duration_value')
                                ->label('时长数值')
                                ->numeric()
                                ->minValue(1)
                                ->default(30)
                                ->hidden(fn (Closure $get): bool => ! in_array($get('type'), [CardType::Time->value, CardType::Trial->value])),

                            TextInput::make('max_uses')
                                ->label('可用次数')
                                ->numeric()
                                ->minValue(1)
                                ->default(100)
                                ->hidden(fn (Closure $get): bool => $get('type') !== CardType::Count->value),
                        ]),
                    ]),

                Wizard\Step::make('备注与确认')
                    ->schema([
                        TextInput::make('note')
                            ->label('备注')
                            ->nullable()
                            ->maxLength(255),
                    ]),
            ])
            ->contained(false)
            ->columnSpanFull(),
        ];
    }
}