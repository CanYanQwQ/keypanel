<?php

namespace App\Filament\Resources\CardKeys\Pages;

use App\Enums\CardType;
use App\Enums\DurationUnit;
use App\Filament\Resources\CardKeys\CardKeyResource;
use App\Models\CardKey;
use App\Services\CardKeyService;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Components\Utilities\Get;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\CreateRecord;
use Filament\Resources\Pages\Concerns\HasWizard;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Wizard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\HtmlString;

class CreateCardKey extends CreateRecord
{
    use HasWizard;

    protected static string $resource = CardKeyResource::class;

    public function getSteps(): array
    {
        return [
            Wizard\Step::make('类型与数量')
                ->schema([
                    Select::make('type')
                        ->label('卡密类型')
                        ->options(CardType::options())
                        ->default(CardType::Time->value)
                        ->live()
                        ->required()
                        ->native(false),

                    TextInput::make('quantity')
                        ->label('生成数量')
                        ->numeric()
                        ->minValue(1)
                        ->maxValue((int) config('cardkey.card.max_batch_size', 10000))
                        ->default(10)
                        ->required(),

                    Select::make('app_id')
                        ->label('所属应用')
                        ->options(fn () => \App\Models\App::pluck('name', 'id')->toArray())
                        ->placeholder('不限制（通用卡密）')
                        ->nullable()
                        ->native(false),

                    TextInput::make('code_prefix')
                        ->label('卡密前缀')
                        ->helperText('可选，如 VIP，仅限大写字母与数字，最长 8 位')
                        ->nullable()
                        ->maxLength(8),
                ]),

            Wizard\Step::make('权益')
                ->schema([
                    Grid::make(1)->schema([
                        Select::make('duration_unit')
                            ->label('时长单位')
                            ->options(DurationUnit::options())
                            ->default(DurationUnit::Day->value)
                            ->hidden(fn (Get $get): bool => ! in_array($get('type'), [CardType::Time->value, CardType::Trial->value]))
                            ->native(false),

                        TextInput::make('duration_value')
                            ->label('时长数值')
                            ->numeric()->minValue(1)->default(30)
                            ->hidden(fn (Get $get): bool => ! in_array($get('type'), [CardType::Time->value, CardType::Trial->value])),

                        TextInput::make('max_uses')
                            ->label('可用次数')
                            ->numeric()->minValue(1)->default(100)
                            ->hidden(fn (Get $get): bool => $get('type') !== CardType::Count->value),
                    ]),
                ]),

            Wizard\Step::make('备注')
                ->schema([
                    TextInput::make('note')->label('备注')->nullable()->maxLength(255),
                ]),
        ];
    }

    protected function handleRecordCreation(array $data): Model
    {
        $app = isset($data['app_id']) ? \App\Models\App::find($data['app_id']) : null;
        $svc = app(CardKeyService::class);

        try {
            [$batch, $codes] = $svc->generateBatch(
                app: $app,
                type: CardType::from($data['type']),
                quantity: (int) ($data['quantity'] ?? 10),
                durationValue: isset($data['duration_value']) ? (int) $data['duration_value'] : null,
                durationUnit: isset($data['duration_unit']) ? DurationUnit::from($data['duration_unit']) : null,
                maxUses: isset($data['max_uses']) ? (int) $data['max_uses'] : null,
                codePrefix: $data['code_prefix'] ?? null,
                note: $data['note'] ?? null,
                createdBy: auth()->id(),
            );

            \App\Models\AdminOperationLog::create([
                'user_id' => auth()->id(),
                'admin_name' => auth()->user()->name,
                'action' => 'card.batch_generated',
                'description' => "批量生成 {$batch->quantity} 张「{$batch->type->getLabel()}」批次 {$batch->batch_no}",
                'target_type' => 'card_key_batch',
                'target_id' => (string) $batch->id,
                'ip' => request()->ip(),
            ]);

            $this->_batchNo = $batch->batch_no;
            $this->_plainCodes = $codes;
            $this->_quantity = count($codes);

            return CardKey::where('batch_id', $batch->id)->orderBy('id')->firstOrFail();
        } catch (\Throwable $e) {
            Notification::make()->title('生成失败')->body($e->getMessage())->danger()->send();
            throw $e;
        }
    }

    protected function getRedirectUrl(): string
    {
        return $this->getResourceUrl();
    }


    protected function afterCreate(): void
    {
        if (empty($this->_plainCodes)) return;

        $lines = collect($this->_plainCodes)
            ->map(fn (string $code, int $i) => ($i + 1).'. '.e($code))
            ->implode("\n");

        session()->flash('cardkey_batch_codes', $this->_plainCodes);
        session()->flash('cardkey_batch_no', $this->_batchNo);

        Notification::make()
            ->title("批次 {$this->_batchNo} 生成成功")
            ->body(new HtmlString(
                "<textarea readonly rows='10' style='width:100%;font-family:monospace;font-size:13px;line-height:1.8;border:1px solid var(--color-gray-300);border-radius:8px;padding:8px;resize:none;background:var(--color-gray-50);color:var(--color-gray-900)' "
                ."onfocus='this.select()' onmouseup='return false'>"
                . e($lines) . '</textarea>'
                .'<p style="margin-top:8px;font-size:12px;color:var(--color-gray-500)">点击上方文本框聚焦后按 Ctrl+C 复制所有卡密</p>'
            ))
            ->icon('heroicon-o-ticket')
            ->persistent()
            ->seconds(0)
            ->send();
    }

    private ?string $_batchNo = null;
    private array $_plainCodes = [];
    private int $_quantity = 0;
}
