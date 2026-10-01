<?php

namespace App\Models;

use App\Enums\CardType;
use App\Enums\DurationUnit;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * 卡密批次：记录一次批量生成的来源，便于按批次追溯、导出与删除。
 */
class CardKeyBatch extends Model
{
    use HasFactory;

    protected $fillable = [
        'batch_no',
        'app_id',
        'type',
        'quantity',
        'duration_value',
        'duration_unit',
        'max_uses',
        'code_prefix',
        'note',
        'created_by',
    ];

    protected function casts(): array
    {
        return [
            'type' => CardType::class,
            'duration_unit' => DurationUnit::class,
            'quantity' => 'integer',
            'duration_value' => 'integer',
            'max_uses' => 'integer',
        ];
    }

    public static function generateBatchNo(): string
    {
        return 'B'.now()->format('YmdHis').strtoupper(bin2hex(random_bytes(2)));
    }

    // ------------------------------------------------------------------
    // 关联
    // ------------------------------------------------------------------

    public function app(): BelongsTo
    {
        return $this->belongsTo(App::class);
    }

    public function cardKeys(): HasMany
    {
        return $this->hasMany(CardKey::class, 'batch_id');
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    // ------------------------------------------------------------------
    // 展示
    // ------------------------------------------------------------------

    /**
     * 权益描述，如「30 天」「100 次」「永久」。
     */
    public function getEntitlementLabelAttribute(): string
    {
        return match (true) {
            $this->type === CardType::Permanent => '永久有效',
            $this->type === CardType::Count => ($this->max_uses ?? 0).' 次',
            $this->duration_value !== null && $this->duration_unit !== null
                => $this->duration_value.' '.$this->duration_unit->shortLabel(),
            default => '—',
        };
    }

    public function getUsedQuantityAttribute(): int
    {
        // 优先使用预加载的聚合值，避免 N+1
        if (array_key_exists('used_quantity', $this->attributes)) {
            return (int) $this->attributes['used_quantity'];
        }

        return $this->cardKeys()->where('status', '!=', 'unused')->count();
    }
}
