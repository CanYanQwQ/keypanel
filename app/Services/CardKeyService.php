<?php

namespace App\Services;

use App\Enums\ApiErrorCode;
use App\Enums\CardStatus;
use App\Enums\CardType;
use App\Enums\DurationUnit;
use App\Models\App;
use App\Models\CardKey;
use App\Models\CardKeyBatch;
use App\Models\VerificationLog;
use App\Support\CardKeyCodec;
use App\Support\CardTransportCrypto;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use RuntimeException;

class CardKeyService
{
    public function decryptSubmittedCode(string|array $submitted, App $app): string
    {
        if (is_array($submitted)) {
            $key = CardTransportCrypto::deriveKey($app->app_secret, $app->app_id);

            try {
                $plain = CardTransportCrypto::decrypt($submitted, $key, $app->app_id);
            } catch (\Throwable) {
                throw new CardKeyException(ApiErrorCode::DecryptFailed);
            }
        } else {
            // 全局设置或应用级开关开启时，明文卡密一律拒绝
            if ($app->require_encrypted_card || SettingsService::getBool('api.require_encrypted_card')) {
                throw new CardKeyException(ApiErrorCode::DecryptFailed);
            }

            $plain = $submitted;
        }

        $plain = CardKeyCodec::normalize($plain);

        if (! CardKeyCodec::isWellFormed($plain)) {
            throw new CardKeyException(ApiErrorCode::CardNotFound);
        }

        return $plain;
    }

    /**
     * @return array{0: CardKeyBatch, 1: list<string>}
     */
    public function generateBatch(
        ?App $app,
        CardType $type,
        int $quantity,
        ?int $durationValue = null,
        ?DurationUnit $durationUnit = null,
        ?int $maxUses = null,
        ?string $codePrefix = null,
        ?string $note = null,
        ?int $createdBy = null,
    ): array {
        $plainCodes = [];

        for ($i = 0; $i < $quantity; $i++) {
            $plainCodes[] = CardKeyCodec::generate($codePrefix);
        }

        $hashes = array_map(fn (string $c) => CardKeyCodec::hash($c), $plainCodes);

        if (CardKey::whereIn('code_hash', $hashes)->exists()) {
            throw new RuntimeException('生成的卡密与已有卡密哈希冲突，请重试');
        }

        return DB::transaction(function () use ($app, $type, $quantity, $durationValue, $durationUnit, $maxUses, $codePrefix, $note, $createdBy, $plainCodes): array {
            $batch = CardKeyBatch::create([
                'batch_no' => CardKeyBatch::generateBatchNo(),
                'app_id' => $app?->id,
                'type' => $type->value,
                'quantity' => $quantity,
                'duration_value' => $durationValue,
                'duration_unit' => $durationUnit?->value,
                'max_uses' => $maxUses,
                'code_prefix' => $codePrefix !== null ? CardKeyCodec::normalizePrefix($codePrefix) : null,
                'note' => $note,
                'created_by' => $createdBy,
            ]);

            $now = now();
            $rows = [];

            foreach ($plainCodes as $code) {
                $rows[] = [
                    'app_id' => $app?->id,
                    'batch_id' => $batch->id,
                    'code_hash' => CardKeyCodec::hash($code),
                    'code_encrypted' => CardKeyCodec::encrypt($code),
                    'code_masked' => CardKeyCodec::mask($code),
                    'code_prefix' => CardKeyCodec::prefixOf($code),
                    'type' => $type->value,
                    'status' => CardStatus::Unused->value,
                    'duration_value' => $durationValue,
                    'duration_unit' => $durationUnit?->value,
                    'max_uses' => $maxUses,
                    'used_count' => 0,
                    'max_devices' => SettingsService::getInt('card.default_max_devices'),
                    'created_by' => $createdBy,
                    'created_at' => $now,
                    'updated_at' => $now,
                ];
            }

            CardKey::insert($rows);

            return [$batch, $plainCodes];
        });
    }

    public function verify(string $code, App $app, ?string $deviceId, ?string $ip, ?string $ua, ?string $reqId = null): VerificationOutcome
    {
        $card = CardKey::findByCode($code);
        $outcome = $this->runCardAction($card, $app, $deviceId, fn (CardKey $c) => $this->buildResponse($c));
        $this->writeLog($card, $app, 'verify', $outcome->code, $deviceId, $ip, $ua, $reqId);
        return $outcome;
    }

    public function activate(string $code, App $app, ?string $deviceId, ?string $ip, ?string $ua, ?string $reqId = null): VerificationOutcome
    {
        $card = CardKey::findByCode($code);

        $outcome = $this->runCardAction($card, $app, $deviceId, function (CardKey $c) use ($ip): array {
            if ($c->status === CardStatus::Unused) {
                $c->activated_at = now();
                $c->expires_at = $c->computeExpiresAt();
                $c->status = CardStatus::Activated;
                $c->last_verified_at = now();
                $c->last_verify_ip = $ip;
                $c->save();
            }
            $resp = $this->buildResponse($c);
            $resp['activated'] = true;
            return $resp;
        });
        $this->writeLog($card, $app, 'activate', $outcome->code, $deviceId, $ip, $ua, $reqId);
        return $outcome;
    }

    public function consume(string $code, App $app, ?string $deviceId, int $count, ?string $ip, ?string $ua, ?string $reqId = null): VerificationOutcome
    {
        if ($count < 1 || $count > 1000) {
            return VerificationOutcome::fail(ApiErrorCode::InvalidParams);
        }

        $card = CardKey::findByCode($code);

        $outcome = $this->runCardAction($card, $app, $deviceId, function (CardKey $c) use ($count, $ip): array {
            if ($c->type !== CardType::Count) {
                throw new CardKeyException(ApiErrorCode::CardTypeUnsupported);
            }
            $remaining = $c->remainingUses();
            if ($remaining <= 0) {
                throw new CardKeyException(ApiErrorCode::CardDepleted);
            }
            $actual = min($count, $remaining);
            $c->used_count += $actual;
            if ($c->isDepleted()) {
                $c->status = CardStatus::Depleted;
            }
            $c->last_verified_at = now();
            $c->last_verify_ip = $ip;
            $c->save();
            return ['consumed' => $actual, 'remaining' => $c->remainingUses()];
        });
        $this->writeLog($card, $app, 'consume', $outcome->code, $deviceId, $ip, $ua, $reqId);
        return $outcome;
    }

    public function query(string $code, App $app, ?string $deviceId, ?string $ip, ?string $ua, ?string $reqId = null): VerificationOutcome
    {
        $card = CardKey::findByCode($code);
        $outcome = $this->runCardAction($card, $app, $deviceId, fn (CardKey $c) => $this->buildResponse($c));
        $this->writeLog($card, $app, 'query', $outcome->code, $deviceId, $ip, $ua, $reqId);
        return $outcome;
    }

    public function unbind(string $code, App $app, ?string $deviceId, bool $force, ?string $ip, ?string $ua, ?string $reqId = null): VerificationOutcome
    {
        $card = CardKey::findByCode($code);

        $outcome = $this->runCardAction($card, $app, $deviceId, function (CardKey $c) use ($force, $deviceId): array {
            if (! $c->isBound()) {
                return ['unbound' => false, 'message' => '卡密尚未绑定设备'];
            }
            if (! $force && ! $c->deviceMatches($deviceId)) {
                throw new CardKeyException(ApiErrorCode::DeviceMismatch);
            }
            $c->device_id = null;
            $c->device_bound_at = null;
            $c->save();
            return ['unbound' => true];
        });
        $this->writeLog($card, $app, 'unbind', $outcome->code, $deviceId, $ip, $ua, $reqId);
        return $outcome;
    }

    // ========== admin ==========

    public function extend(CardKey $card, int $value, DurationUnit $unit): void
    {
        if ($card->type === CardType::Permanent) {
            throw new InvalidArgumentException('永久卡无需延长有效期');
        }
        $base = ($card->expires_at?->isFuture()) ? $card->expires_at : now();
        $card->expires_at = $unit->addTo($base, $value);
        $card->duration_value = $value;
        $card->duration_unit = $unit;
        if ($card->status === CardStatus::Expired) {
            $card->status = CardStatus::Activated;
        }
        $card->save();
    }

    public function resetUses(CardKey $card, ?int $newMax = null): void
    {
        if ($card->type !== CardType::Count) {
            throw new InvalidArgumentException('仅次数卡支持重置次数');
        }
        if ($newMax !== null && $newMax > 0) {
            $card->max_uses = $newMax;
        }
        $card->used_count = 0;
        if ($card->status === CardStatus::Depleted) {
            $card->status = $card->activated_at ? CardStatus::Activated : CardStatus::Unused;
        }
        $card->save();
    }

    public function resetBinding(CardKey $card): void
    {
        $card->device_id = null;
        $card->device_bound_at = null;
        $card->save();
    }

    public function setDisabled(CardKey $card, bool $disable, ?string $reason = null): void
    {
        if ($disable) {
            $card->status = CardStatus::Disabled;
            $card->disabled_at = now();
            $card->disabled_reason = $reason;
        } else {
            $resolved = $card->resolveStatus();
            $card->status = $resolved === CardStatus::Disabled
                ? ($card->activated_at ? CardStatus::Activated : CardStatus::Unused)
                : $resolved;
            $card->disabled_at = null;
            $card->disabled_reason = null;
        }
        $card->save();
    }

    // ========== internal ==========

    /**
     * 在事务与行锁保护下执行卡密操作。
     *
     * 为什么需要加锁：
     *   本方法内的多个判断都是「读取 → 判断 → 写入」模式：
     *     - consume 的 used_count 自增（并发时会互相覆盖，导致超扣次数）
     *     - 首次设备绑定（并发时两个请求可能各绑一台设备）
     *     - 状态检查与后续写入之间（并发时可能基于过期状态做决策）
     *
     *   加锁后，同一张卡密的并发请求会串行执行。业务语义完全不变，
     *   只是消除了竞态条件。不同卡密之间互不影响，不会降低整体吞吐。
     *
     * 注：SQLite 下 lockForUpdate() 不生效（Laravel 会忽略该子句），
     *     但本项目生产环境为 MySQL，行为符合预期。
     */
    private function runCardAction(?CardKey $card, App $app, ?string $deviceId, callable $action): VerificationOutcome
    {
        if ($card === null) {
            return VerificationOutcome::fail(ApiErrorCode::CardNotFound);
        }
        if ($card->app_id !== null && $card->app_id !== $app->id) {
            return VerificationOutcome::fail(ApiErrorCode::CardNotBoundToApp);
        }

        return DB::transaction(function () use ($card, $deviceId, $action): VerificationOutcome {
            // 重新读取并加行锁，确保后续判断基于最新状态。
            // 不能在事务外读取后再加锁，那样锁不住已过期的快照。
            $locked = CardKey::whereKey($card->getKey())->lockForUpdate()->first();

            if ($locked === null) {
                return VerificationOutcome::fail(ApiErrorCode::CardNotFound);
            }

            $status = $locked->resolveStatus();

            if ($status === CardStatus::Disabled) {
                return VerificationOutcome::fail(ApiErrorCode::CardDisabled);
            }
            if ($status === CardStatus::Expired) {
                return VerificationOutcome::fail(ApiErrorCode::CardExpired);
            }
            if ($status === CardStatus::Depleted) {
                return VerificationOutcome::fail(ApiErrorCode::CardDepleted);
            }
            if ($locked->isBound() && ! $locked->deviceMatches($deviceId)) {
                return VerificationOutcome::fail(ApiErrorCode::DeviceMismatch);
            }
            if (! $locked->isBound() && filled($deviceId) && $locked->max_devices > 0) {
                $locked->device_id = $deviceId;
                $locked->device_bound_at = now();
                $locked->bind_count = ($locked->bind_count ?? 0) + 1;
                $locked->save();
            }

            try {
                return VerificationOutcome::success($action($locked), $locked);
            } catch (CardKeyException $e) {
                return VerificationOutcome::fail($e->errorCode);
            }
        });
    }

    private function buildResponse(CardKey $card): array
    {
        return [
            'card_id' => $card->id,
            'status' => $card->status->value,
            'type' => $card->type->value,
            'activated_at' => $card->activated_at?->toIso8601String(),
            'expires_at' => $card->expires_at?->toIso8601String(),
            'remaining_seconds' => $card->secondsUntilExpiry(),
            'remaining_uses' => $card->remainingUses(),
            'device_bound' => $card->isBound(),
        ];
    }

    private function writeLog(?CardKey $card, App $app, string $action, ApiErrorCode $code, ?string $deviceId, ?string $ip, ?string $ua, ?string $reqId): void
    {
        VerificationLog::create([
            'app_id' => $app->id,
            'card_key_id' => $card?->id,
            'code_masked' => $card?->code_masked,
            'action' => $action,
            'result' => $code->isSuccess() ? 'success' : (string) $code->value,
            'message' => $code->message(),
            'ip' => $ip,
            'device_id' => $deviceId,
            'user_agent' => $ua,
            'request_id' => $reqId,
        ]);
    }
}
