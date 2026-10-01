<?php

namespace App\Services;

use App\Enums\ApiErrorCode;
use App\Models\CardKey;

/**
 * 卡密验证结果：统一 JSON 输出前的标准化中间产物。
 */
readonly class VerificationOutcome
{
    private function __construct(
        public bool $success,
        public ApiErrorCode $code,
        public ?array $data,
        public ?CardKey $card,
    ) {}

    public static function success(array $data, ?CardKey $card = null): self
    {
        return new self(true, ApiErrorCode::Success, $data, $card);
    }

    public static function fail(ApiErrorCode $code): self
    {
        return new self(false, $code, null, null);
    }

    /**
     * 组装为 API 统一 JSON 结构。
     */
    public function toApiResponse(): array
    {
        $payload = [
            'code' => $this->code->value,
            'message' => $this->code->message(),
            'success' => $this->success,
            'server_time' => now()->timestamp,
        ];

        if ($this->data !== null) {
            $payload['data'] = $this->data;
        }

        return $payload;
    }
}