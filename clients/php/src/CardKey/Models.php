<?php

declare(strict_types=1);

namespace CardKey;

final class ApiResponse
{
    public function __construct(
        public readonly int $code,
        public readonly string $message,
        public readonly bool $success,
        public readonly int $serverTime,
        public readonly mixed $data,
    ) {
    }

    /** @param array<string, mixed> $payload */
    public static function fromArray(array $payload): self
    {
        foreach (['code', 'message', 'success', 'server_time'] as $field) {
            if (!array_key_exists($field, $payload)) {
                throw new ProtocolException("API response is missing {$field}");
            }
        }
        if (!is_int($payload['code']) && !is_numeric($payload['code'])) {
            throw new ProtocolException('API response code is invalid');
        }
        if (!is_bool($payload['success'])) {
            throw new ProtocolException('API response success is invalid');
        }

        return new self((int) $payload['code'], (string) $payload['message'], $payload['success'], (int) $payload['server_time'], $payload['data'] ?? null);
    }
}

final class EncryptedCardKey
{
    public function __construct(
        public readonly string $iv,
        public readonly string $data,
        public readonly string $tag,
    ) {
    }

    /** @return array{iv: string, data: string, tag: string} */
    public function toArray(): array
    {
        return ['iv' => $this->iv, 'data' => $this->data, 'tag' => $this->tag];
    }
}
