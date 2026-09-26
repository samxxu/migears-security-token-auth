<?php

declare(strict_types=1);

namespace MiGears\TokenAuth;

use MiGears\TokenAuth\Exception\TokenAuthException;

/**
 * A stored token record.
 *
 * Records are immutable value objects; rotation replaces a record through
 * withUsedAt() rather than mutating it. Only the SHA-256 hash of a token is
 * ever used as the storage key, so a leaked store holds no usable token.
 */
final class TokenRecord
{
    /** @var string Access token record type */
    public const TYPE_ACCESS = 'access';
    /** @var string Refresh token record type */
    public const TYPE_REFRESH = 'refresh';

    /**
     * @param string      $type      One of TYPE_ACCESS or TYPE_REFRESH
     * @param string      $userId    Owner of the token
     * @param string      $familyId  Rotation chain this token belongs to
     * @param int         $expiresAt Unix timestamp after which the token is dead
     * @param string|null $deviceId  Optional device identifier supplied at issue time
     * @param int|null    $usedAt    Unix timestamp of the rotation that consumed this refresh token
     */
    public function __construct(
        public readonly string $type,
        public readonly string $userId,
        public readonly string $familyId,
        public readonly int $expiresAt,
        public readonly ?string $deviceId = null,
        public readonly ?int $usedAt = null,
    ) {
    }

    public function isExpired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }

    public function isUsed(): bool
    {
        return $this->usedAt !== null;
    }

    /**
     * Mark this record as consumed by a rotation.
     */
    public function withUsedAt(int $usedAt): self
    {
        return new self(
            type: $this->type,
            userId: $this->userId,
            familyId: $this->familyId,
            expiresAt: $this->expiresAt,
            deviceId: $this->deviceId,
            usedAt: $usedAt,
        );
    }

    /**
     * @return array{type: string, user_id: string, family_id: string, expires_at: int, device_id: string|null, used_at: int|null}
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'user_id' => $this->userId,
            'family_id' => $this->familyId,
            'expires_at' => $this->expiresAt,
            'device_id' => $this->deviceId,
            'used_at' => $this->usedAt,
        ];
    }

    /**
     * Rebuild a record from its stored representation.
     *
     * @param array<string, mixed> $data
     *
     * @throws TokenAuthException If a required field is missing or has the wrong shape
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['type'], $data['user_id'], $data['family_id'], $data['expires_at'])) {
            throw TokenAuthException::invalidRecord();
        }

        if (!is_string($data['type']) || !is_string($data['user_id']) || !is_string($data['family_id'])) {
            throw TokenAuthException::invalidRecord();
        }

        if (!is_int($data['expires_at'])) {
            throw TokenAuthException::invalidRecord();
        }

        $deviceId = $data['device_id'] ?? null;
        $usedAt = $data['used_at'] ?? null;

        if (($deviceId !== null && !is_string($deviceId)) || ($usedAt !== null && !is_int($usedAt))) {
            throw TokenAuthException::invalidRecord();
        }

        return new self(
            type: $data['type'],
            userId: $data['user_id'],
            familyId: $data['family_id'],
            expiresAt: $data['expires_at'],
            deviceId: $deviceId,
            usedAt: $usedAt,
        );
    }
}
