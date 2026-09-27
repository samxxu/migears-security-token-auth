<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth;

/**
 * A stored token record.
 *
 * Records are immutable value objects; rotation replaces a record through
 * withUsedAt() rather than mutating it. toArray() is the exact shape written to
 * the PSR-16 store, and no field ever holds a usable credential: the cache key
 * is derived from the token's hash.
 *
 * A record carries no revocation state of its own. Whether it is still honoured
 * is decided by two cache keys outside it, the family marker and the user
 * generation, so a revocation never has to touch the records themselves.
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
     * Rebuild a record from the value read out of the store.
     *
     * Returns null instead of throwing: whatever sits under a token's key either
     * is one of our records or it counts as a cache miss, so a corrupted or
     * foreign value can never be mistaken for a valid token.
     *
     * Timestamps also accept a numeric string, because cache adapters differ in
     * how faithfully they round-trip integers.
     */
    public static function fromStored(mixed $value): ?self
    {
        if (!is_array($value)) return null;

        $type = $value['type'] ?? null;
        $userId = $value['user_id'] ?? null;
        $familyId = $value['family_id'] ?? null;
        $expiresAt = self::intOrNull($value['expires_at'] ?? null);
        $deviceId = $value['device_id'] ?? null;
        $usedAtRaw = $value['used_at'] ?? null;
        $usedAt = self::intOrNull($usedAtRaw);

        if (!is_string($type) || !is_string($userId) || !is_string($familyId)) return null;
        if ($type !== self::TYPE_ACCESS && $type !== self::TYPE_REFRESH) return null;
        if ($userId === '' || $familyId === '' || $expiresAt === null) return null;
        if ($usedAtRaw !== null && $usedAt === null) return null;
        if ($deviceId !== null && !is_string($deviceId)) return null;

        return new self(
            type: $type,
            userId: $userId,
            familyId: $familyId,
            expiresAt: $expiresAt,
            deviceId: $deviceId,
            usedAt: $usedAt,
        );
    }

    private static function intOrNull(mixed $value): ?int
    {
        if (is_int($value)) return $value;
        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) return (int) $value;

        return null;
    }
}
