<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth;

/**
 * The cache key layout of the token store, in one place.
 *
 * The module owns three prefixes inside the caller's PSR-16 cache: one key per
 * token record, one marker per rotation family, and one generation per user.
 * Revocation deletes or rewrites a marker instead of removing a set of records,
 * because PSR-16 cannot enumerate keys.
 *
 * @internal Used by TokenAuth, which exposes the same keys to operators.
 */
final class TokenStoreKeys
{
    /**
     * @var int Hex characters of a hash kept in a cache key.
     *
     * PSR-16 only guarantees keys up to 64 characters, and a SHA-256 digest is
     * already 64 hex characters, so the digest is shortened to leave room for the
     * prefix. 128 bits of the hash is far beyond what guessing a 256-bit token
     * would need.
     */
    private const KEY_HASH_LENGTH = 32;

    /** @var string Key prefix for token records */
    private const PREFIX_RECORD = '__migears_tok_';
    /** @var string Key prefix for family markers */
    private const PREFIX_FAMILY = '__migears_fam_';
    /** @var string Key prefix for user generations */
    private const PREFIX_USER = '__migears_usr_';

    private function __construct()
    {
    }

    /**
     * Key holding a token record.
     */
    public static function recordKey(string $token): string
    {
        return self::PREFIX_RECORD . self::hash($token);
    }

    /**
     * Key marking a rotation family as alive, holding the generation it was issued under.
     */
    public static function familyKey(string $familyId): string
    {
        return self::PREFIX_FAMILY . self::hash($familyId);
    }

    /**
     * Key holding a user's current revocation generation.
     */
    public static function userKey(string $userId): string
    {
        return self::PREFIX_USER . self::hash($userId);
    }

    /**
     * Whether a value read out of the store is still one generation.
     *
     * Anything else answers false, a missing key included. That is what makes an
     * evicting store fail closed instead of resurrecting a revoked family.
     */
    public static function holdsGeneration(mixed $stored, string $generation): bool
    {
        return is_string($stored) && $stored !== '' && hash_equals($generation, $stored);
    }

    private static function hash(string $value): string
    {
        return substr(hash('sha256', $value), 0, self::KEY_HASH_LENGTH);
    }
}
