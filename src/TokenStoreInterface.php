<?php

declare(strict_types=1);

namespace MiGears\TokenAuth;

/**
 * Storage contract for token records.
 *
 * Implementations are keyed by the SHA-256 hash of a token, never by the token
 * itself. A store must be able to remove records by family and by user, which
 * means the backing table needs an index on family_id and user_id.
 */
interface TokenStoreInterface
{
    /**
     * Persist a record, overwriting any record stored under the same hash.
     */
    public function save(string $hash, TokenRecord $record): void;

    /**
     * Look up a single record by token hash.
     */
    public function find(string $hash): ?TokenRecord;

    /**
     * Remove a single record by token hash.
     */
    public function delete(string $hash): void;

    /**
     * Remove every record in a rotation family, access tokens included.
     */
    public function deleteByFamily(string $familyId): void;

    /**
     * Remove every record owned by a user, across all devices and families.
     */
    public function deleteByUser(string $userId): void;

    /**
     * Drop records that expired at or before the given timestamp.
     *
     * Intended to be run from a scheduled job; TokenAuth never calls it, so
     * that per-request cost stays predictable.
     *
     * @return int Number of records removed
     */
    public function pruneExpired(int $now): int;
}
