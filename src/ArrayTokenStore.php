<?php

declare(strict_types=1);

namespace MiGears\TokenAuth;

/**
 * In-memory token store.
 *
 * Useful for tests, single-process workers, and as a reference implementation
 * of TokenStoreInterface. Multi-process deployments should back the interface
 * with shared storage (database, Redis) instead.
 */
final class ArrayTokenStore implements TokenStoreInterface
{
    /** @var array<string, TokenRecord> */
    private array $records = [];

    public function save(string $hash, TokenRecord $record): void
    {
        $this->records[$hash] = $record;
    }

    public function find(string $hash): ?TokenRecord
    {
        return $this->records[$hash] ?? null;
    }

    public function delete(string $hash): void
    {
        unset($this->records[$hash]);
    }

    public function deleteByFamily(string $familyId): void
    {
        foreach ($this->records as $hash => $record) {
            if ($record->familyId === $familyId) unset($this->records[$hash]);
        }
    }

    public function deleteByUser(string $userId): void
    {
        foreach ($this->records as $hash => $record) {
            if ($record->userId === $userId) unset($this->records[$hash]);
        }
    }

    public function pruneExpired(int $now): int
    {
        $removed = 0;

        foreach ($this->records as $hash => $record) {
            if ($record->isExpired($now)) {
                unset($this->records[$hash]);
                $removed++;
            }
        }

        return $removed;
    }

    /**
     * Number of records currently held. Handy for tests and diagnostics.
     */
    public function count(): int
    {
        return count($this->records);
    }
}
