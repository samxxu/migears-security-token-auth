<?php

declare(strict_types=1);

namespace MiGears\TokenAuth\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\TokenAuth\ArrayTokenStore;
use MiGears\TokenAuth\TokenRecord;

final class ArrayTokenStoreTest extends TestCase
{
    private ArrayTokenStore $store;

    protected function setUp(): void
    {
        $this->store = new ArrayTokenStore();
    }

    private function record(string $userId = '1', string $familyId = 'family-1', int $expiresAt = 2000): TokenRecord
    {
        return new TokenRecord(
            type: TokenRecord::TYPE_REFRESH,
            userId: $userId,
            familyId: $familyId,
            expiresAt: $expiresAt,
        );
    }

    public function testSaveAndFind(): void
    {
        $record = $this->record();
        $this->store->save('hash-1', $record);

        self::assertSame($record, $this->store->find('hash-1'));
        self::assertNull($this->store->find('hash-2'));
    }

    public function testSaveOverwritesTheSameKey(): void
    {
        $this->store->save('hash-1', $this->record());
        $used = $this->record()->withUsedAt(1500);
        $this->store->save('hash-1', $used);

        self::assertSame($used, $this->store->find('hash-1'));
        self::assertSame(1, $this->store->count());
    }

    public function testDeleteRemovesASingleRecord(): void
    {
        $this->store->save('hash-1', $this->record());

        $this->store->delete('hash-1');

        self::assertNull($this->store->find('hash-1'));
        self::assertSame(0, $this->store->count());
    }

    public function testDeleteByFamilyLeavesOtherFamiliesAlone(): void
    {
        $this->store->save('hash-1', $this->record(familyId: 'family-1'));
        $this->store->save('hash-2', $this->record(familyId: 'family-1'));
        $this->store->save('hash-3', $this->record(familyId: 'family-2'));

        $this->store->deleteByFamily('family-1');

        self::assertNull($this->store->find('hash-1'));
        self::assertNull($this->store->find('hash-2'));
        self::assertNotNull($this->store->find('hash-3'));
    }

    public function testDeleteByUserLeavesOtherUsersAlone(): void
    {
        $this->store->save('hash-1', $this->record(userId: '1'));
        $this->store->save('hash-2', $this->record(userId: '1', familyId: 'family-2'));
        $this->store->save('hash-3', $this->record(userId: '2'));

        $this->store->deleteByUser('1');

        self::assertNull($this->store->find('hash-1'));
        self::assertNull($this->store->find('hash-2'));
        self::assertNotNull($this->store->find('hash-3'));
    }

    public function testPruneExpiredRemovesOnlyExpiredRecords(): void
    {
        $this->store->save('hash-1', $this->record(expiresAt: 100));
        $this->store->save('hash-2', $this->record(expiresAt: 2000));

        $removed = $this->store->pruneExpired(500);

        self::assertSame(1, $removed);
        self::assertNull($this->store->find('hash-1'));
        self::assertNotNull($this->store->find('hash-2'));
    }

    public function testPruneExpiredOnEmptyStoreReturnsZero(): void
    {
        self::assertSame(0, $this->store->pruneExpired(500));
    }
}
