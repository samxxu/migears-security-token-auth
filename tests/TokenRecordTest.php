<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\SecurityTokenAuth\TokenRecord;

final class TokenRecordTest extends TestCase
{
    private function record(int $expiresAt = 2000): TokenRecord
    {
        return new TokenRecord(
            type: TokenRecord::TYPE_REFRESH,
            userId: '42',
            familyId: 'family-1',
            expiresAt: $expiresAt,
            deviceId: 'iphone-15',
        );
    }

    public function testIsExpiredIsInclusiveAtTheBoundary(): void
    {
        $record = $this->record(2000);

        self::assertFalse($record->isExpired(1999));
        // A record expiring exactly now is already dead
        self::assertTrue($record->isExpired(2000));
        self::assertTrue($record->isExpired(2001));
    }

    public function testFreshRecordIsNotUsed(): void
    {
        self::assertNull($this->record()->usedAt);
        self::assertFalse($this->record()->isUsed());
    }

    public function testWithUsedAtKeepsEveryOtherField(): void
    {
        $used = $this->record()->withUsedAt(1500);

        self::assertTrue($used->isUsed());
        self::assertSame(1500, $used->usedAt);
        self::assertSame(TokenRecord::TYPE_REFRESH, $used->type);
        self::assertSame('42', $used->userId);
        self::assertSame('family-1', $used->familyId);
        self::assertSame(2000, $used->expiresAt);
        self::assertSame('iphone-15', $used->deviceId);
    }

    public function testWithUsedAtReturnsANewInstance(): void
    {
        $record = $this->record();

        self::assertNotSame($record, $record->withUsedAt(1500));
        self::assertFalse($record->isUsed());
    }

    public function testStoredRoundTrip(): void
    {
        $record = $this->record()->withUsedAt(1500);

        self::assertEquals($record, TokenRecord::fromStored($record->toArray()));
    }

    public function testToArrayUsesSnakeCaseKeys(): void
    {
        self::assertSame([
            'type' => 'refresh',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
            'device_id' => 'iphone-15',
            'used_at' => null,
        ], $this->record()->toArray());
    }

    public function testFromStoredRejectsValuesThatAreNotArrays(): void
    {
        self::assertNull(TokenRecord::fromStored('a string'));
        self::assertNull(TokenRecord::fromStored(42));
        self::assertNull(TokenRecord::fromStored(null));
        self::assertNull(TokenRecord::fromStored(new \stdClass()));
    }

    public function testFromStoredRejectsMissingFields(): void
    {
        self::assertNull(TokenRecord::fromStored(['type' => 'access']));
        self::assertNull(TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
        ]));
    }

    public function testFromStoredRejectsAnUnknownType(): void
    {
        self::assertNull(TokenRecord::fromStored([
            'type' => 'session',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
        ]));
    }

    public function testFromStoredRejectsEmptyIdentityFields(): void
    {
        self::assertNull(TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '',
            'family_id' => 'family-1',
            'expires_at' => 2000,
        ]));

        self::assertNull(TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => '',
            'expires_at' => 2000,
        ]));
    }

    public function testFromStoredAcceptsNumericStringTimestamps(): void
    {
        // Cache adapters differ in how faithfully they round-trip integers
        $record = TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => '2000',
            'used_at' => '1500',
        ]);

        self::assertSame(2000, $record?->expiresAt);
        self::assertSame(1500, $record?->usedAt);
    }

    public function testFromStoredRejectsMalformedTimestamps(): void
    {
        self::assertNull(TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 'soon',
        ]));

        self::assertNull(TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
            'used_at' => 'soon',
        ]));
    }

    public function testFromStoredRejectsMalformedOptionalFields(): void
    {
        self::assertNull(TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
            'device_id' => 17,
        ]));
    }

    public function testFromStoredDefaultsOptionalFieldsToNull(): void
    {
        $record = TokenRecord::fromStored([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
        ]);

        self::assertNull($record?->deviceId);
        self::assertNull($record?->usedAt);
    }
}
