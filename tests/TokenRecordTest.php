<?php

declare(strict_types=1);

namespace MiGears\TokenAuth\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\TokenAuth\TokenRecord;
use MiGears\TokenAuth\Exception\TokenAuthException;

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

    public function testArrayRoundTrip(): void
    {
        $record = $this->record()->withUsedAt(1500);

        self::assertEquals($record, TokenRecord::fromArray($record->toArray()));
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

    public function testFromArrayRejectsMissingFields(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('malformed');

        TokenRecord::fromArray(['type' => 'access']);
    }

    public function testFromArrayRejectsWrongScalarTypes(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('malformed');

        TokenRecord::fromArray([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => '2000',
        ]);
    }

    public function testFromArrayRejectsMalformedOptionalFields(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('malformed');

        TokenRecord::fromArray([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
            'used_at' => 'soon',
        ]);
    }

    public function testFromArrayDefaultsOptionalFieldsToNull(): void
    {
        $record = TokenRecord::fromArray([
            'type' => 'access',
            'user_id' => '42',
            'family_id' => 'family-1',
            'expires_at' => 2000,
        ]);

        self::assertNull($record->deviceId);
        self::assertNull($record->usedAt);
    }
}
