<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\SecurityTokenAuth\TokenPair;

final class TokenPairTest extends TestCase
{
    public function testToArrayUsesOAuthFieldNames(): void
    {
        $pair = new TokenPair('access-token', 'refresh-token', 900);

        self::assertSame([
            'token_type' => 'Bearer',
            'access_token' => 'access-token',
            'expires_in' => 900,
            'refresh_token' => 'refresh-token',
        ], $pair->toArray());
    }

    public function testTokenTypeCanBeOverridden(): void
    {
        $pair = new TokenPair('a', 'r', 60, 'MAC');

        self::assertSame('MAC', $pair->tokenType);
        self::assertSame('MAC', $pair->toArray()['token_type']);
    }

    public function testPublicPropertiesExposeTheTokens(): void
    {
        $pair = new TokenPair('a', 'r', 60);

        self::assertSame('a', $pair->accessToken);
        self::assertSame('r', $pair->refreshToken);
        self::assertSame(60, $pair->expiresIn);
    }
}
