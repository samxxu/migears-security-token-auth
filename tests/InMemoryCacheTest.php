<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth\Tests;

use PHPUnit\Framework\TestCase;

final class InMemoryCacheTest extends TestCase
{
    private int $now = 1700000000;

    private function cache(): InMemoryCache
    {
        $this->now = 1700000000;

        return new InMemoryCache(function (): int {
            return $this->now;
        });
    }

    public function testSetAndGet(): void
    {
        $cache = $this->cache();
        $cache->set('key-1', ['value' => 1]);

        self::assertSame(['value' => 1], $cache->get('key-1'));
        self::assertSame('fallback', $cache->get('key-2', 'fallback'));
        self::assertTrue($cache->has('key-1'));
        self::assertFalse($cache->has('key-2'));
    }

    public function testDeleteAndClear(): void
    {
        $cache = $this->cache();
        $cache->set('key-1', 1);
        $cache->set('key-2', 2);

        $cache->delete('key-1');
        self::assertNull($cache->get('key-1'));
        self::assertSame(1, $cache->count());

        $cache->clear();
        self::assertSame(0, $cache->count());
    }

    public function testEntryExpiresOnceTheTtlPasses(): void
    {
        $cache = $this->cache();
        $cache->set('key-1', 'value', 60);

        $this->now += 59;
        self::assertSame('value', $cache->get('key-1'));

        $this->now += 1;
        self::assertNull($cache->get('key-1'));
        self::assertSame(0, $cache->count());
    }

    public function testNoTtlMeansNoExpiryAndZeroTtlDeletes(): void
    {
        $cache = $this->cache();
        $cache->set('forever', 'value');

        $this->now += 86400 * 400;
        self::assertSame('value', $cache->get('forever'));

        // PSR-16: a zero TTL is a request to delete, not to store
        $cache->set('zero', 'value', 0);
        self::assertNull($cache->get('zero'));
    }

    public function testMultipleOperations(): void
    {
        $cache = $this->cache();
        $cache->setMultiple(['a' => 1, 'b' => 2], 60);

        self::assertSame(['a' => 1, 'b' => 2], $cache->getMultiple(['a', 'b']));
        self::assertSame(['a' => 1, 'c' => 'miss'], $cache->getMultiple(['a', 'c'], 'miss'));

        $cache->deleteMultiple(['a', 'b']);
        self::assertSame(0, $cache->count());
    }

    public function testRefuseWritesMakesEverySetFail(): void
    {
        $cache = $this->cache();
        $cache->refuseWrites();

        self::assertFalse($cache->set('key-1', 'value'));
        self::assertFalse($cache->setMultiple(['key-1' => 'value']));
        self::assertSame(0, $cache->count());
    }

    public function testRecordedTtlsAndWritesAreVisible(): void
    {
        $cache = $this->cache();
        $cache->set('key-1', 'value', 900);
        $cache->set('key-1', 'value', 900);

        self::assertSame(900, $cache->ttlOf('key-1'));
        self::assertSame(2, $cache->writesOf('key-1'));
        self::assertNull($cache->ttlOf('key-2'));
    }

    public function testEvictDropsAKeySilently(): void
    {
        $cache = $this->cache();
        $cache->set('key-1', 'value');

        $cache->evict('key-1');

        self::assertNull($cache->get('key-1'));
        self::assertSame(0, $cache->count());
    }

    public function testValuesExposeEveryEntry(): void
    {
        $cache = $this->cache();
        $cache->set('key-1', ['a' => 1]);
        $cache->set('key-2', 'plain');

        self::assertSame(['key-1' => ['a' => 1], 'key-2' => 'plain'], $cache->values());
        self::assertSame(['key-1', 'key-2'], $cache->keys());
    }
}
