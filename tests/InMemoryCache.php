<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth\Tests;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache for the test suite.
 *
 * It is a test double, not a deployment option: entries live in the process and
 * nothing survives it. Beyond the interface it exposes what the tests need to
 * look at the store from the outside: the recorded TTLs, the number of writes a
 * key received, and the ability to evict a key the way a real cache under memory
 * pressure would.
 *
 * @phpstan-type Entry array{value: mixed, expiresAt: int|null}
 */
final class InMemoryCache implements CacheInterface
{
    /** @var array<string, Entry> */
    private array $entries = [];
    /** @var array<string, int|null> TTL as requested by the caller, for assertions */
    private array $ttls = [];
    /** @var array<string, int> Number of writes per key, for assertions */
    private array $writes = [];
    private bool $refuseWrites = false;
    private bool $refuseDeletes = false;

    public function __construct(private readonly ?\Closure $clock = null)
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $entry = $this->entries[$key] ?? null;

        if ($entry === null) return $default;

        if ($entry['expiresAt'] !== null && $entry['expiresAt'] <= $this->now()) {
            unset($this->entries[$key], $this->ttls[$key], $this->writes[$key]);

            return $default;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        if ($this->refuseWrites) return false;

        $seconds = $this->seconds($ttl);

        // PSR-16: a zero or negative TTL means the item is already expired
        if ($seconds !== null && $seconds <= 0) {
            $this->delete($key);

            return true;
        }

        $this->entries[$key] = [
            'value' => $value,
            'expiresAt' => $seconds === null ? null : $this->now() + $seconds,
        ];
        $this->ttls[$key] = $seconds;
        $this->writes[$key] = ($this->writes[$key] ?? 0) + 1;

        return true;
    }

    public function delete(string $key): bool
    {
        if ($this->refuseDeletes) return false;

        unset($this->entries[$key], $this->ttls[$key], $this->writes[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->entries = [];
        $this->ttls = [];
        $this->writes = [];

        return true;
    }

    /**
     * @param iterable<string> $keys
     *
     * @return array<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): array
    {
        $values = [];

        foreach ($keys as $key) {
            $values[(string) $key] = $this->get((string) $key, $default);
        }

        return $values;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            if (!$this->set((string) $key, $value, $ttl)) return false;
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        if ($this->refuseDeletes) return false;

        foreach ($keys as $key) {
            $this->delete((string) $key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, self::class) !== self::class;
    }

    /**
     * Number of live entries.
     */
    public function count(): int
    {
        $count = 0;
        foreach (array_keys($this->entries) as $key) {
            if ($this->get($key) !== null) $count++;
        }

        return $count;
    }

    /**
     * @return list<string>
     */
    public function keys(): array
    {
        $keys = [];
        foreach (array_keys($this->entries) as $key) {
            $keys[] = $key;
        }

        return $keys;
    }

    /**
     * @return array<string, mixed>
     */
    public function values(): array
    {
        $values = [];
        foreach (array_keys($this->entries) as $key) {
            $values[$key] = $this->entries[$key]['value'];
        }

        return $values;
    }

    /**
     * The TTL the module asked for, or null when it asked for no expiry.
     */
    public function ttlOf(string $key): ?int
    {
        return $this->ttls[$key] ?? null;
    }

    /**
     * How many times the module wrote that key.
     */
    public function writesOf(string $key): int
    {
        return $this->writes[$key] ?? 0;
    }

    /**
     * Drop a key the way an evicting backend would: without the caller noticing.
     */
    public function evict(string $key): void
    {
        unset($this->entries[$key], $this->ttls[$key], $this->writes[$key]);
    }

    /**
     * Make every later write fail, as a store under pressure would.
     */
    public function refuseWrites(bool $refuse = true): void
    {
        $this->refuseWrites = $refuse;
    }

    /**
     * Make every later delete fail, as a store under pressure would.
     */
    public function refuseDeletes(bool $refuse = true): void
    {
        $this->refuseDeletes = $refuse;
    }

    private function seconds(null|int|\DateInterval $ttl): ?int
    {
        if ($ttl instanceof \DateInterval) {
            return (int) (new \DateTimeImmutable('@' . $this->now()))->add($ttl)->getTimestamp() - $this->now();
        }

        return $ttl;
    }

    private function now(): int
    {
        return $this->clock === null ? time() : (int) ($this->clock)();
    }
}
