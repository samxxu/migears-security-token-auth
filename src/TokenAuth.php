<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth;

use MiGears\Security\Token;
use MiGears\SecurityTokenAuth\Exception\TokenAuthException;
use Psr\SimpleCache\CacheInterface;

/**
 * Bearer token authentication for native apps and other non-browser clients.
 *
 * Issues a short-lived access token together with a long-lived, single-use
 * refresh token. Every refresh rotates the refresh token, so a stolen refresh
 * token is worth one use at most; replaying a rotated token is treated as theft
 * and revokes the whole family (a grace window keeps ordinary client retries
 * from being mistaken for theft).
 *
 * Both tokens are opaque random strings. Only the first half of their SHA-256
 * hash is ever used as a cache key, so a dumped store cannot be replayed against
 * the API, and access tokens can be revoked immediately instead of lingering
 * until they expire.
 *
 * Storage is any PSR-16 cache and the module owns three key prefixes inside it:
 * one key per token record, one marker per rotation family, and one generation
 * per user. Revocation rewrites a key instead of deleting a set of keys, because
 * PSR-16 cannot enumerate them; the layout and the key-length rule belong to
 * {@see TokenStoreKeys}.
 *
 * Two consequences follow from that layout, and both are deliberate:
 *
 * - A session has an absolute lifetime of refreshTtl. Rotation extends the
 *   refresh token itself, never the family marker, so a family cannot renew
 *   itself forever.
 * - A missing key counts as a mismatch. A store that evicts or loses keys
 *   therefore rejects tokens instead of resurrecting revoked ones, which is why
 *   the backend has to be durable and non-evicting.
 *
 * PSR-16 has no compare-and-swap, so single use holds for sequential requests
 * only: two requests racing on the same refresh token can both read it as unused
 * and both receive a successor.
 *
 * This class deliberately does not implement Security\AuthInterface: login()
 * there returns void and its $remember flag is a cookie concept, so a bearer
 * implementation would have to ignore both. Issuance is expressed as
 * issue()/refresh() instead, and the read side as authenticate().
 *
 * @template TUser of object
 */
final class TokenAuth implements TokenAuthInterface
{
    /** @var int Default access token TTL in seconds (15 minutes) */
    public const DEFAULT_ACCESS_TTL = 900;
    /** @var int Default refresh token TTL in seconds (30 days) */
    public const DEFAULT_REFRESH_TTL = 2592000;
    /** @var int Default window in which a replayed refresh token is treated as a retry (30 seconds) */
    public const DEFAULT_REUSE_GRACE_PERIOD = 30;

    /** @var int Token length in bytes before hex encoding */
    private const TOKEN_LENGTH = 32;
    /** @var int Family identifier length in bytes before hex encoding */
    private const FAMILY_ID_LENGTH = 16;
    /** @var int Generation length in bytes before hex encoding */
    private const GENERATION_LENGTH = 16;

    /** @var callable(string): ?TUser */
    private readonly mixed $userLoader;
    /** @var callable(): int|null */
    private readonly mixed $clock;

    /**
     * @param CacheInterface               $store            PSR-16 store holding records, family markers and user generations
     * @param callable(string): ?TUser     $userLoader       Loads a user from an ID
     * @param int                          $accessTtl        Access token TTL in seconds
     * @param int                          $refreshTtl       Refresh token TTL, and the absolute lifetime of a rotation family
     * @param int                          $reuseGracePeriod Seconds in which a replayed refresh token counts as a retry
     * @param callable(): int|null         $clock            Clock source, defaults to time()
     *
     * Declared as mixed rather than callable because PHP does not allow callable
     * as a property type.
     *
     * @throws TokenAuthException If a TTL, the grace period, the loader, or the clock is unusable
     */
    public function __construct(
        private readonly CacheInterface $store,
        mixed $userLoader,
        private readonly int $accessTtl = self::DEFAULT_ACCESS_TTL,
        private readonly int $refreshTtl = self::DEFAULT_REFRESH_TTL,
        private readonly int $reuseGracePeriod = self::DEFAULT_REUSE_GRACE_PERIOD,
        mixed $clock = null,
    ) {
        self::assertCallable($userLoader, 'userLoader');

        if ($accessTtl < 1) {
            throw TokenAuthException::invalidConfiguration('accessTtl must be at least 1 second.');
        }

        if ($refreshTtl < 1) {
            throw TokenAuthException::invalidConfiguration('refreshTtl must be at least 1 second.');
        }

        if ($reuseGracePeriod < 0) {
            throw TokenAuthException::invalidConfiguration('reuseGracePeriod cannot be negative.');
        }

        if ($clock !== null) self::assertCallable($clock, 'clock');

        $this->userLoader = $userLoader;
        $this->clock = $clock;
    }

    /**
     * Fail fast with a domain exception instead of an Error at first use.
     *
     * Takes mixed on purpose: the constructor documents these arguments as
     * callables, so only an untyped helper can still check them at runtime.
     *
     * @throws TokenAuthException If the value is not callable
     */
    private static function assertCallable(mixed $value, string $name): void
    {
        if (!is_callable($value)) {
            throw TokenAuthException::invalidConfiguration($name . ' must be callable.');
        }
    }

    /**
     * Store key holding a token record.
     *
     * Public because the key layout is part of the deployment: it is what an
     * operator inspects or clears, and what the documentation describes.
     * {@see TokenStoreKeys} owns the layout itself.
     */
    public static function recordKey(string $token): string
    {
        return TokenStoreKeys::recordKey($token);
    }

    /**
     * Store key marking a rotation family as alive, holding the generation it was issued under.
     */
    public static function familyKey(string $familyId): string
    {
        return TokenStoreKeys::familyKey($familyId);
    }

    /**
     * Store key holding a user's current revocation generation.
     */
    public static function userKey(string $userId): string
    {
        return TokenStoreKeys::userKey($userId);
    }

    /**
     * @param TUser $user
     *
     * @throws TokenAuthException If the user ID cannot be read or the tokens cannot be stored
     */
    public function issue(object $user, ?string $deviceId = null): TokenPair
    {
        $userId = $this->extractUserId($user);
        $familyId = Token::generate(self::FAMILY_ID_LENGTH);

        // The marker holds the generation the family was issued under, and it lives exactly
        // refreshTtl from here: rotation never extends it, so a session cannot renew forever.
        $this->write(
            self::familyKey($familyId),
            $this->userGeneration($userId),
            $this->now() + $this->refreshTtl,
            'the family marker',
        );

        return $this->createPair($userId, $familyId, $deviceId);
    }

    /**
     * @throws TokenAuthException If the token is unknown, expired, replayed, or cannot be rotated
     */
    public function refresh(string $refreshToken): TokenPair
    {
        $key = self::recordKey($refreshToken);
        $record = $this->load($key);

        // A refresh token must never be accepted where an access token is expected,
        // and vice versa, so the record type is checked on every lookup.
        if ($record === null || $record->type !== TokenRecord::TYPE_REFRESH) {
            throw TokenAuthException::unknownRefreshToken();
        }

        if ($record->isUsed()) {
            throw $this->handleReuse($record);
        }

        if ($record->isExpired($this->now())) {
            $this->store->delete($key);
            throw TokenAuthException::expiredRefreshToken();
        }

        if (!$this->familyIsHonoured($record)) {
            throw TokenAuthException::unknownRefreshToken();
        }

        // Single use: the presented token is consumed before its successor is written.
        // PSR-16 has no compare-and-swap, so a request that read this record before the
        // write below still sees it as unused.
        $this->write(
            $key,
            $record->withUsedAt($this->now())->toArray(),
            $record->expiresAt,
            'the consumed refresh token record',
        );

        return $this->createPair($record->userId, $record->familyId, $record->deviceId);
    }

    /**
     * @throws TokenAuthException If the revocation could not be stored
     */
    public function revoke(string $token): void
    {
        $record = $this->load(self::recordKey($token));

        // Unknown or already revoked tokens are not an error: logout is idempotent.
        if ($record === null) return;

        // Dropping the family marker kills every record of that family at once, which is
        // the reason the store never has to enumerate its keys.
        if ($this->store->delete(self::familyKey($record->familyId)) !== true) {
            throw TokenAuthException::storageFailure('the token family could not be revoked');
        }
    }

    /**
     * @throws TokenAuthException If the revocation could not be stored
     */
    public function revokeAllForUser(string $userId): void
    {
        // Every family marker holds the generation it was issued under, so one new
        // generation invalidates all of that user's families without touching them.
        $this->write(
            self::userKey($userId),
            $this->newGeneration(),
            $this->now() + $this->refreshTtl,
            'the user generation',
        );
    }

    /**
     * Resolve the user behind an access token.
     *
     * Returns null rather than throwing for unknown, expired, wrong-type, or
     * revoked tokens, so middleware can answer 401 without branching on
     * exceptions.
     *
     * @return TUser|null
     */
    public function authenticate(string $accessToken): ?object
    {
        $key = self::recordKey($accessToken);
        $record = $this->load($key);

        if ($record === null || $record->type !== TokenRecord::TYPE_ACCESS) return null;

        if ($record->isExpired($this->now())) {
            $this->store->delete($key);
            return null;
        }

        if (!$this->familyIsHonoured($record)) return null;

        $user = ($this->userLoader)($record->userId);

        return is_object($user) ? $user : null;
    }

    /**
     * Write the pair that belongs to a family, access record first.
     *
     * @throws TokenAuthException If either record cannot be stored
     */
    private function createPair(string $userId, string $familyId, ?string $deviceId): TokenPair
    {
        $now = $this->now();

        $accessToken = Token::generate(self::TOKEN_LENGTH);
        $refreshToken = Token::generate(self::TOKEN_LENGTH);

        $this->write(
            self::recordKey($accessToken),
            (new TokenRecord(
                type: TokenRecord::TYPE_ACCESS,
                userId: $userId,
                familyId: $familyId,
                expiresAt: $now + $this->accessTtl,
                deviceId: $deviceId,
            ))->toArray(),
            $now + $this->accessTtl,
            'the access token record',
        );

        // The refresh record lives for the whole family lifetime, so a consumed one stays
        // readable and a replay remains distinguishable from a random guess.
        $this->write(
            self::recordKey($refreshToken),
            (new TokenRecord(
                type: TokenRecord::TYPE_REFRESH,
                userId: $userId,
                familyId: $familyId,
                expiresAt: $now + $this->refreshTtl,
                deviceId: $deviceId,
            ))->toArray(),
            $now + $this->refreshTtl,
            'the refresh token record',
        );

        return new TokenPair($accessToken, $refreshToken, $this->accessTtl);
    }

    /**
     * Whether a record's family is still alive and still issued under the user's
     * current generation.
     *
     * A missing key answers false on purpose: a store that lost the marker, or never
     * had it, must not resurrect a revoked family. That is also why the backend has to
     * be durable and non-evicting.
     */
    private function familyIsHonoured(TokenRecord $record): bool
    {
        $familyKey = TokenStoreKeys::familyKey($record->familyId);
        $userKey = TokenStoreKeys::userKey($record->userId);

        $values = [];
        foreach ($this->store->getMultiple([$familyKey, $userKey]) as $key => $value) {
            $values[(string) $key] = $value;
        }

        $userGeneration = $values[$userKey] ?? null;

        // The marker must exist and carry the user's current generation
        return is_string($userGeneration)
            && TokenStoreKeys::holdsGeneration($values[$familyKey] ?? null, $userGeneration);
    }

    /**
     * The user's current revocation generation, seeded on first use.
     *
     * The seed writes only when the key is absent, and never refreshes an existing
     * value: rewriting a value read earlier could land after a concurrent
     * revokeAllForUser() and silently undo it.
     *
     * @throws TokenAuthException If the generation cannot be stored
     */
    private function userGeneration(string $userId): string
    {
        $key = self::userKey($userId);
        $current = $this->store->get($key);

        if (is_string($current) && $current !== '') return $current;

        $generation = $this->newGeneration();

        $this->write($key, $generation, $this->now() + $this->refreshTtl, 'the user generation');

        return $generation;
    }

    /**
     * Decide whether a replayed refresh token is a client retry or theft.
     *
     * @throws TokenAuthException Always: either the retry or the reuse flavour
     */
    private function handleReuse(TokenRecord $record): TokenAuthException
    {
        $usedAgo = $this->now() - (int) $record->usedAt;

        // A grace period of 0 means "revoke on the first replay".
        if ($usedAgo >= $this->reuseGracePeriod) {
            // Outside the window a rotated token can only come from a copy of the
            // stored token, so the entire family is revoked.
            $this->store->delete(self::familyKey($record->familyId));

            return TokenAuthException::refreshTokenReuseDetected();
        }

        return TokenAuthException::refreshTokenAlreadyUsed();
    }

    /**
     * @throws TokenAuthException
     */
    private function extractUserId(object $user): string
    {
        // is_callable() — unlike method_exists() — ignores non-public methods
        if (is_callable([$user, 'getId'])) {
            $userId = (string) $user->getId();
        } elseif (isset($user->id)) {
            $userId = (string) $user->id;
        } elseif ($user instanceof \ArrayAccess && isset($user['id'])) {
            $userId = (string) $user['id'];
        } else {
            throw TokenAuthException::cannotExtractUserId();
        }

        // An empty ID is not an identity: it would collapse every such user onto one key
        if ($userId === '') throw TokenAuthException::cannotExtractUserId();

        return $userId;
    }

    private function load(string $key): ?TokenRecord
    {
        return TokenRecord::fromStored($this->store->get($key));
    }

    /**
     * Store a value with an absolute expiry, refusing to continue when the store says no.
     *
     * @throws TokenAuthException If the store refused the write
     */
    private function write(string $key, mixed $value, int $expiresAt, string $what): void
    {
        $ttl = max(1, $expiresAt - $this->now());

        if ($this->store->set($key, $value, $ttl) !== true) {
            throw TokenAuthException::storageFailure($what . ' could not be stored');
        }
    }

    private function newGeneration(): string
    {
        return Token::generate(self::GENERATION_LENGTH);
    }

    private function now(): int
    {
        return $this->clock === null ? time() : (int) ($this->clock)();
    }
}
