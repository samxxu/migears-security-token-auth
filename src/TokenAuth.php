<?php

declare(strict_types=1);

namespace MiGears\TokenAuth;

use MiGears\Security\Token;
use MiGears\TokenAuth\Exception\TokenAuthException;

/**
 * Bearer token authentication for native apps and other non-browser clients.
 *
 * Issues a short-lived access token together with a long-lived, single-use
 * refresh token. Every refresh rotates the refresh token, so a stolen refresh
 * token is worth one use at most; replaying a rotated token is treated as
 * theft and revokes the whole family (a grace window keeps ordinary client
 * retries from being mistaken for theft).
 *
 * Both tokens are opaque random strings and only their SHA-256 hashes are
 * stored, so a dumped store cannot be replayed against the API and access
 * tokens can be revoked immediately instead of lingering until they expire.
 *
 * This class deliberately does not implement Security\AuthInterface: login()
 * there returns void and its $remember flag is a cookie concept, so a bearer
 * implementation would have to ignore both. Token issuance is expressed as
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

    /** @var callable(string): ?TUser */
    private readonly mixed $userLoader;
    /** @var callable(): int|null */
    private readonly mixed $clock;

    /**
     * @param TokenStoreInterface          $store            Storage for token records
     * @param callable(string): ?TUser     $userLoader       Loads a user from an ID
     * @param int                          $accessTtl        Access token TTL in seconds
     * @param int                          $refreshTtl       Refresh token TTL in seconds
     * @param int                          $reuseGracePeriod Seconds in which a replayed refresh token counts as a retry
     * @param callable(): int|null         $clock            Clock source, defaults to time()
     *
     * Declared as mixed rather than callable because PHP does not allow callable
     * as a property type.
     *
     * @throws TokenAuthException If a TTL, the grace period, the loader, or the clock is unusable
     */
    public function __construct(
        private readonly TokenStoreInterface $store,
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
     * @param TUser $user
     *
     * @throws TokenAuthException If the user ID cannot be read
     */
    public function issue(object $user, ?string $deviceId = null): TokenPair
    {
        return $this->createPair($this->extractUserId($user), null, $deviceId);
    }

    /**
     * @throws TokenAuthException If the token is unknown, expired, or replayed
     */
    public function refresh(string $refreshToken): TokenPair
    {
        $hash = $this->hash($refreshToken);
        $record = $this->store->find($hash);

        // A refresh token must never be accepted where an access token is expected,
        // and vice versa, so the record type is checked on every lookup.
        if ($record === null || $record->type !== TokenRecord::TYPE_REFRESH) {
            throw TokenAuthException::unknownRefreshToken();
        }

        if ($record->isUsed()) {
            throw $this->handleReuse($record);
        }

        if ($record->isExpired($this->now())) {
            $this->store->delete($hash);
            throw TokenAuthException::expiredRefreshToken();
        }

        // Single use: consume the presented token before issuing the successor,
        // so a concurrent replay cannot slip through.
        $this->store->save($hash, $record->withUsedAt($this->now()));

        return $this->createPair($record->userId, $record->familyId, $record->deviceId);
    }

    public function revoke(string $refreshToken): void
    {
        $record = $this->store->find($this->hash($refreshToken));

        // Unknown or already revoked tokens are not an error: logout is idempotent.
        if ($record === null) return;

        $this->store->deleteByFamily($record->familyId);
    }

    public function revokeAllForUser(string $userId): void
    {
        $this->store->deleteByUser($userId);
    }

    /**
     * Resolve the user behind an access token.
     *
     * Returns null rather than throwing for unknown, expired, or wrong-type
     * tokens, so middleware can answer 401 without branching on exceptions.
     *
     * @return TUser|null
     */
    public function authenticate(string $accessToken): ?object
    {
        $hash = $this->hash($accessToken);
        $record = $this->store->find($hash);

        if ($record === null || $record->type !== TokenRecord::TYPE_ACCESS) return null;

        if ($record->isExpired($this->now())) {
            $this->store->delete($hash);
            return null;
        }

        $user = ($this->userLoader)($record->userId);
        return is_object($user) ? $user : null;
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
            $this->store->deleteByFamily($record->familyId);

            return TokenAuthException::refreshTokenReuseDetected();
        }

        return TokenAuthException::refreshTokenAlreadyUsed();
    }

    private function createPair(string $userId, ?string $familyId, ?string $deviceId): TokenPair
    {
        $now = $this->now();

        // A rotation continues its family; a fresh issue starts a new one.
        $familyId ??= Token::generate(16);

        $accessToken = Token::generate(self::TOKEN_LENGTH);
        $refreshToken = Token::generate(self::TOKEN_LENGTH);

        $this->store->save($this->hash($accessToken), new TokenRecord(
            type: TokenRecord::TYPE_ACCESS,
            userId: $userId,
            familyId: $familyId,
            expiresAt: $now + $this->accessTtl,
            deviceId: $deviceId,
        ));

        // Both records share the family, so revoking one revokes the other.
        $this->store->save($this->hash($refreshToken), new TokenRecord(
            type: TokenRecord::TYPE_REFRESH,
            userId: $userId,
            familyId: $familyId,
            expiresAt: $now + $this->refreshTtl,
            deviceId: $deviceId,
        ));

        return new TokenPair($accessToken, $refreshToken, $this->accessTtl);
    }

    /**
     * @throws TokenAuthException
     */
    private function extractUserId(object $user): string
    {
        // is_callable() — unlike method_exists() — ignores non-public methods
        if (is_callable([$user, 'getId'])) return (string) $user->getId();
        if (isset($user->id)) return (string) $user->id;
        if ($user instanceof \ArrayAccess && isset($user['id'])) return (string) $user['id'];

        throw TokenAuthException::cannotExtractUserId();
    }

    /**
     * Storage key for a token: only the hash is ever persisted.
     */
    private function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    private function now(): int
    {
        return $this->clock === null ? time() : (int) ($this->clock)();
    }
}
