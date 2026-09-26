<?php

declare(strict_types=1);

namespace MiGears\TokenAuth\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\TokenAuth\ArrayTokenStore;
use MiGears\TokenAuth\TokenAuth;
use MiGears\TokenAuth\TokenRecord;
use MiGears\TokenAuth\Exception\TokenAuthException;

/**
 * A user stub exposing getId().
 */
final class TestUser
{
    public function __construct(
        public readonly string $id,
        public readonly string $name = '',
    ) {
    }

    public function getId(): string
    {
        return $this->id;
    }
}

/**
 * A user stub with only a public $id property.
 */
final class TestUserWithProperty
{
    public function __construct(
        public string $id,
    ) {
    }
}

/**
 * A user stub exposing its ID through array access only.
 */
final class TestArrayAccessUser implements \ArrayAccess
{
    /** @param array<string, mixed> $data */
    public function __construct(private array $data)
    {
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->data[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->data[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->data[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->data[$offset]);
    }
}

final class TokenAuthTest extends TestCase
{
    private ArrayTokenStore $store;

    /** @var int Controllable clock used instead of time() */
    private int $now = 1700000000;

    /** @var array<string, TestUser> */
    private array $users = [];

    protected function setUp(): void
    {
        $this->store = new ArrayTokenStore();
        $this->now = 1700000000;
        $this->users = [
            '1' => new TestUser('1', 'Alice'),
            '2' => new TestUser('2', 'Bob'),
        ];
    }

    private function createAuth(
        int $accessTtl = TokenAuth::DEFAULT_ACCESS_TTL,
        int $refreshTtl = TokenAuth::DEFAULT_REFRESH_TTL,
        int $reuseGracePeriod = TokenAuth::DEFAULT_REUSE_GRACE_PERIOD,
        ?callable $userLoader = null,
    ): TokenAuth {
        return new TokenAuth(
            store: $this->store,
            userLoader: $userLoader ?? fn(string $id): ?object => $this->users[$id] ?? null,
            accessTtl: $accessTtl,
            refreshTtl: $refreshTtl,
            reuseGracePeriod: $reuseGracePeriod,
            clock: fn(): int => $this->now,
        );
    }

    private function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    // --- issue ---

    public function testIssueReturnsPairWithConfiguredTtl(): void
    {
        $pair = $this->createAuth(accessTtl: 120)->issue($this->users['1']);

        self::assertSame(120, $pair->expiresIn);
        self::assertSame('Bearer', $pair->tokenType);
        self::assertNotSame('', $pair->accessToken);
        self::assertNotSame('', $pair->refreshToken);
        self::assertNotSame($pair->accessToken, $pair->refreshToken);
    }

    public function testIssueStoresOnlyHashes(): void
    {
        $pair = $this->createAuth()->issue($this->users['1']);

        // The raw tokens must not be usable as storage keys
        self::assertNull($this->store->find($pair->accessToken));
        self::assertNull($this->store->find($pair->refreshToken));

        self::assertSame(TokenRecord::TYPE_ACCESS, $this->store->find($this->hash($pair->accessToken))?->type);
        self::assertSame(TokenRecord::TYPE_REFRESH, $this->store->find($this->hash($pair->refreshToken))?->type);
        self::assertSame(2, $this->store->count());
    }

    public function testIssueRecordsUserIdAndDeviceId(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1'], deviceId: 'iphone-15');

        $access = $this->store->find($this->hash($pair->accessToken));
        $refresh = $this->store->find($this->hash($pair->refreshToken));

        self::assertSame('1', $access?->userId);
        self::assertSame('iphone-15', $access?->deviceId);
        self::assertSame($access?->familyId, $refresh?->familyId);
        self::assertSame($this->now + TokenAuth::DEFAULT_ACCESS_TTL, $access?->expiresAt);
        self::assertSame($this->now + TokenAuth::DEFAULT_REFRESH_TTL, $refresh?->expiresAt);
    }

    public function testEachIssueStartsANewFamily(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);
        $second = $auth->issue($this->users['1']);

        self::assertNotSame(
            $this->store->find($this->hash($first->refreshToken))?->familyId,
            $this->store->find($this->hash($second->refreshToken))?->familyId,
        );
    }

    public function testIssueWithUserProperty(): void
    {
        $pair = $this->createAuth()->issue(new TestUserWithProperty('7'));

        self::assertSame('7', $this->store->find($this->hash($pair->accessToken))?->userId);
    }

    public function testIssueWithArrayAccessUser(): void
    {
        $pair = $this->createAuth()->issue(new TestArrayAccessUser(['id' => '9']));

        self::assertSame('9', $this->store->find($this->hash($pair->accessToken))?->userId);
    }

    public function testIssueWithUserWithoutIdThrows(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('Cannot extract user ID');

        $this->createAuth()->issue(new \stdClass());
    }

    // --- authenticate ---

    public function testAuthenticateReturnsTheUserBehindTheToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $user = $auth->authenticate($pair->accessToken);

        self::assertInstanceOf(TestUser::class, $user);
        self::assertSame('1', $user->getId());
        self::assertSame('Alice', $user->name);
    }

    public function testAuthenticateKeepsUsersApart(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);
        $second = $auth->issue($this->users['2']);

        self::assertSame('1', $auth->authenticate($first->accessToken)?->getId());
        self::assertSame('2', $auth->authenticate($second->accessToken)?->getId());
    }

    public function testAuthenticateWithUnknownTokenReturnsNull(): void
    {
        self::assertNull($this->createAuth()->authenticate('not-a-real-token'));
    }

    public function testAuthenticateRejectsARefreshToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        self::assertNull($auth->authenticate($pair->refreshToken));
    }

    public function testAuthenticateAfterAccessTtlReturnsNullAndDropsTheRecord(): void
    {
        $auth = $this->createAuth(accessTtl: 60);
        $pair = $auth->issue($this->users['1']);

        self::assertNotNull($auth->authenticate($pair->accessToken));

        $this->now += 61;

        self::assertNull($auth->authenticate($pair->accessToken));
        self::assertNull($this->store->find($this->hash($pair->accessToken)));
    }

    public function testAuthenticateWhenLoaderReturnsNonObjectReturnsNull(): void
    {
        $auth = $this->createAuth(userLoader: fn(string $id): string => 'not-an-object');
        $pair = $auth->issue($this->users['1']);

        self::assertNull($auth->authenticate($pair->accessToken));
    }

    // --- refresh ---

    public function testRefreshIssuesANewPairInTheSameFamily(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);

        $second = $auth->refresh($first->refreshToken);

        self::assertNotSame($first->accessToken, $second->accessToken);
        self::assertNotSame($first->refreshToken, $second->refreshToken);
        self::assertSame(TokenAuth::DEFAULT_ACCESS_TTL, $second->expiresIn);
        self::assertSame(
            $this->store->find($this->hash($first->refreshToken))?->familyId,
            $this->store->find($this->hash($second->refreshToken))?->familyId,
        );
    }

    public function testRefreshConsumesThePresentedToken(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);

        $auth->refresh($first->refreshToken);

        self::assertSame($this->now, $this->store->find($this->hash($first->refreshToken))?->usedAt);
    }

    public function testRefreshKeepsTheDeviceId(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1'], deviceId: 'iphone-15');

        $second = $auth->refresh($first->refreshToken);

        self::assertSame('iphone-15', $this->store->find($this->hash($second->refreshToken))?->deviceId);
    }

    public function testRepeatedRefreshKeepsOneFamily(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);

        $second = $auth->refresh($first->refreshToken);
        $third = $auth->refresh($second->refreshToken);

        self::assertSame(
            $this->store->find($this->hash($first->refreshToken))?->familyId,
            $this->store->find($this->hash($third->refreshToken))?->familyId,
        );
        self::assertSame('1', $auth->authenticate($third->accessToken)?->getId());
    }

    public function testRefreshWithUnknownTokenThrows(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('unknown');

        $this->createAuth()->refresh('not-a-real-token');
    }

    public function testRefreshRejectsAnAccessToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('unknown');

        $auth->refresh($pair->accessToken);
    }

    public function testRefreshAfterRefreshTtlThrowsAndDropsTheRecord(): void
    {
        $auth = $this->createAuth(refreshTtl: 100);
        $pair = $auth->issue($this->users['1']);

        $this->now += 101;

        try {
            $auth->refresh($pair->refreshToken);
            self::fail('Expected the expired refresh token to be rejected.');
        } catch (TokenAuthException $e) {
            self::assertStringContainsString('expired', $e->getMessage());
        }

        self::assertNull($this->store->find($this->hash($pair->refreshToken)));
    }

    public function testReplayInsideGraceWindowIsTreatedAsARetry(): void
    {
        $auth = $this->createAuth(reuseGracePeriod: 30);
        $first = $auth->issue($this->users['1']);
        $second = $auth->refresh($first->refreshToken);

        try {
            $auth->refresh($first->refreshToken);
            self::fail('Expected the replayed token to be rejected.');
        } catch (TokenAuthException $e) {
            self::assertStringContainsString('already been used', $e->getMessage());
        }

        // The family must survive, so the client's newest token still works
        $third = $auth->refresh($second->refreshToken);
        self::assertSame('1', $auth->authenticate($third->accessToken)?->getId());
    }

    public function testReplayAfterGraceWindowRevokesTheWholeFamily(): void
    {
        $auth = $this->createAuth(reuseGracePeriod: 30);
        $first = $auth->issue($this->users['1']);
        $second = $auth->refresh($first->refreshToken);

        $this->now += 31;

        try {
            $auth->refresh($first->refreshToken);
            self::fail('Expected the replayed token to be rejected.');
        } catch (TokenAuthException $e) {
            self::assertStringContainsString('revoked', $e->getMessage());
        }

        // Both the successor refresh token and its access token are gone
        self::assertNull($auth->authenticate($second->accessToken));
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('unknown');
        $auth->refresh($second->refreshToken);
    }

    public function testZeroGraceWindowRevokesImmediately(): void
    {
        $auth = $this->createAuth(reuseGracePeriod: 0);
        $first = $auth->issue($this->users['1']);
        $auth->refresh($first->refreshToken);

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('revoked');

        $auth->refresh($first->refreshToken);
    }

    // --- revoke ---

    public function testRevokeKillsTheFamily(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $auth->revoke($pair->refreshToken);

        self::assertNull($auth->authenticate($pair->accessToken));
        self::assertSame(0, $this->store->count());
    }

    public function testRevokeKillsRotatedTokensToo(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);
        $second = $auth->refresh($first->refreshToken);

        $auth->revoke($second->refreshToken);

        // The access token issued before the rotation dies with the family
        self::assertNull($auth->authenticate($first->accessToken));
        self::assertNull($auth->authenticate($second->accessToken));
        self::assertSame(0, $this->store->count());
    }

    public function testRevokeIsIdempotentForUnknownTokens(): void
    {
        $auth = $this->createAuth();

        $auth->revoke('not-a-real-token');
        $auth->revoke('not-a-real-token');

        self::assertSame(0, $this->store->count());
    }

    public function testRevokeAcceptsAnAccessToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $auth->revoke($pair->accessToken);

        self::assertNull($auth->authenticate($pair->accessToken));
        self::assertSame(0, $this->store->count());
    }

    public function testRevokeAllForUserOnlyTouchesThatUser(): void
    {
        $auth = $this->createAuth();
        $auth->issue($this->users['1'], deviceId: 'iphone-15');
        $auth->issue($this->users['1'], deviceId: 'pixel-9');
        $other = $auth->issue($this->users['2']);

        $auth->revokeAllForUser('1');

        self::assertSame(2, $this->store->count());
        self::assertSame('2', $auth->authenticate($other->accessToken)?->getId());
    }

    public function testRevokeAllForUnknownUserIsANoOp(): void
    {
        $auth = $this->createAuth();
        $auth->issue($this->users['1']);

        $auth->revokeAllForUser('999');

        self::assertSame(2, $this->store->count());
    }

    // --- configuration ---

    public function testConstructorRejectsNonPositiveAccessTtl(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('accessTtl');

        $this->createAuth(accessTtl: 0);
    }

    public function testConstructorRejectsNonPositiveRefreshTtl(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('refreshTtl');

        $this->createAuth(refreshTtl: 0);
    }

    public function testConstructorRejectsNegativeGracePeriod(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('reuseGracePeriod');

        $this->createAuth(reuseGracePeriod: -1);
    }

    public function testConstructorRejectsNonCallableUserLoader(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('userLoader');

        new TokenAuth(store: $this->store, userLoader: 42);
    }

    public function testConstructorRejectsNonCallableClock(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('clock');

        new TokenAuth(
            store: $this->store,
            userLoader: fn(string $id): ?object => null,
            clock: 42,
        );
    }
}
