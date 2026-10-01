<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\SecurityTokenAuth\TokenAuth;
use MiGears\SecurityTokenAuth\TokenAuthInterface;
use MiGears\SecurityTokenAuth\TokenRecord;
use MiGears\SecurityTokenAuth\Exception\TokenAuthException;

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
 * A user stub whose getId() answers null, so no ID can be read.
 */
final class TestUserWithoutId
{
    public function getId(): ?string
    {
        return null;
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
    private InMemoryCache $cache;

    /** @var int Controllable clock shared with the store */
    private int $now = 1700000000;

    /** @var array<string, TestUser> */
    private array $users = [];

    protected function setUp(): void
    {
        $this->now = 1700000000;
        $this->cache = new InMemoryCache(function (): int {
            return $this->now;
        });
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
            store: $this->cache,
            userLoader: $userLoader ?? fn(string $id): ?object => $this->users[$id] ?? null,
            accessTtl: $accessTtl,
            refreshTtl: $refreshTtl,
            reuseGracePeriod: $reuseGracePeriod,
            clock: function (): int {
                return $this->now;
            },
        );
    }

    private function recordFor(string $token): ?TokenRecord
    {
        return TokenRecord::fromStored($this->cache->get(TokenAuth::recordKey($token)));
    }

    private function familyIdOf(string $refreshToken): string
    {
        return (string) $this->recordFor($refreshToken)?->familyId;
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

        // Neither key nor value may contain a usable token
        foreach ($this->cache->keys() as $key) {
            self::assertStringNotContainsString($pair->accessToken, $key);
            self::assertStringNotContainsString($pair->refreshToken, $key);
        }

        foreach ($this->cache->values() as $value) {
            self::assertStringNotContainsString($pair->accessToken, (string) json_encode($value));
            self::assertStringNotContainsString($pair->refreshToken, (string) json_encode($value));
        }
    }

    public function testIssueWritesTheDocumentedKeyLayout(): void
    {
        $pair = $this->createAuth()->issue($this->users['1'], deviceId: 'iphone-15');

        $access = $this->recordFor($pair->accessToken);
        $refresh = $this->recordFor($pair->refreshToken);
        $familyId = $this->familyIdOf($pair->refreshToken);

        // Two records, one family marker and one user generation
        self::assertSame(4, $this->cache->count());

        self::assertSame(TokenRecord::TYPE_ACCESS, $access?->type);
        self::assertSame('iphone-15', $access?->deviceId);
        self::assertSame($this->now + TokenAuth::DEFAULT_ACCESS_TTL, $access?->expiresAt);
        self::assertSame(TokenRecord::TYPE_REFRESH, $refresh?->type);
        self::assertSame('1', $refresh?->userId);
        self::assertSame($this->now + TokenAuth::DEFAULT_REFRESH_TTL, $refresh?->expiresAt);
        self::assertSame($access?->familyId, $refresh?->familyId);

        // The marker holds the user generation the family was issued under,
        // and both live for the whole family lifetime
        $generation = $this->cache->get(TokenAuth::userKey('1'));
        self::assertIsString($generation);
        self::assertNotSame('', $generation);
        self::assertSame($generation, $this->cache->get(TokenAuth::familyKey($familyId)));
        self::assertSame(TokenAuth::DEFAULT_REFRESH_TTL, $this->cache->ttlOf(TokenAuth::familyKey($familyId)));
        self::assertSame(TokenAuth::DEFAULT_REFRESH_TTL, $this->cache->ttlOf(TokenAuth::userKey('1')));
    }

    public function testEachIssueStartsANewFamily(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);
        $second = $auth->issue($this->users['1']);

        self::assertNotSame(
            $this->familyIdOf($first->refreshToken),
            $this->familyIdOf($second->refreshToken),
        );
    }

    public function testSecondLoginKeepsTheUserGenerationAndRenewsItsTtl(): void
    {
        $auth = $this->createAuth(refreshTtl: 100);
        $auth->issue($this->users['1']);
        $generation = $this->cache->get(TokenAuth::userKey('1'));

        $this->now += 90;
        $auth->issue($this->users['1']);

        // The value is unchanged, so logging in on one device never signs out another...
        self::assertSame($generation, $this->cache->get(TokenAuth::userKey('1')));
        // ...but its lifetime follows the most recent login, not the first one
        self::assertSame(2, $this->cache->writesOf(TokenAuth::userKey('1')));
        self::assertSame(100, $this->cache->ttlOf(TokenAuth::userKey('1')));
    }

    public function testALaterLoginKeepsItsFamilyAlivePastTheFirstLoginsUserTtl(): void
    {
        // refreshTtl 100, accessTtl 900: the scenario the report reproduces.
        $auth = $this->createAuth(accessTtl: 900, refreshTtl: 100);
        $auth->issue($this->users['1']);           // t=0: seeds the user generation, which expires at t=100

        $this->now += 90;
        $second = $auth->issue($this->users['1']); // t=90: its family marker lives until t=190

        $this->now += 11;                          // t=101: one second past the first login's user-key TTL

        // The family issued at t=90 still had nearly all of its 900s access life and must still work.
        self::assertSame('1', $auth->authenticate($second->accessToken)?->getId());

        // A login at t=101 must not bump the generation and silently sign that family out.
        $third = $auth->issue($this->users['1']);
        self::assertSame('1', $auth->authenticate($second->accessToken)?->getId());
        self::assertSame('1', $auth->authenticate($third->accessToken)?->getId());
    }

    public function testIssueWithUserProperty(): void
    {
        $pair = $this->createAuth()->issue(new TestUserWithProperty('7'));

        self::assertSame('7', $this->recordFor($pair->accessToken)?->userId);
    }

    public function testIssueWithArrayAccessUser(): void
    {
        $pair = $this->createAuth()->issue(new TestArrayAccessUser(['id' => '9']));

        self::assertSame('9', $this->recordFor($pair->accessToken)?->userId);
    }

    public function testIssueWithUserWithoutIdThrows(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('Cannot extract user ID');

        $this->createAuth()->issue(new \stdClass());
    }

    public function testIssueWithEmptyUserIdThrows(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('Cannot extract user ID');

        $this->createAuth()->issue(new TestUserWithoutId());
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
        self::assertNull($this->cache->get(TokenAuth::recordKey($pair->accessToken)));
    }

    public function testAnAccessRecordKeptPastItsExpiryIsStillRejected(): void
    {
        $auth = $this->createAuth(accessTtl: 60);
        $pair = $auth->issue($this->users['1']);
        $key = TokenAuth::recordKey($pair->accessToken);

        // A store that ignores or rounds up TTLs would still be holding the record,
        // exactly as in testARecordKeptPastItsExpiryIsStillRejected on the refresh side
        $this->cache->set($key, [
            'type' => TokenRecord::TYPE_ACCESS,
            'user_id' => '1',
            'family_id' => $this->familyIdOf($pair->refreshToken),
            'expires_at' => $this->now - 1,
            'device_id' => null,
            'used_at' => null,
        ]);

        self::assertNull($auth->authenticate($pair->accessToken));
        self::assertNull($this->cache->get($key));
    }

    public function testAuthenticateWhenLoaderReturnsNonObjectReturnsNull(): void
    {
        $auth = $this->createAuth(userLoader: fn(string $id): string => 'not-an-object');
        $pair = $auth->issue($this->users['1']);

        self::assertNull($auth->authenticate($pair->accessToken));
    }

    public function testAuthenticateWhenLoaderReturnsNullReturnsNull(): void
    {
        $auth = $this->createAuth(userLoader: fn(string $id): ?object => null);
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
            $this->familyIdOf($first->refreshToken),
            $this->familyIdOf($second->refreshToken),
        );
    }

    public function testRefreshConsumesThePresentedToken(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);

        $auth->refresh($first->refreshToken);

        $consumed = $this->recordFor($first->refreshToken);
        self::assertSame($this->now, $consumed?->usedAt);
        self::assertTrue($consumed?->isUsed());

        // A consumed record keeps its original lifetime, so the replay stays visible
        self::assertSame(TokenAuth::DEFAULT_REFRESH_TTL, $this->cache->ttlOf(TokenAuth::recordKey($first->refreshToken)));
    }

    public function testRefreshKeepsTheDeviceId(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1'], deviceId: 'iphone-15');

        $second = $auth->refresh($first->refreshToken);

        self::assertSame('iphone-15', $this->recordFor($second->refreshToken)?->deviceId);
    }

    public function testRepeatedRefreshKeepsOneFamily(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);

        $second = $auth->refresh($first->refreshToken);
        $third = $auth->refresh($second->refreshToken);

        self::assertSame(
            $this->familyIdOf($first->refreshToken),
            $this->familyIdOf($third->refreshToken),
        );
        self::assertSame('1', $auth->authenticate($third->accessToken)?->getId());
    }

    public function testRotationDoesNotExtendTheFamilyLifetime(): void
    {
        $auth = $this->createAuth();
        $first = $auth->issue($this->users['1']);
        $familyKey = TokenAuth::familyKey($this->familyIdOf($first->refreshToken));

        $auth->refresh($first->refreshToken);

        // Only issue() writes the marker, so the family keeps its absolute lifetime
        self::assertSame(1, $this->cache->writesOf($familyKey));
        self::assertSame(TokenAuth::DEFAULT_REFRESH_TTL, $this->cache->ttlOf($familyKey));
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
            // Expiry is the store's TTL, so an expired token reads as an unknown one
            self::assertStringContainsString('unknown', $e->getMessage());
        }

        self::assertNull($this->cache->get(TokenAuth::recordKey($pair->refreshToken)));
    }

    public function testARecordKeptPastItsExpiryIsStillRejected(): void
    {
        $auth = $this->createAuth(refreshTtl: 100);
        $pair = $auth->issue($this->users['1']);
        $key = TokenAuth::recordKey($pair->refreshToken);

        // A store that ignores or rounds up TTLs would still be holding the record
        $this->cache->set($key, [
            'type' => TokenRecord::TYPE_REFRESH,
            'user_id' => '1',
            'family_id' => $this->familyIdOf($pair->refreshToken),
            'expires_at' => $this->now - 1,
            'device_id' => null,
            'used_at' => null,
        ]);

        try {
            $auth->refresh($pair->refreshToken);
            self::fail('Expected the expired refresh token to be rejected.');
        } catch (TokenAuthException $e) {
            self::assertStringContainsString('expired', $e->getMessage());
        }

        self::assertNull($this->cache->get($key));
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

    public function testRefusedDeleteWhileRevokingAReplayedFamilyThrows(): void
    {
        $auth = $this->createAuth(reuseGracePeriod: 30);
        $first = $auth->issue($this->users['1']);
        $auth->refresh($first->refreshToken);

        $this->now += 31;
        $this->cache->refuseDeletes();

        // The replay revokes the family; a store that refuses the delete must not
        // leave that revocation unnoticed, exactly as revoke() does not.
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('could not be revoked');

        $auth->refresh($first->refreshToken);
    }

    // --- revoke ---

    public function testRevokeKillsTheFamily(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);
        $familyKey = TokenAuth::familyKey($this->familyIdOf($pair->refreshToken));

        $auth->revoke($pair->refreshToken);

        // The marker is what carries revocation, so the records themselves may stay
        self::assertNull($this->cache->get($familyKey));
        self::assertNull($auth->authenticate($pair->accessToken));
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
    }

    public function testRevokeIsIdempotentForUnknownTokens(): void
    {
        $auth = $this->createAuth();

        $auth->revoke('not-a-real-token');
        $auth->revoke('not-a-real-token');

        self::assertSame(0, $this->cache->count());
    }

    public function testRevokeAcceptsAnAccessToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $auth->revoke($pair->accessToken);

        self::assertNull($auth->authenticate($pair->accessToken));
    }

    public function testRevokeWithAnExpiredAccessTokenLeavesTheFamilyAlive(): void
    {
        $auth = $this->createAuth(accessTtl: 60);
        $pair = $auth->issue($this->users['1']);
        $familyKey = TokenAuth::familyKey($this->familyIdOf($pair->refreshToken));

        // The access record lives accessTtl only; past it the store has dropped it.
        $this->now += 61;
        self::assertNull($this->cache->get(TokenAuth::recordKey($pair->accessToken)));

        // revoke() resolves the token through its record, so an expired access token
        // cannot resolve the family: the call is a silent no-op, not a revocation.
        $auth->revoke($pair->accessToken);

        // The marker and the 30-day refresh token are untouched, so refresh still works
        self::assertNotNull($this->cache->get($familyKey));
        $rotated = $auth->refresh($pair->refreshToken);
        self::assertSame('1', $auth->authenticate($rotated->accessToken)?->getId());
    }

    public function testRevokeLeavesOtherFamiliesOfTheSameUserAlone(): void
    {
        $auth = $this->createAuth();
        $phone = $auth->issue($this->users['1'], deviceId: 'iphone-15');
        $tablet = $auth->issue($this->users['1'], deviceId: 'ipad-pro');

        $auth->revoke($phone->refreshToken);

        self::assertNull($auth->authenticate($phone->accessToken));
        self::assertSame('1', $auth->authenticate($tablet->accessToken)?->getId());
    }

    // --- revokeAllForUser ---

    public function testRevokeAllForUserKillsEveryFamilyOfThatUser(): void
    {
        $auth = $this->createAuth();
        $phone = $auth->issue($this->users['1'], deviceId: 'iphone-15');
        $tablet = $auth->issue($this->users['1'], deviceId: 'ipad-pro');

        $auth->revokeAllForUser('1');

        self::assertNull($auth->authenticate($phone->accessToken));
        self::assertNull($auth->authenticate($tablet->accessToken));

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('unknown');
        $auth->refresh($phone->refreshToken);
    }

    public function testRevokeAllForUserOnlyTouchesThatUser(): void
    {
        $auth = $this->createAuth();
        $auth->issue($this->users['1'], deviceId: 'iphone-15');
        $auth->issue($this->users['1'], deviceId: 'pixel-9');
        $other = $auth->issue($this->users['2']);

        $auth->revokeAllForUser('1');

        self::assertSame('2', $auth->authenticate($other->accessToken)?->getId());
    }

    public function testRevokeAllForAnUnknownUserLeavesEveryoneSignedIn(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $auth->revokeAllForUser('999');

        self::assertSame('1', $auth->authenticate($pair->accessToken)?->getId());
    }

    public function testLoginAfterRevokingAllStartsFresh(): void
    {
        $auth = $this->createAuth();
        $old = $auth->issue($this->users['1']);
        $auth->revokeAllForUser('1');

        $fresh = $auth->issue($this->users['1']);

        self::assertNull($auth->authenticate($old->accessToken));
        self::assertSame('1', $auth->authenticate($fresh->accessToken)?->getId());

        $rotated = $auth->refresh($fresh->refreshToken);
        self::assertSame('1', $auth->authenticate($rotated->accessToken)?->getId());
    }

    // --- store failures and lost keys ---

    public function testEvictedFamilyMarkerRejectsTheToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $this->cache->evict(TokenAuth::familyKey($this->familyIdOf($pair->refreshToken)));

        self::assertNull($auth->authenticate($pair->accessToken));

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('unknown');
        $auth->refresh($pair->refreshToken);
    }

    public function testEvictedUserGenerationRejectsTheToken(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $this->cache->evict(TokenAuth::userKey('1'));

        self::assertNull($auth->authenticate($pair->accessToken));
    }

    public function testCorruptedRecordValueCountsAsAMiss(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);

        $this->cache->set(TokenAuth::recordKey($pair->accessToken), ['type' => 'access']);

        self::assertNull($auth->authenticate($pair->accessToken));
    }

    public function testRefusedWriteDuringIssueThrows(): void
    {
        $auth = $this->createAuth();
        $this->cache->refuseWrites();

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('Token storage failure');

        $auth->issue($this->users['1']);
    }

    public function testRefusedWriteDuringRevokeAllForUserThrows(): void
    {
        $auth = $this->createAuth();
        $auth->issue($this->users['1']);
        $this->cache->refuseWrites();

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('Token storage failure');

        $auth->revokeAllForUser('1');
    }

    public function testRefusedDeleteDuringRevokeThrows(): void
    {
        $auth = $this->createAuth();
        $pair = $auth->issue($this->users['1']);
        $this->cache->refuseDeletes();

        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('could not be revoked');

        $auth->revoke($pair->refreshToken);
    }

    // --- interface ---

    public function testTheInterfaceCoversTheWholeFlow(): void
    {
        $auth = $this->createAuth();
        self::assertInstanceOf(TokenAuthInterface::class, $auth);

        /** @var TokenAuthInterface $typed */
        $typed = $auth;
        $pair = $typed->issue($this->users['1'], deviceId: 'iphone-15');

        self::assertSame('1', $typed->authenticate($pair->accessToken)?->getId());

        // Rotation hands out a new pair; the access token issued before the rotation keeps
        // working until its own TTL runs out, so a rotation never breaks a request in flight
        $rotated = $typed->refresh($pair->refreshToken);
        self::assertSame('1', $typed->authenticate($pair->accessToken)?->getId());
        self::assertSame('1', $typed->authenticate($rotated->accessToken)?->getId());

        $typed->revoke($rotated->refreshToken);
        self::assertNull($typed->authenticate($pair->accessToken));
        self::assertNull($typed->authenticate($rotated->accessToken));
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

        new TokenAuth(store: $this->cache, userLoader: 42);
    }

    public function testConstructorRejectsNonCallableClock(): void
    {
        $this->expectException(TokenAuthException::class);
        $this->expectExceptionMessage('clock');

        new TokenAuth(
            store: $this->cache,
            userLoader: fn(string $id): ?object => null,
            clock: 42,
        );
    }
}
