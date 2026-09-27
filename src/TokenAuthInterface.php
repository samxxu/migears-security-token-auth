<?php

declare(strict_types=1);

namespace MiGears\SecurityTokenAuth;

use MiGears\SecurityTokenAuth\Exception\TokenAuthException;

/**
 * What a login, refresh, logout, or protected endpoint depends on.
 *
 * Both sides of the flow are here: issuing is issue() / refresh(), and the read
 * side is authenticate(). Middleware can therefore be written against this
 * interface alone, and a test double is a one-class job.
 */
interface TokenAuthInterface
{
    /**
     * Issue a fresh token pair, starting a new rotation family.
     *
     * @param object      $user     User object to issue tokens for
     * @param string|null $deviceId Optional device identifier recorded with the tokens
     *
     * @throws TokenAuthException If the user ID cannot be read or the tokens cannot be stored
     */
    public function issue(object $user, ?string $deviceId = null): TokenPair;

    /**
     * Exchange a refresh token for a new pair, rotating the refresh token.
     *
     * @throws TokenAuthException If the token is unknown, expired, or replayed
     */
    public function refresh(string $refreshToken): TokenPair;

    /**
     * Revoke a rotation family through any token of that family.
     *
     * Revoking an unknown or already revoked token is a no-op, so logout stays idempotent.
     *
     * @throws TokenAuthException If the revocation could not be stored
     */
    public function revoke(string $token): void;

    /**
     * Revoke every token of a user, across all devices.
     *
     * @throws TokenAuthException If the revocation could not be stored
     */
    public function revokeAllForUser(string $userId): void;

    /**
     * Resolve the user behind an access token, or null when it must not be honoured.
     *
     * Unknown, expired, wrong-type, and revoked tokens all answer null, so middleware
     * never branches on exceptions to answer 401. A store failure is different: it
     * raises the store's own exception rather than masquerading as an invalid token.
     *
     * @return object|null The user, or null
     */
    public function authenticate(string $accessToken): ?object;
}
