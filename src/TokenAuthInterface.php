<?php

declare(strict_types=1);

namespace MiGears\TokenAuth;

use MiGears\TokenAuth\Exception\TokenAuthException;

/**
 * Instruction for the write side of token authentication.
 *
 * The read side (turning a bearer token into a user) is deliberately left to
 * TokenAuth::authenticate(), because a rotation family is a write-side concept:
 * TokenAuthInterface is what a login, refresh, or logout endpoint depends on.
 */
interface TokenAuthInterface
{
    /**
     * Issue a fresh token pair, starting a new rotation family.
     *
     * @param object      $user     User object to issue tokens for
     * @param string|null $deviceId Optional device identifier recorded with the tokens
     */
    public function issue(object $user, ?string $deviceId = null): TokenPair;

    /**
     * Exchange a refresh token for a new pair, rotating the refresh token.
     *
     * @throws TokenAuthException If the token is unknown, expired, or replayed
     */
    public function refresh(string $refreshToken): TokenPair;

    /**
     * Revoke a rotation family through any of its refresh tokens.
     *
     * Revoking an unknown or already revoked token is a no-op, so logout stays idempotent.
     */
    public function revoke(string $refreshToken): void;

    /**
     * Revoke every token of a user, across all devices.
     */
    public function revokeAllForUser(string $userId): void;
}
