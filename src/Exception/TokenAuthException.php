<?php

declare(strict_types=1);

namespace MiGears\TokenAuth\Exception;

use MiGears\Security\Exception\SecurityException;

/**
 * Token authentication exception.
 *
 * Extends the shared SecurityException so callers can keep catching security
 * failures with one catch block while still branching on the specific reason.
 */
class TokenAuthException extends SecurityException
{
    /**
     * Create a new exception for an invalid constructor argument.
     */
    public static function invalidConfiguration(string $reason): self
    {
        return new self('Invalid token auth configuration: ' . $reason);
    }

    /**
     * Create a new exception for a user object whose ID cannot be read.
     */
    public static function cannotExtractUserId(): self
    {
        return new self('Cannot extract user ID: object must have a public getId(), ->id, or [\'id\'].');
    }

    /**
     * Create a new exception for a refresh token that is not in the store.
     */
    public static function unknownRefreshToken(): self
    {
        return new self('Refresh token is unknown, revoked, or not a refresh token.');
    }

    /**
     * Create a new exception for an expired refresh token.
     */
    public static function expiredRefreshToken(): self
    {
        return new self('Refresh token has expired.');
    }

    /**
     * Create a new exception for a refresh token replayed inside the reuse grace window.
     */
    public static function refreshTokenAlreadyUsed(): self
    {
        return new self('Refresh token has already been used; the family is kept alive in case this is a client retry.');
    }

    /**
     * Create a new exception for a refresh token replayed after the grace window.
     */
    public static function refreshTokenReuseDetected(): self
    {
        return new self('Refresh token reuse detected; the whole token family has been revoked.');
    }

    /**
     * Create a new exception for a stored record that cannot be interpreted.
     */
    public static function invalidRecord(): self
    {
        return new self('Stored token record is malformed.');
    }
}
