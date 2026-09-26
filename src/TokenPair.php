<?php

declare(strict_types=1);

namespace MiGears\TokenAuth;

/**
 * An issued token pair.
 *
 * Field names in toArray() follow the OAuth 2.0 token response (RFC 6749
 * section 5.1) so the array can be returned to a client as JSON untouched.
 */
final class TokenPair
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken,
        public readonly int $expiresIn,
        public readonly string $tokenType = 'Bearer',
    ) {
    }

    /**
     * Shape the pair as an OAuth 2.0 token response body.
     *
     * @return array{token_type: string, access_token: string, expires_in: int, refresh_token: string}
     */
    public function toArray(): array
    {
        return [
            'token_type' => $this->tokenType,
            'access_token' => $this->accessToken,
            'expires_in' => $this->expiresIn,
            'refresh_token' => $this->refreshToken,
        ];
    }
}
