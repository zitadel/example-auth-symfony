<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Represents an authenticated user from ZITADEL with their profile information
 * and OAuth tokens.
 *
 * This user object is stored in the Symfony Security token after successful
 * authentication and contains all user data retrieved from ZITADEL's userinfo
 * endpoint, along with the OAuth tokens needed for API calls and session management.
 *
 * The user identifier (sub claim) is used as the primary key for user identification
 * across requests. Additional profile data like email, name, and roles are stored
 * as attributes and can be accessed via getter methods.
 */
final readonly class User implements UserInterface
{
    /**
     * @param string $userIdentifier The unique user identifier from ZITADEL (sub claim)
     * @param array<string, mixed> $attributes All user profile data from ZITADEL
     * @param string $accessToken OAuth access token for making authenticated API calls
     * @param string|null $refreshToken OAuth refresh token for obtaining new access tokens
     * @param string|null $idToken OpenID Connect ID token used for logout
     * @param int $expiresAt Unix timestamp when the access token expires
     * @param array<string> $roles User roles extracted from ZITADEL (defaults to ROLE_USER)
     */
    public function __construct(
        private string $userIdentifier,
        private array $attributes,
        private string $accessToken,
        private ?string $refreshToken,
        private ?string $idToken,
        private int $expiresAt,
        private array $roles = ['ROLE_USER'],
    ) {
    }

    #[\Override]
    public function getUserIdentifier(): string
    {
        return $this->userIdentifier;
    }

    /**
     * @return array<string>
     */
    #[\Override]
    public function getRoles(): array
    {
        return $this->roles;
    }

    #[\Override]
    public function eraseCredentials(): void
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    public function isTokenExpired(): bool
    {
        return time() >= $this->expiresAt;
    }

    /**
     * Creates a new User instance with refreshed token data.
     *
     * @param string $accessToken New access token
     * @param string|null $refreshToken New refresh token (or existing if not provided)
     * @param int $expiresAt New expiration timestamp
     * @return self New User instance with updated tokens
     */
    public function withRefreshedTokens(
        string $accessToken,
        ?string $refreshToken,
        int $expiresAt,
    ): self {
        return new self(
            $this->userIdentifier,
            $this->attributes,
            $accessToken,
            $refreshToken ?? $this->refreshToken,
            $this->idToken,
            $expiresAt,
            $this->roles,
        );
    }
}
