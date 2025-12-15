<?php

declare(strict_types=1);

namespace App\Service;

use App\Security\User;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Handles OAuth token refresh and ZITADEL logout URL generation.
 *
 * This service manages the OAuth token lifecycle by refreshing expired access tokens
 * using refresh tokens, and constructs secure logout URLs for terminating sessions
 * both locally and at the ZITADEL identity provider.
 *
 * Token refresh maintains long-lived user sessions without requiring re-authentication.
 * When an access token expires (typically after 1 hour), this service exchanges the
 * refresh token for a new access token, allowing seamless continued access.
 *
 * Logout URL generation includes CSRF protection via state parameters and properly
 * terminates the user's session at ZITADEL before redirecting back to the application.
 */
final readonly class AuthService
{
    /**
     * @param HttpClientInterface $httpClient HTTP client for making OAuth API calls
     * @param string $zitadelDomain Base domain of ZITADEL instance
     * @param string $clientId OAuth client ID from ZITADEL application
     * @param string $clientSecret OAuth client secret for token exchange
     * @param string $postLogoutUrl URL where ZITADEL redirects after logout
     */
    public function __construct(
        private HttpClientInterface $httpClient,
        private string $zitadelDomain,
        private string $clientId,
        private string $clientSecret,
        private string $postLogoutUrl,
    ) {
    }

    /**
     * Refreshes an expired access token using the refresh token.
     *
     * When a user's access token expires (typically after 1 hour), this method
     * seamlessly exchanges the refresh token for a new access token, allowing
     * the user to continue using the application without re-authentication.
     *
     * The refresh token grant type is used to request new tokens from ZITADEL's
     * token endpoint. If successful, a new User object is created with the
     * updated tokens while preserving all other user data.
     *
     * @param User $user The current user with expired access token
     * @return User|null New User object with refreshed tokens, or null if refresh fails
     */
    public function refreshAccessToken(User $user): ?User
    {
        $refreshToken = $user->getRefreshToken();

        if (!$refreshToken) {
            return null;
        }

        try {
            $response = $this->httpClient->request('POST', rtrim($this->zitadelDomain, '/') . '/oauth/v2/token', [
                'body' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $refreshToken,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ],
            ]);

            if ($response->getStatusCode() !== 200) {
                return null;
            }

            $data = $response->toArray();

            return $user->withRefreshedTokens(
                accessToken: $data['access_token'],
                refreshToken: $data['refresh_token'] ?? $refreshToken,
                expiresAt: time() + ($data['expires_in'] ?? 3600),
            );
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Constructs a secure logout URL for ZITADEL with CSRF protection.
     *
     * This method creates a proper logout URL that terminates the user's session
     * both in the application and at ZITADEL. It includes security measures to
     * prevent Cross-Site Request Forgery (CSRF) attacks during the logout process.
     *
     * The logout flow:
     * 1. User clicks "logout" in the application
     * 2. Application calls this method to get the logout URL
     * 3. User is redirected to ZITADEL's end_session endpoint
     * 4. ZITADEL terminates the session and redirects back to the application
     * 5. Application validates the state parameter for security
     *
     * @param string $idToken The user's ID token from their current session
     * @return array{url: string, state: string} Logout URL and state value for validation
     */
    public function buildLogoutUrl(string $idToken): array
    {
        $state = bin2hex(random_bytes(16));
        $params = http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $this->postLogoutUrl,
            'state' => $state,
        ]);

        return [
            'url' => rtrim($this->zitadelDomain, '/') . '/oidc/v1/end_session?' . $params,
            'state' => $state,
        ];
    }
}
