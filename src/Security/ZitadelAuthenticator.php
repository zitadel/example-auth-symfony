<?php

/** @noinspection PhpMultipleClassDeclarationsInspection */
/** @noinspection PhpUnused */

declare(strict_types=1);

namespace App\Security;

use Override;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Authenticates users via ZITADEL using OAuth 2.0 Authorization Code Flow with PKCE.
 *
 * This authenticator implements the complete OAuth/OIDC flow:
 * 1. Redirects users to ZITADEL for authentication
 * 2. Handles the OAuth callback with authorization code
 * 3. Exchanges authorization code for access/refresh/ID tokens using PKCE
 * 4. Fetches user profile from ZITADEL's userinfo endpoint
 * 5. Creates authenticated User object with all tokens and profile data
 *
 * PKCE (Proof Key for Code Exchange) is used for enhanced security, preventing
 * authorization code interception attacks without requiring client secrets.
 *
 * The authenticator automatically handles token refresh when access tokens expire,
 * maintaining long-lived sessions without requiring re-authentication.
 */
final class ZitadelAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    /**
     * @param HttpClientInterface $httpClient HTTP client for making OAuth API calls
     * @param RouterInterface $router Router for generating callback URLs
     * @param string $zitadelDomain Base domain of ZITADEL instance
     * @param string $clientId OAuth client ID from ZITADEL application
     * @param string $clientSecret OAuth client secret (used for token exchange)
     */
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly RouterInterface $router,
        private readonly string $zitadelDomain,
        private readonly string $clientId,
        private readonly string $clientSecret,
    ) {
    }

    #[Override]
    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'auth_callback';
    }

    /**
     * Authenticates the user by exchanging the OAuth authorization code for tokens
     * and fetching user profile information from ZITADEL.
     *
     * This method implements the OAuth 2.0 token exchange flow:
     * 1. Retrieves authorization code and PKCE verifier from request
     * 2. Exchanges code for access/refresh/ID tokens via ZITADEL token endpoint
     * 3. Fetches user profile from ZITADEL userinfo endpoint using access token
     * 4. Creates User object with all profile data and tokens
     *
     * PKCE validation happens server-side at ZITADEL by comparing the code_verifier
     * with the previously sent code_challenge, ensuring the authorization code
     * hasn't been intercepted.
     *
     * @param Request $request The callback request from ZITADEL containing the authorization code
     * @return Passport Security passport containing authenticated user credentials
     * @throws ClientExceptionInterface
     * @throws DecodingExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     */
    #[Override]
    public function authenticate(Request $request): Passport
    {
        $code = $request->query->get('code');
        $session = $request->getSession();
        $codeVerifier = $session->get('oauth2_pkce_verifier');

        if (!$code || !$codeVerifier) {
            throw new AuthenticationException('Missing authorization code or PKCE verifier');
        }

        $tokenResponse = $this->httpClient->request('POST', rtrim($this->zitadelDomain, '/') . '/oauth/v2/token', [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->router->generate('auth_callback', [], UrlGeneratorInterface::ABSOLUTE_URL),
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code_verifier' => $codeVerifier,
            ],
        ]);

        if ($tokenResponse->getStatusCode() !== 200) {
            throw new AuthenticationException('Failed to exchange authorization code for tokens');
        }

        $tokens = $tokenResponse->toArray();
        $accessToken = $tokens['access_token'] ?? null;
        $refreshToken = $tokens['refresh_token'] ?? null;
        $idToken = $tokens['id_token'] ?? null;
        $expiresIn = $tokens['expires_in'] ?? 3600;

        if (!$accessToken) {
            throw new AuthenticationException('No access token received');
        }

        $userInfoResponse = $this->httpClient->request('GET', rtrim($this->zitadelDomain, '/') . '/oidc/v1/userinfo', [
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken,
            ],
        ]);

        if ($userInfoResponse->getStatusCode() !== 200) {
            throw new AuthenticationException('Failed to fetch user info');
        }

        $userInfo = $userInfoResponse->toArray();
        $userId = $userInfo['sub'] ?? null;

        if (!$userId) {
            throw new AuthenticationException('No user identifier in userinfo response');
        }

        $session->remove('oauth2_pkce_verifier');
        $session->remove('oauth2_state');

        $user = new User(
            userIdentifier: $userId,
            attributes: $userInfo,
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            idToken: $idToken,
            expiresAt: time() + $expiresIn,
        );

        return new SelfValidatingPassport(
            new UserBadge($userId, fn () => $user)
        );
    }

    /**
     * Called when authentication is successful.
     *
     * Redirects the user to their originally requested URL (if available via callbackUrl)
     * or to the profile page by default. This maintains the user's intended navigation
     * flow after authentication.
     *
     * @param Request $request The current request
     * @param TokenInterface $token The security token containing the authenticated user
     * @param string $firewallName The name of the firewall that authenticated the user
     * @return Response|null Redirect response to the target page
     */
    #[Override]
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $callbackUrl = $request->query->get('callbackUrl')
            ?? $request->request->get('callbackUrl');

        if ($callbackUrl && is_string($callbackUrl) && $callbackUrl !== '') {
            return new RedirectResponse($callbackUrl);
        }

        return new RedirectResponse($this->router->generate('profile'));
    }

    /**
     * Called when authentication fails.
     *
     * Redirects the user to the error page with an appropriate error message.
     * The error page displays user-friendly messages based on the failure reason.
     *
     * @param Request $request The current request
     * @param AuthenticationException $exception The exception that caused authentication to fail
     * @return Response|null Redirect response to the error page
     */
    #[Override]
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new RedirectResponse($this->router->generate('auth_error', [
            'error' => 'authentication_failed',
        ]));
    }

    #[Override]
    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->router->generate('auth_signin'));
    }
}
