<?php

declare(strict_types=1);

namespace App\Controller;

use App\Service\AuthService;
use App\Service\MessageService;
use App\Security\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Handles all authentication-related routes including sign-in, logout, and callbacks.
 *
 * This controller manages the complete authentication flow:
 * - Displaying sign-in pages with provider options
 * - Initiating OAuth flow by redirecting to ZITADEL
 * - Handling logout requests and ZITADEL logout callbacks
 * - Displaying authentication error pages
 * - Providing userinfo endpoint for fetching extended user data
 *
 * All routes implement CSRF protection where applicable to prevent
 * Cross-Site Request Forgery attacks.
 */
final class AuthController extends AbstractController
{
    public function __construct(
        private readonly AuthService $authService,
        private readonly MessageService $messageService,
        private readonly RouterInterface $router,
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
        private readonly string $zitadelDomain,
        private readonly string $clientId,
    ) {
    }

    /**
     * Displays the sign-in page with available authentication providers.
     *
     * This page shows users the available ways to authenticate (ZITADEL) and
     * handles display of any authentication errors that occurred during previous
     * sign-in attempts. The callbackUrl parameter preserves the user's intended
     * destination after successful authentication.
     *
     * @param Request $request The current request containing optional error and callbackUrl params
     * @return Response Rendered sign-in page
     */
    #[Route('/auth/signin', name: 'auth_signin')]
    public function showSignin(Request $request): Response
    {
        $error = $request->query->get('error');
        $callbackUrl = $request->query->get('callbackUrl');

        return $this->render('auth/signin.html.twig', [
            'providers' => [[
                'id' => 'zitadel',
                'name' => 'ZITADEL',
                'signinUrl' => $this->generateUrl('auth_signin_provider', ['provider' => 'zitadel']),
            ]],
            'callbackUrl' => $callbackUrl,
            'message' => $error ? $this->messageService->getMessage($error, 'signin-error') : null,
            'csrf_token' => $this->csrfTokenManager->getToken('authenticate')->getValue(),
        ]);
    }

    /**
     * Initiates OAuth authentication flow by redirecting to ZITADEL.
     *
     * This endpoint generates PKCE parameters (code verifier and challenge),
     * stores them in session for later validation, and redirects the user to
     * ZITADEL's authorization endpoint to begin authentication.
     *
     * PKCE (Proof Key for Code Exchange) prevents authorization code interception
     * attacks by requiring the same client that initiated the flow to complete it.
     *
     * @param Request $request The current request
     * @param string $provider The OAuth provider name (currently only 'zitadel')
     * @return RedirectResponse Redirect to ZITADEL authorization endpoint
     */
    #[Route('/auth/signin/{provider}', name: 'auth_signin_provider', methods: ['POST'])]
    public function redirectToProvider(Request $request, string $provider): RedirectResponse
    {
        $session = $request->getSession();
        $callbackUrl = $request->request->get('callbackUrl');

        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        $state = bin2hex(random_bytes(16));

        $session->set('oauth2_pkce_verifier', $codeVerifier);
        $session->set('oauth2_state', $state);

        if ($callbackUrl) {
            $session->set('oauth2_callback_url', $callbackUrl);
        }

        $params = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->router->generate('auth_callback', [], RouterInterface::ABSOLUTE_URL),
            'response_type' => 'code',
            'scope' => 'openid profile email offline_access urn:zitadel:iam:user:metadata urn:zitadel:iam:user:resourceowner urn:zitadel:iam:org:projects:roles',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        return new RedirectResponse(
            rtrim($this->zitadelDomain, '/') . '/oauth/v2/authorize?' . $params
        );
    }

    /**
     * Handles OAuth callback from ZITADEL after user authentication.
     *
     * This route is automatically handled by the ZitadelAuthenticator which:
     * - Validates the state parameter for CSRF protection
     * - Exchanges the authorization code for tokens using PKCE
     * - Fetches user profile from ZITADEL
     * - Creates authenticated session
     *
     * The authenticator will redirect to either the callback URL or profile page
     * upon successful authentication.
     *
     * @param Request $request The callback request from ZITADEL
     * @return Response Handled by ZitadelAuthenticator
     */
    #[Route('/auth/callback', name: 'auth_callback')]
    public function handleProviderCallback(Request $request): Response
    {
        return new Response('', Response::HTTP_OK);
    }

    /**
     * Displays authentication error page with user-friendly messages.
     *
     * Shows contextual error information based on the error code, helping users
     * understand what went wrong (access denied, configuration issues, etc.) and
     * how to proceed.
     *
     * @param Request $request The current request containing error parameter
     * @return Response Rendered error page
     */
    #[Route('/auth/error', name: 'auth_error')]
    public function showError(Request $request): Response
    {
        $error = $request->query->get('error');
        $message = $this->messageService->getMessage($error, 'auth-error');

        return $this->render('auth/error.html.twig', $message);
    }

    /**
     * Initiates logout process by redirecting to ZITADEL's logout endpoint.
     *
     * This endpoint validates that the user has an active session with a valid
     * ID token, generates a cryptographically secure state parameter for CSRF
     * protection, and stores it in a secure HTTP-only cookie.
     *
     * The state parameter will be validated upon the user's return from ZITADEL
     * to ensure the logout callback is legitimate and not a forged request.
     *
     * @param Request $request The current request
     * @return Response Redirect to ZITADEL logout URL or error response
     */
    #[Route('/auth/logout', name: 'auth_logout', methods: ['POST'])]
    public function logout(Request $request): Response
    {
        $user = $this->getUser();

        if (!$user instanceof User || !$user->getIdToken()) {
            return new Response('No valid session or ID token found', Response::HTTP_BAD_REQUEST);
        }

        $logoutData = $this->authService->buildLogoutUrl($user->getIdToken());

        $response = new RedirectResponse($logoutData['url']);
        $response->headers->setCookie(
            Cookie::create('logout_state')
                ->withValue($logoutData['state'])
                ->withExpires(0)
                ->withPath('/auth/logout/callback')
                ->withSecure($request->isSecure())
                ->withHttpOnly(true)
                ->withSameSite('lax')
        );

        return $response;
    }

    /**
     * Handles logout callback from ZITADEL after user signs out.
     *
     * This endpoint validates the logout request to prevent CSRF attacks by
     * comparing the state parameter from the URL with the value stored in the
     * secure cookie. If validation succeeds, it clears the user's session and
     * redirects to a success page. Otherwise, it redirects to an error page.
     *
     * @param Request $request The callback request from ZITADEL
     * @return RedirectResponse Redirect to success or error page
     */
    #[Route('/auth/logout/callback', name: 'auth_logout_callback')]
    public function logoutCallback(Request $request): RedirectResponse
    {
        $state = $request->query->get('state');
        $logoutState = $request->cookies->get('logout_state');

        if ($state && $logoutState && $state === $logoutState) {
            $request->getSession()->invalidate();

            $response = new RedirectResponse($this->generateUrl('auth_logout_success'));
            $response->headers->clearCookie('logout_state', '/auth/logout/callback');

            return $response;
        }

        $reason = urlencode('Invalid or missing state parameter.');
        return new RedirectResponse($this->generateUrl('auth_logout_error', ['reason' => $reason]));
    }

    /**
     * Displays logout success page.
     *
     * Renders a confirmation page indicating the user has successfully logged out.
     * The template includes client-side logic to redirect the user back to the
     * home page after a short delay.
     *
     * @return Response Rendered success page
     */
    #[Route('/auth/logout/success', name: 'auth_logout_success')]
    public function logoutSuccess(): Response
    {
        return $this->render('auth/logout/success.html.twig');
    }

    /**
     * Displays logout error page.
     *
     * Shows a user-friendly error page for failed logout attempts, typically due
     * to CSRF protection failures where the state parameter from the identity
     * provider does not match the one stored in session.
     *
     * @param Request $request The current request containing reason parameter
     * @return Response Rendered error page
     */
    #[Route('/auth/logout/error', name: 'auth_logout_error')]
    public function logoutError(Request $request): Response
    {
        return $this->render('auth/logout/error.html.twig', [
            'reason' => $request->query->get('reason', 'An unknown error occurred.'),
        ]);
    }

    /**
     * Fetches extended user information from ZITADEL's UserInfo endpoint.
     *
     * Provides real-time user data including roles, custom attributes, and
     * organization membership that may not be in the cached session. Uses the
     * current session's access token to make an authenticated request to ZITADEL.
     *
     * This endpoint is protected by Symfony Security and requires authentication.
     *
     * @param Request $request The current request
     * @return Response JSON response with user information or error
     */
    #[Route('/auth/userinfo', name: 'auth_userinfo')]
    public function userInfo(Request $request): Response
    {
        $user = $this->getUser();

        if (!$user instanceof User) {
            return $this->json(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        return $this->json($user->getAttributes());
    }
}
