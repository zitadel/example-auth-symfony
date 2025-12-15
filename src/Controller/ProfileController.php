<?php

declare(strict_types=1);

namespace App\Controller;

use App\Security\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Handles the user profile page displaying authenticated user information.
 *
 * This controller is protected by Symfony Security and requires authentication.
 * It displays comprehensive user data including profile information, tokens,
 * and session metadata.
 */
final class ProfileController extends AbstractController
{
    public function __construct(
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
    ) {
    }

    /**
     * Displays the user profile page with session information.
     *
     * Renders a comprehensive view of the authenticated user's profile including
     * display name, email, roles, custom attributes, and session metadata such as
     * tokens and expiry times. The profile page demonstrates a successful PKCE
     * authentication flow completion.
     *
     * This route is protected by Symfony Security firewall configuration.
     *
     * @param Request $request The current request
     * @return Response Rendered profile page
     */
    #[Route('/profile', name: 'profile')]
    public function show(Request $request): Response
    {
        $user = $this->getUser();

        if (!$user instanceof User) {
            return $this->redirectToRoute('auth_signin');
        }

        $sessionData = [
            'user' => $user->getAttributes(),
            'accessToken' => $user->getAccessToken(),
            'refreshToken' => $user->getRefreshToken(),
            'idToken' => $user->getIdToken(),
            'expiresAt' => $user->getExpiresAt(),
        ];

        return $this->render('profile.html.twig', [
            'user' => $user,
            'userJson' => json_encode($sessionData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'csrf_token' => $this->csrfTokenManager->getToken('logout')->getValue(),
        ]);
    }
}
