<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Handles the application home page.
 *
 * Displays the main landing page with authentication status and login options.
 * The page content adapts based on whether the user is authenticated or not.
 */
final class HomeController extends AbstractController
{
    public function __construct(
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
    ) {
    }

    /**
     * Displays the home page with authentication status and login options.
     *
     * Retrieves the current authentication state and renders the home page template
     * with appropriate content. Unauthenticated users see the login button, while
     * authenticated users may see personalized content.
     *
     * @param Request $request The current request
     * @return Response Rendered home page
     */
    #[Route('/', name: 'home')]
    public function index(Request $request): Response
    {
        return $this->render('home.html.twig', [
            'isAuthenticated' => $this->getUser() !== null,
            'loginUrl' => $this->generateUrl('auth_signin_provider', ['provider' => 'zitadel']),
            'csrf_token' => $this->csrfTokenManager->getToken('authenticate')->getValue(),
        ]);
    }
}
