<?php

declare(strict_types=1);

namespace App\Service;

/**
 * Provides user-friendly error messages for authentication failures.
 *
 * This service translates technical authentication error codes into clear,
 * actionable messages that help users understand what went wrong and how
 * to proceed. It supports both sign-in flow errors and general authentication
 * errors with appropriate guidance for each scenario.
 */
final readonly class MessageService
{
    /**
     * Retrieves a user-friendly error message and heading based on an error code
     * and category.
     *
     * @param string|null $errorCode The error code from the authentication flow
     * @param string $category The category of error ('signin-error' or 'auth-error')
     * @return array{heading: string, message: string} Heading and message for display
     */
    public function getMessage(?string $errorCode, string $category): array
    {
        $normalized = strtolower($errorCode ?? 'default');

        return match ($category) {
            'signin-error' => $this->getSigninError($normalized),
            'auth-error' => $this->getAuthError($normalized),
            default => [
                'heading' => 'Unknown Error',
                'message' => 'An unknown error occurred.',
            ],
        };
    }

    /**
     * @return array{heading: string, message: string}
     */
    private function getSigninError(string $code): array
    {
        return match ($code) {
            'signin', 'oauthsignin', 'oauthcallback', 'oauthcreateaccount', 'emailcreateaccount', 'callback' => [
                'heading' => 'Sign-in Failed',
                'message' => 'Try signing in with a different account.',
            ],
            'oauthaccountnotlinked' => [
                'heading' => 'Account Not Linked',
                'message' => 'To confirm your identity, sign in with the same account you used originally.',
            ],
            'emailsignin' => [
                'heading' => 'Email Not Sent',
                'message' => 'The email could not be sent.',
            ],
            'credentialssignin' => [
                'heading' => 'Sign-in Failed',
                'message' => 'Sign in failed. Check the details you provided are correct.',
            ],
            'sessionrequired' => [
                'heading' => 'Sign-in Required',
                'message' => 'Please sign in to access this page.',
            ],
            default => [
                'heading' => 'Unable to Sign in',
                'message' => 'An unexpected error occurred during sign-in. Please try again.',
            ],
        };
    }

    /**
     * @return array{heading: string, message: string}
     */
    private function getAuthError(string $code): array
    {
        return match ($code) {
            'configuration' => [
                'heading' => 'Server Error',
                'message' => 'There is a problem with the server configuration. Check the server logs for more information.',
            ],
            'accessdenied' => [
                'heading' => 'Access Denied',
                'message' => 'You do not have permission to sign in.',
            ],
            'verification' => [
                'heading' => 'Sign-in Link Invalid',
                'message' => 'The sign-in link is no longer valid. It may have been used already or it may have expired.',
            ],
            default => [
                'heading' => 'Authentication Error',
                'message' => 'An unexpected error occurred during authentication. Please try again.',
            ],
        };
    }
}
