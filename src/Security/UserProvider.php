<?php

declare(strict_types=1);

namespace App\Security;

use Override;
use RuntimeException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * @implements UserProviderInterface<User>
 */
final class UserProvider implements UserProviderInterface
{
    #[Override]
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException();
        }
        return $user;
    }

    #[Override]
    public function supportsClass(string $class): bool
    {
        return User::class === $class || is_subclass_of($class, User::class);
    }

    #[Override]
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new RuntimeException('User loading not supported - users come from OAuth flow');
    }
}
