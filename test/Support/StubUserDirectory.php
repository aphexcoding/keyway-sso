<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\UserDirectoryInterface;
use Keyway\Sso\Core\Provisioning\ExistingUser;

/**
 * A user table with two columns and no database.
 *
 * `asked` records what the lookup was called with, which is the only way to see from outside
 * that the flow looked the person up by the column the connection is configured to match on.
 */
final class StubUserDirectory implements UserDirectoryInterface
{
    /** @var array<string, ExistingUser> */
    public array $byEmail = [];

    /** @var array<string, ExistingUser> */
    public array $byUsername = [];

    /** @var list<string> */
    public array $asked = [];

    public function findByEmail(string $email): ?ExistingUser
    {
        $this->asked[] = 'email:' . $email;

        return $this->byEmail[$email] ?? null;
    }

    public function findByUsername(string $username): ?ExistingUser
    {
        $this->asked[] = 'username:' . $username;

        return $this->byUsername[$username] ?? null;
    }
}
