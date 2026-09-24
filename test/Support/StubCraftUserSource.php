<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\elements\User;
use craft\services\Users;

/**
 * craft\services\Users answering getUserById() from a field instead of from a connection.
 *
 * Same trick as StubCraftUsers (which answers the other lookup, for the password-login path):
 * the empty constructor skips the Yii component's init(), so the real class hierarchy and the
 * real signature stay, and only the database goes away. `null` is a real answer here - it is
 * what Craft returns for an account deleted while a login was in flight.
 */
final class StubCraftUserSource extends Users
{
    public ?User $user = null;

    /** @var list<int> */
    public array $asked = [];

    public function __construct()
    {
        // Deliberately does not call parent::__construct(): no application, no database.
    }

    public function getUserById(int $userId): ?User
    {
        $this->asked[] = $userId;

        return $this->user;
    }
}
