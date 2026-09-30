<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\elements\User;
use craft\services\Users;

/**
 * craft\services\Users with the database taken out and nothing else changed.
 *
 * The empty constructor is the whole trick: `Users` is a Yii component, and skipping its
 * init() is what lets the one method the adapter calls be answered from a field instead of from
 * a connection. Everything else - the signature, the return type, the "either column" contract
 * of getUserByUsernameOrEmail() - stays exactly as Craft declares it, so the adapter is talking
 * to the real class hierarchy.
 *
 * `asked` exists so a test can prove the adapter did NOT go to the database, which is the only
 * way to see the empty-identifier guard from outside.
 */
final class StubCraftUsers extends Users
{
    public ?User $row = null;

    /** @var list<string> */
    public array $asked = [];

    public function __construct()
    {
        // Deliberately does not call parent::__construct(): no application, no database.
    }

    public function getUserByUsernameOrEmail(string $usernameOrEmail): ?User
    {
        $this->asked[] = $usernameOrEmail;

        return $this->row;
    }
}
