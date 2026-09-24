<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use craft\elements\User;
use craft\services\Users;
use Keyway\Sso\Core\Port\UserDirectoryInterface;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Core\Support\Ascii;

/**
 * UserDirectoryInterface on craft\services\Users. Read-only, as the port requires: the core
 * decides, the Craft layer writes, and nothing here touches an account.
 *
 * WHY Users::getUserByUsernameOrEmail() AND NOT User::find()->email(...). The port demands a
 * case-insensitive lookup, and case-insensitivity is a property of the database, not of Craft:
 * MySQL's collation does it, Postgres does not. Craft's service already carries that fork
 * (vendor/craftcms/cms/src/services/Users.php:278-295 lower-cases both sides on Postgres), and
 * a second copy of it here would be one more thing to keep in step with Craft.
 *
 * The same service call brings two hazards with it, and both are handled by CraftUserSnapshot,
 * where they are testable:
 *
 *  - IT MATCHES EITHER COLUMN. `username` OR `email`, so findByEmail() can come back with an
 *    account that merely uses the address as its username. The column that was asked for is
 *    re-checked before the row is believed.
 *  - IT RETURNS EVERY STATUS. `->status(null)` (Users.php:276), which is exactly what this port
 *    needs - a directory that hid suspended and deactivated accounts would report them as "no
 *    such user" and let just-in-time provisioning recreate them. The status is mapped verbatim
 *    instead.
 *
 * What is left in this class is six lines of delegation, which is the point: everything that
 * could be wrong sits in the pure class next door.
 */
final class CraftUserDirectory implements UserDirectoryInterface
{
    private Users $users;

    public function __construct(Users $users)
    {
        $this->users = $users;
    }

    public function findByEmail(string $email): ?ExistingUser
    {
        return $this->lookup($email, static fn(User $user): ?string => $user->email);
    }

    public function findByUsername(string $username): ?ExistingUser
    {
        return $this->lookup($username, static fn(User $user): ?string => $user->username);
    }

    /**
     * @param callable(User): ?string $column The field the caller actually asked about.
     */
    private function lookup(string $wanted, callable $column): ?ExistingUser
    {
        // An empty identifier would otherwise be handed to the database, where it can match an
        // account whose username column is empty. Nobody signs in as "".
        if (Ascii::trim($wanted) === '') {
            return null;
        }

        $user = $this->users->getUserByUsernameOrEmail($wanted);

        if ($user === null || !CraftUserSnapshot::matchesIdentifier($wanted, $column($user))) {
            return null;
        }

        return CraftUserSnapshot::map(
            $user->id,
            $user->email,
            $user->username,
            $user->admin,
            $user->getStatus(),
            $user->locked
        );
    }
}
