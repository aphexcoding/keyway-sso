<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\elements\User;
use ReflectionClass;

/**
 * A real craft\elements\User whose permissions are a list instead of a database.
 *
 * `User::can()` (elements/User.php:1870-1884) returns true for admins, true on the Solo
 * edition, and otherwise asks `Craft::$app->getUserPermissions()`. The first two branches make
 * it useless as a fixture - every account would pass - and the third needs an application. So
 * the method is overridden here and nothing else is: the status, which is what
 * `helpers\User::getAuthStatus()` computes upstream of the control-panel check, is still Craft's
 * own code working off the real flags (see CraftUserFixture for why that matters).
 *
 * Subclassing is safe and deliberate: `craft\elements\User` is not final, `can()` is not final,
 * and every signature in CraftSignIn takes the parent type.
 */
final class PermissionedCraftUser extends User
{
    /** @var list<string> Permission handles this account has. */
    public array $granted = [];

    /** @var list<string> Every handle the code under test asked about, in order. */
    public array $asked = [];

    /** @var list<\craft\models\UserGroup> Groups the account already belongs to. */
    public array $groups = [];

    /**
     * @param list<string> $granted
     * @param array<string, mixed> $properties Public properties of User / ElementTrait.
     */
    public static function with(array $granted, array $properties = []): self
    {
        $user = (new ReflectionClass(self::class))->newInstanceWithoutConstructor();

        // An active, unlocked, non-pending account: the state in which Craft raises no
        // objection of its own, so that anything refused below is refused by OUR gate.
        $defaults = [
            'id' => 41,
            'active' => true,
            'enabled' => true,
            'archived' => false,
            'suspended' => false,
            'pending' => false,
            'locked' => false,
            'passwordResetRequired' => false,
            'email' => 'person@example.test',
        ];

        foreach (array_merge($defaults, $properties) as $name => $value) {
            $user->$name = $value;
        }

        $user->granted = $granted;

        return $user;
    }

    public function can(string $permission): bool
    {
        $this->asked[] = $permission;

        return in_array($permission, $this->granted, true);
    }

    /**
     * The groups this account is already in, as a list instead of a query.
     *
     * Craft's own getGroups() (elements/User.php:1486-1497) reads `Craft::$app->edition` and then
     * goes to `getUserGroups()->getGroupsByUserId()`, neither of which exists outside a booted
     * install - so on the provisioning paths, where CraftSignIn merges the mapped groups with
     * the ones the account already has, the real method cannot run. Empty is the honest default:
     * it is what a just-created account has.
     *
     * @return list<\craft\models\UserGroup>
     */
    public function getGroups(): array
    {
        return $this->groups;
    }
}
