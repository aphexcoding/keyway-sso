<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\models\UserGroup;
use craft\services\UserGroups;

/**
 * craft\services\UserGroups answering getGroupByHandle() from an array instead of a connection.
 *
 * Same trick as the other Craft stubs: the empty constructor skips the Yii component's init(),
 * so the real class and the real signature stay and only the database goes away.
 *
 * `null` is a real answer and the default one - it is what Craft returns for a handle that does
 * not exist on the site, which is the administrator-typo path CraftSignIn turns into a note
 * rather than a refusal.
 */
final class StubCraftUserGroups extends UserGroups
{
    /** @var array<string, int> handle => group id */
    private array $groups;

    /** @var list<string> Every handle that was looked up, in order. */
    public array $asked = [];

    /**
     * @param array<string, int> $groups
     */
    public function __construct(array $groups = [])
    {
        // Deliberately does not call parent::__construct(): no application, no database.
        $this->groups = $groups;
    }

    public function getGroupByHandle(string $groupHandle): ?UserGroup
    {
        $this->asked[] = $groupHandle;

        if (!isset($this->groups[$groupHandle])) {
            return null;
        }

        return new UserGroup([
            'id' => $this->groups[$groupHandle],
            'handle' => $groupHandle,
            'name' => $groupHandle,
        ]);
    }
}
