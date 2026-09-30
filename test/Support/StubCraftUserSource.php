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

    /**
     * Every group write this login caused, in order, as `[userId, groupIds]`.
     *
     * Recorded rather than executed because the real call replaces the whole set: the thing
     * worth asserting is not what it returned but WHETHER IT HAPPENED AT ALL. An edition below
     * Craft Pro must produce no entry here - an empty write on such a site strips the group
     * Craft itself just assigned.
     *
     * @var list<array{0: int, 1: list<int>}>
     */
    public array $groupWrites = [];

    public function __construct()
    {
        // Deliberately does not call parent::__construct(): no application, no database.
    }

    public function getUserById(int $userId): ?User
    {
        $this->asked[] = $userId;

        return $this->user;
    }

    /**
     * @param list<int>|array<int, int> $groupIds
     */
    public function assignUserToGroups(int $userId, array $groupIds): bool
    {
        $this->groupWrites[] = [$userId, array_values(array_map('intval', $groupIds))];

        return true;
    }
}
