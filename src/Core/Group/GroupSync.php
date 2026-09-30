<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

/**
 * Which groups a user must end up in, given what the mapping produced and what they already had.
 *
 * GroupMapper answers "which groups do the identity provider's claims map to". It deliberately
 * does NOT answer "and what happens to the groups this person was already in", because that
 * needs the current membership, which only the Craft layer can read. This class is the missing
 * half, and it is here - pure, with no Craft in sight - for the same reason ProvisioningDecision
 * is: it is a decision about somebody's access, and a decision about access that can only be
 * exercised by booting a CMS is a decision nobody re-tests.
 *
 * THE TWO MODES, and the hazard in each:
 *
 *  - Append keeps every existing membership and adds the mapped ones. An administrator who adds
 *    somebody to a group by hand keeps that group. The cost is that a group can never be taken
 *    away by the identity provider, which is why it is a choice and not the only behaviour.
 *  - Replace makes the identity provider the source of truth: the user ends up in exactly the
 *    mapped groups and nothing else. The hazard is stated rather than smoothed over - when the
 *    mapping produces nothing (a renamed group at the IdP, a rule that stopped matching), this
 *    mode strips the account of every group it has, on every login. `denyIfNoGroupMatch` in
 *    ProvisioningSettings is the guard for exactly that case, and it belongs there: a sync that
 *    quietly declined to empty the list would be a third mode nobody configured.
 *
 * Order is preserved and duplicates are dropped, because the result is handed to Craft's
 * `assignUserToGroups()`, and a list with the same handle twice is a diff that looks like a
 * change on every login in the diagnostics panel.
 */
final class GroupSync
{
    private function __construct()
    {
    }

    /**
     * @param list<string> $mapped   Group handles the mapping produced.
     * @param list<string> $existing Group handles the account is in right now.
     * @return list<string> Handles the account must be in after this login.
     */
    public static function resolve(array $mapped, array $existing, GroupSyncMode $mode): array
    {
        $wanted = $mode === GroupSyncMode::Replace
            ? $mapped
            : array_merge($existing, $mapped);

        $result = [];

        foreach ($wanted as $handle) {
            $handle = (string)$handle;

            if ($handle === '' || in_array($handle, $result, true)) {
                continue;
            }

            $result[] = $handle;
        }

        return $result;
    }

    /**
     * True when applying `resolve()` would change anything.
     *
     * Used to keep the Craft layer from writing group membership on every single login: a write
     * that changes nothing still touches the database, still fires Craft's group-assignment
     * events, and still shows up in anything watching them.
     *
     * @param list<string> $existing
     * @param list<string> $resolved
     */
    public static function changes(array $existing, array $resolved): bool
    {
        $before = $existing;
        $after = $resolved;
        sort($before);
        sort($after);

        return $before !== $after;
    }
}
