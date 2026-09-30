<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Access;

/**
 * Whether an account that has just been provisioned may be dropped into the control panel.
 *
 * The rule itself is three lines long, and that is exactly why it lives here rather than inside
 * the Craft adapter: a three-line rule buried in a class that needs a database is a rule no test
 * ever asks about. It was measured - with the check deleted from CraftSignIn the whole suite
 * still passed - so the rule is now a value-in, value-out decision with a table of cases below
 * it, and the adapter is left with the part only it can do: reading the two permissions off a
 * craft\elements\User.
 *
 * WHY THIS IS ASKED AT ALL, when Craft has helpers\User::getAuthStatus(). That helper asks
 * `accessCp` only inside its `$request->getIsCpRequest()` branch (helpers/User.php:49-58), and
 * the callback address this plugin tells an administrator to register with the identity provider
 * is an action URL, which is not a control panel request. Measured against the real helper: an
 * active account with NO permissions at all, on a non-CP request, comes back from
 * getAuthStatus() as null - "no objection". Without this decision such an account would be
 * signed in and dropped on the front end with nothing in the diagnostics saying why.
 *
 * WHY `accessCpWhenSystemIsOff` IS A SEPARATE ANSWER, not a second boolean folded into the
 * first: it is the permission that distinguishes "cannot come in at all" from "cannot come in
 * while the site is offline", and an administrator reading the diagnostics row needs to be told
 * which of the two they are looking at. Craft draws the same distinction
 * (AUTH_NO_CP_ACCESS vs AUTH_NO_CP_OFFLINE_ACCESS).
 */
final class ControlPanelAccess
{
    /** Craft's permission handle for "may open the control panel". */
    public const ACCESS_CP = 'accessCp';

    /** Craft's permission handle for "may open it even while the system is offline". */
    public const ACCESS_CP_WHEN_SYSTEM_IS_OFF = 'accessCpWhenSystemIsOff';

    private function __construct()
    {
    }

    /**
     * The permission handle this account is missing, or null when it may come in.
     *
     * Both permissions are passed as plain booleans, read in advance, rather than as something
     * lazy. On Craft that costs nothing: `services\UserPermissions` keeps a per-user-id cache
     * (`$_permissionsByUserId`, services/UserPermissions.php:257-271), so the second read never
     * reaches the database, and for an administrator `User::can()` returns true before it looks
     * anything up at all.
     *
     * @param bool $canAccessCp                Craft's `accessCp` for this account.
     * @param bool $canAccessCpWhenSystemIsOff Craft's `accessCpWhenSystemIsOff`; only consulted
     *                                         when the system is offline.
     * @param bool $systemIsLive               What `Craft::$app->getIsLive()` said, read in
     *                                         Plugin and passed down, never read here.
     */
    public static function missingPermission(
        bool $canAccessCp,
        bool $canAccessCpWhenSystemIsOff,
        bool $systemIsLive
    ): ?string {
        if (!$canAccessCp) {
            return self::ACCESS_CP;
        }

        if (!$systemIsLive && !$canAccessCpWhenSystemIsOff) {
            return self::ACCESS_CP_WHEN_SYSTEM_IS_OFF;
        }

        return null;
    }
}
