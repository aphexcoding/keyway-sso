<?php

declare(strict_types=1);

use Keyway\Sso\Core\Access\ControlPanelAccess;
use Keyway\Sso\Test\Support\Assert;

/**
 * The full truth table of "may this account be dropped into the control panel".
 *
 * This decision used to be three lines inside CraftSignIn, and it was measured that deleting
 * them left the whole suite green - a rule that can lock a client out of their own control
 * panel, guarded by nothing. Every combination of the two permissions against a live and an
 * offline system is enumerated below, including the ones that pass, so that a change to the
 * order of the two checks is a failing test rather than a silently different diagnostics row.
 */
return [
    'no accessCp is refused, and the diagnostics name the permission' => static function (): void {
        Assert::same(
            'accessCp',
            ControlPanelAccess::missingPermission(false, false, true),
            'the returned handle is what the administrator is shown; "true" would say nothing'
        );
    },

    'accessCp alone is enough while the system is live' => static function (): void {
        Assert::null(ControlPanelAccess::missingPermission(true, false, true));
    },

    'accessCp is asked first, so an offline system still reports the bigger problem'
        => static function (): void {
            // Both permissions missing, system offline. Telling somebody they lack
            // accessCpWhenSystemIsOff would send them to fix the smaller of two problems.
            Assert::same('accessCp', ControlPanelAccess::missingPermission(false, false, false));
            Assert::same('accessCp', ControlPanelAccess::missingPermission(false, true, false));
        },

    'accessCp without accessCpWhenSystemIsOff is refused while the system is offline'
        => static function (): void {
            Assert::same(
                'accessCpWhenSystemIsOff',
                ControlPanelAccess::missingPermission(true, false, false)
            );
        },

    'both permissions let the account in while the system is offline' => static function (): void {
        Assert::null(ControlPanelAccess::missingPermission(true, true, false));
    },

    'accessCpWhenSystemIsOff is never asked while the system is live' => static function (): void {
        // Same answer with and without it: the offline permission must not become a second way
        // to be refused on a site that is up.
        Assert::null(ControlPanelAccess::missingPermission(true, false, true));
        Assert::null(ControlPanelAccess::missingPermission(true, true, true));
    },

    'the handles are Craft\'s own spelling' => static function (): void {
        // Craft looks these up case-insensitively for accessCp but stores permissions lowercased
        // (services/UserPermissions.php); the string also reaches the administrator in a
        // diagnostics row, so it is pinned rather than retyped at each call site.
        Assert::same('accessCp', ControlPanelAccess::ACCESS_CP);
        Assert::same('accessCpWhenSystemIsOff', ControlPanelAccess::ACCESS_CP_WHEN_SYSTEM_IS_OFF);
    },
];
