<?php

declare(strict_types=1);

use Keyway\Sso\Core\Group\GroupSync;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Test\Support\Assert;

/**
 * The half of group mapping that needs to know what the account already has.
 *
 * GroupMapper says which groups the claims map to; this says what happens to the memberships
 * somebody already had. It is a decision about access, so it is tested here rather than left as
 * a loop inside the Craft adapter, where exercising it would mean booting a CMS.
 */
return [
    'append keeps what the account already had' => static function (): void {
        Assert::sameList(
            ['authors', 'editors'],
            GroupSync::resolve(['editors'], ['authors'], GroupSyncMode::Append)
        );
    },

    'append never produces the same handle twice' => static function (): void {
        // The result is handed to assignUserToGroups(); a duplicate would read as a change on
        // every single login in anything watching group assignments.
        Assert::sameList(
            ['editors', 'authors'],
            GroupSync::resolve(['editors', 'authors'], ['editors'], GroupSyncMode::Append)
        );
    },

    'append with nothing mapped changes nothing' => static function (): void {
        $existing = ['authors', 'editors'];

        Assert::sameList($existing, GroupSync::resolve([], $existing, GroupSyncMode::Append));
        Assert::false(
            GroupSync::changes($existing, GroupSync::resolve([], $existing, GroupSyncMode::Append)),
            'a login that maps to nothing must not rewrite membership in append mode'
        );
    },

    'replace makes the identity provider the only source of truth' => static function (): void {
        Assert::sameList(
            ['editors'],
            GroupSync::resolve(['editors'], ['authors', 'admins'], GroupSyncMode::Replace)
        );
    },

    // Written down as a test rather than as a warning in a docblock: in replace mode a mapping
    // that stops matching (a renamed group at the IdP) empties the account's membership on the
    // next login. That is what "source of truth" means, `denyIfNoGroupMatch` is the guard, and
    // a sync that quietly declined to do it would be a third mode nobody configured.
    'replace with nothing mapped empties the membership' => static function (): void {
        Assert::sameList([], GroupSync::resolve([], ['authors'], GroupSyncMode::Replace));
        Assert::true(GroupSync::changes(['authors'], []));
    },

    'empty handles are dropped rather than written' => static function (): void {
        Assert::sameList(
            ['editors'],
            GroupSync::resolve(['', 'editors'], [''], GroupSyncMode::Append)
        );
    },

    'changes() ignores order, because membership is a set' => static function (): void {
        Assert::false(GroupSync::changes(['a', 'b'], ['b', 'a']));
        Assert::true(GroupSync::changes(['a', 'b'], ['a']));
        Assert::true(GroupSync::changes(['a'], ['a', 'b']));
    },
];
