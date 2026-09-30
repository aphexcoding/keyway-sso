<?php

declare(strict_types=1);

use Keyway\Sso\Core\Group\AdminRule;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Group\GroupRule;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Test\Support\Assert;

return [
    'exact, prefix and suffix rules all match' => static function (): void {
        $mapper = new GroupMapper(new GroupMap([
            GroupRule::exact('Editors', 'editors'),
            GroupRule::prefix('craft-', 'craftUsers'),
            GroupRule::suffix('-support', 'support'),
        ]));

        $result = $mapper->mapGroups(['Editors', 'craft-authors', 'tier1-support', 'Sales']);

        Assert::sameList(['editors', 'craftUsers', 'support'], $result->groups());
        Assert::sameList(['Editors', 'craft-authors', 'tier1-support'], $result->matchedIdpGroups());
        Assert::sameList(['Sales'], $result->unmatchedIdpGroups());
    },

    'matching is case-insensitive by default and strict when asked' => static function (): void {
        $rules = [GroupRule::exact('Editors', 'editors')];

        $loose = (new GroupMapper(new GroupMap($rules)))->mapGroups(['EDITORS']);
        $strict = (new GroupMapper(new GroupMap($rules, [], null, GroupSyncMode::Append, true)))
            ->mapGroups(['EDITORS']);

        Assert::sameList(['editors'], $loose->groups());
        Assert::sameList([], $strict->groups());
        Assert::sameList(['EDITORS'], $strict->unmatchedIdpGroups());
    },

    'one IdP group can feed several Craft groups, without duplicates' => static function (): void {
        $mapper = new GroupMapper(new GroupMap([
            GroupRule::exact('staff', 'editors'),
            GroupRule::prefix('sta', 'editors'),
            GroupRule::suffix('aff', 'reviewers'),
        ]));

        $result = $mapper->mapGroups(['staff']);

        Assert::sameList(['editors', 'reviewers'], $result->groups());
        Assert::sameList(['staff'], $result->matchedIdpGroups());
    },

    'default group applies only when nothing matched' => static function (): void {
        $map = new GroupMap([GroupRule::exact('Editors', 'editors')], [], 'members');
        $mapper = new GroupMapper($map);

        $matched = $mapper->mapGroups(['Editors']);
        $unmatched = $mapper->mapGroups(['Sales']);
        $empty = $mapper->mapGroups([]);

        Assert::sameList(['editors'], $matched->groups());
        Assert::false($matched->usedDefaultGroup());

        Assert::sameList(['members'], $unmatched->groups());
        Assert::true($unmatched->usedDefaultGroup());
        Assert::false($unmatched->hasRuleMatch());

        Assert::sameList(['members'], $empty->groups());
        Assert::true($empty->usedDefaultGroup());
    },

    'without a default an unmatched login produces no groups' => static function (): void {
        $result = (new GroupMapper(new GroupMap([GroupRule::exact('Editors', 'editors')])))
            ->mapGroups(['Sales']);

        Assert::sameList([], $result->groups());
        Assert::false($result->usedDefaultGroup());
        Assert::false($result->hasRuleMatch());
    },

    'sync mode is carried through to the assignment' => static function (): void {
        $append = (new GroupMapper(new GroupMap([GroupRule::exact('a', 'aa')])))->mapGroups(['a']);
        $replace = (new GroupMapper(new GroupMap(
            [GroupRule::exact('a', 'aa')],
            [],
            null,
            GroupSyncMode::Replace
        )))->mapGroups(['a']);

        Assert::same(GroupSyncMode::Append, $append->syncMode());
        Assert::same(GroupSyncMode::Replace, $replace->syncMode());
    },

    'admin is never granted without the escalation switch' => static function (): void {
        $map = new GroupMap(
            [GroupRule::exact('Editors', 'editors')],
            [AdminRule::exact('Craft-Admins')]
        );

        $result = (new GroupMapper($map))->mapGroups(['Craft-Admins']);

        Assert::true($result->adminRuleMatched(), 'the rule itself matches');
        Assert::false($result->grantsAdmin(), 'but escalation is off by default');
        Assert::false($result->revokesAdmin());
    },

    'admin is granted only when a rule matches and escalation is on' => static function (): void {
        $map = new GroupMap(
            [],
            [AdminRule::exact('Craft-Admins')],
            null,
            GroupSyncMode::Append,
            false,
            true
        );
        $mapper = new GroupMapper($map);

        $granted = $mapper->mapGroups(['Craft-Admins', 'Sales']);
        $notGranted = $mapper->mapGroups(['Sales']);

        Assert::true($granted->grantsAdmin());
        Assert::false($notGranted->grantsAdmin());
        Assert::false($notGranted->adminRuleMatched());
    },

    'escalation without any admin rule can never grant admin' => static function (): void {
        $map = new GroupMap([], [], null, GroupSyncMode::Append, false, true);
        $result = (new GroupMapper($map))->mapGroups(['Craft-Admins', 'root', 'Domain Admins']);

        Assert::false($result->grantsAdmin());
        Assert::false($result->adminRuleMatched());
    },

    'a group rule cannot be used as an admin rule' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new GroupMap([], [GroupRule::exact('Craft-Admins', 'admins')])
        );
    },

    'admin is not revoked unless explicitly configured' => static function (): void {
        $withoutRevoke = new GroupMap(
            [],
            [AdminRule::exact('Craft-Admins')],
            null,
            GroupSyncMode::Append,
            false,
            true
        );
        $withRevoke = new GroupMap(
            [],
            [AdminRule::exact('Craft-Admins')],
            null,
            GroupSyncMode::Append,
            false,
            true,
            true
        );

        $a = (new GroupMapper($withoutRevoke))->mapGroups(['Sales']);
        $b = (new GroupMapper($withRevoke))->mapGroups(['Sales']);
        $c = (new GroupMapper($withRevoke))->mapGroups(['Craft-Admins']);

        Assert::false($a->revokesAdmin(), 'default is never to demote');
        Assert::true($b->revokesAdmin());
        Assert::false($c->revokesAdmin(), 'a matching admin keeps admin');
    },

    'revoking admin requires escalation to be enabled' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new GroupMap(
                [],
                [AdminRule::exact('Craft-Admins')],
                null,
                GroupSyncMode::Append,
                false,
                false,
                true
            )
        );
    },

    'empty and too-short match patterns are rejected' => static function (): void {
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::prefix('', 'editors'));
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::prefix('a', 'editors'));
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::suffix('  ', 'editors'));
        Assert::throws(InvalidArgumentException::class, static fn () => AdminRule::prefix('x'));
        Assert::doesNotThrow(static fn () => GroupRule::exact('a', 'editors'));
    },

    'invalid Craft group handles are rejected' => static function (): void {
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::exact('x', '9editors'));
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::exact('x', 'bad handle'));
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new GroupMap([], [], 'bad handle')
        );
    },

    'groups are read from the configured source attributes' => static function (): void {
        $map = new GroupMap(
            [GroupRule::exact('Editors', 'editors')],
            [],
            null,
            GroupSyncMode::Append,
            false,
            false,
            false,
            ['memberOf', 'groups']
        );
        $mapper = new GroupMapper($map);

        $payload = new IdentityPayload('jan', [
            'memberOf' => ['Editors', ' '],
            'groups' => ['Editors', 'Sales'],
            'roles' => ['Ignored'],
        ]);

        Assert::sameList(['Editors', 'Sales'], $mapper->collectIdpGroups($payload));

        $result = $mapper->map($payload);
        Assert::sameList(['editors'], $result->groups());
        Assert::sameList(['Sales'], $result->unmatchedIdpGroups());
    },

    'group source attributes cannot be an empty list' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new GroupMap(
                [],
                [],
                null,
                GroupSyncMode::Append,
                false,
                false,
                false,
                ['  ']
            )
        );
    },

    'blank IdP group names never match a rule' => static function (): void {
        $result = (new GroupMapper(new GroupMap([GroupRule::prefix('cr', 'craftUsers')])))
            ->mapGroups(['', '   ']);

        Assert::sameList([], $result->groups());
        Assert::sameList([], $result->matchedIdpGroups());
    },

    'the assignment serialises for the diagnostics panel' => static function (): void {
        $map = new GroupMap(
            [GroupRule::exact('Editors', 'editors')],
            [AdminRule::exact('Craft-Admins')],
            null,
            GroupSyncMode::Replace,
            false,
            true
        );

        $array = (new GroupMapper($map))->mapGroups(['Editors', 'Craft-Admins'])->toArray();

        Assert::same(['editors'], $array['groups']);
        Assert::same(true, $array['grantsAdmin']);
        Assert::same('replace', $array['syncMode']);
        Assert::same(['Craft-Admins'], $array['unmatched']);
    },

    'an exact rule is exact, not a substring match' => static function (): void {
        $mapper = new GroupMapper(new GroupMap([GroupRule::exact('Editors', 'editors')]));

        foreach (['Editors-Archive', 'Former Editors', 'XEditorsX', 'Edito'] as $group) {
            $result = $mapper->mapGroups([$group]);
            Assert::sameList([], $result->groups(), $group);
        }

        Assert::sameList(['editors'], $mapper->mapGroups(['Editors'])->groups());
    },

    'a prefix rule does not match in the middle of a name' => static function (): void {
        $mapper = new GroupMapper(new GroupMap([GroupRule::prefix('craft-', 'craftUsers')]));

        Assert::sameList([], $mapper->mapGroups(['legacy-craft-authors'])->groups());
        Assert::sameList(['craftUsers'], $mapper->mapGroups(['craft-authors'])->groups());
    },

    'a suffix rule does not match in the middle of a name' => static function (): void {
        $mapper = new GroupMapper(new GroupMap([GroupRule::suffix('-admins', 'siteAdmins')]));

        Assert::sameList([], $mapper->mapGroups(['tier-admins-readonly'])->groups());
        Assert::sameList(['siteAdmins'], $mapper->mapGroups(['tier1-admins'])->groups());
    },

    'an empty exact pattern is rejected even though it passes the length rule' => static function (): void {
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::exact('', 'editors'));
        Assert::throws(InvalidArgumentException::class, static fn () => GroupRule::exact('   ', 'editors'));
        Assert::throws(InvalidArgumentException::class, static fn () => AdminRule::exact(''));
    },

    'an admin rule matches exactly, not by substring' => static function (): void {
        $map = new GroupMap(
            [],
            [AdminRule::exact('Craft-Admins')],
            null,
            GroupSyncMode::Append,
            false,
            true
        );
        $mapper = new GroupMapper($map);

        Assert::false($mapper->mapGroups(['Not-Craft-Admins-Really'])->grantsAdmin());
        Assert::true($mapper->mapGroups(['Craft-Admins'])->grantsAdmin());
    },
];
