<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftSignIn;
use Keyway\Sso\Adapter\SignInResult;
use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Group\GroupAssignment;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Provisioning\ProvisioningAction;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\PermissionedCraftUser;
use Keyway\Sso\Test\Support\StubCraftApplication;
use Keyway\Sso\Test\Support\StubCraftElements;
use Keyway\Sso\Test\Support\StubCraftSession;
use Keyway\Sso\Test\Support\StubCraftUserGroups;
use Keyway\Sso\Test\Support\StubCraftUserSource;

/**
 * CraftSignIn, run for real, on the paths that end in a refusal before anything is written.
 *
 * The sibling file `craft_signin_contract` pins the Craft signatures this class rests on and
 * says plainly that it covers no behaviour. That gap had a price, and it was measured: replacing
 * the control-panel check with `if (false)` - deleting the only thing that stops an account with
 * no permissions from being signed in - left the suite at 537/537 green.
 *
 * WHAT MAKES THIS RUNNABLE WITHOUT A DATABASE. A decision whose action is SignInOnly never
 * reaches `saveElement()` or `assignUserToGroups()`, which are the only two calls that need a
 * connection. What is left is the lookup (a stubbed craft\services\Users), Craft's own
 * `helpers\User::getAuthStatus()`, the control panel gate, and the session start. So the
 * refusal paths - the ones that decide whether somebody gets in - are exactly the paths that
 * can be exercised here.
 *
 * WHAT THE CREATION PATH NEEDED ON TOP OF THAT, added after it broke in production. A decision
 * whose action is Create does reach `saveElement()`, and `new User()` cannot even be evaluated
 * here (it dies wiring CustomFieldBehavior, on "Unknown component ID: errorHandler"), so for a
 * long time this file said the path was untestable and left it to the acceptance test. The
 * acceptance test then found the bug the hard way, on a live Craft with Okta: a first SSO login
 * on the DEFAULT configuration was refused with "username: Username cannot be blank". Two stubs
 * close that - the element comes from the factory CraftSignIn now accepts, and `saveElement()`
 * from StubCraftElements, which refuses a blank username exactly as that install did. The cases
 * below therefore fail on the code as it was shipped, which is the only reason they are worth
 * the two stubs.
 *
 * WHAT IT STILL DOES NOT COVER, stated so a green line is not mistaken for more than it is:
 * that a row actually lands in the database, group membership, custom field writing, and the
 * rest of Craft's own validation. Those remain the acceptance test on a real Craft install.
 */
if (!class_exists(\craft\elements\User::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_signin', 'skipped: vendor absent (run composer install)'));

    return [];
}

const KEYWAY_TEST_SESSION_DURATION = 3600;

/** A decision that signs an existing account in and writes nothing. */
$signInOnly = static function (): ProvisioningDecision {
    return new ProvisioningDecision(
        ProvisioningAction::SignInOnly,
        ProvisioningDecision::EXISTING_UNCHANGED,
        'The account already matches the identity provider; nothing to write.',
        new MappedAttributes([]),
        new GroupAssignment([], [], [], false, false, false, false, GroupSyncMode::Append),
        UserMatchKey::Email,
        'person@example.test',
        '41'
    );
};

/**
 * Runs one login end to end and hands back what happened.
 *
 * `Elements` and `UserGroups` arrive as constructor-less instances on purpose: on this path the
 * adapter must not touch either, and if it ever did, the uninitialised component would fail
 * loudly. That is an assertion, not a convenience.
 *
 * @param list<string> $granted
 * @return array{0: SignInResult, 1: StubCraftSession, 2: PermissionedCraftUser}
 */
$login = static function (
    array $granted,
    bool $systemIsLive = true,
    bool $sessionAccepts = true
) use ($signInOnly): array {
    $app = StubCraftApplication::install($systemIsLive);

    try {
        $user = PermissionedCraftUser::with($granted);

        $users = new StubCraftUserSource();
        $users->user = $user;

        $session = new StubCraftSession();
        $session->accepts = $sessionAccepts;

        $signIn = new CraftSignIn(
            $session,
            $users,
            (new ReflectionClass(\craft\services\UserGroups::class))->newInstanceWithoutConstructor(),
            (new ReflectionClass(\craft\services\Elements::class))->newInstanceWithoutConstructor(),
            KEYWAY_TEST_SESSION_DURATION,
            $systemIsLive
        );

        return [$signIn->signIn($signInOnly()), $session, $user];
    } finally {
        $app->restore();
    }
};

/** The decision a first-time SSO login produces: no account matched, create one. */
$jitCreate = static function (MappedAttributes $attributes): ProvisioningDecision {
    return new ProvisioningDecision(
        ProvisioningAction::Create,
        ProvisioningDecision::JIT_CREATE,
        'No account matched; a new one will be created from the mapped attributes.',
        $attributes,
        new GroupAssignment([], [], [], false, false, false, false, GroupSyncMode::Append),
        UserMatchKey::Email,
        'person@example.test'
    );
};

/**
 * Runs a just-in-time account creation and hands back what was written.
 *
 * The element is supplied rather than constructed, for the reason in the file docblock, and it
 * is the same fixture the sign-in cases above use - so everything after the save (Craft's own
 * auth status, the control-panel gate, the session) is the real code path, not a shortcut.
 *
 * @return array{0: SignInResult, 1: StubCraftElements, 2: PermissionedCraftUser}
 */
$create = static function (
    MappedAttributes $attributes,
    bool $useEmailAsUsername = false
) use ($jitCreate): array {
    $app = StubCraftApplication::install(true);

    try {
        // No id: Craft hands one out when a brand-new element is saved, and StubCraftElements
        // does the same, so the id in the result is one this login actually caused.
        $user = PermissionedCraftUser::with(['accessCp'], ['id' => null]);

        $elements = new StubCraftElements();
        $elements->useEmailAsUsername = $useEmailAsUsername;

        $signIn = new CraftSignIn(
            new StubCraftSession(),
            new StubCraftUserSource(),
            (new ReflectionClass(\craft\services\UserGroups::class))->newInstanceWithoutConstructor(),
            $elements,
            KEYWAY_TEST_SESSION_DURATION,
            true,
            // Named, because the constructor grew `$craftKeepsUserGroups` between the two: the
            // element seam stays last, and a positional call here would have silently handed a
            // closure to a bool.
            newUser: static fn (): \craft\elements\User => $user
        );

        return [$signIn->signIn($jitCreate($attributes)), $elements, $user];
    } finally {
        $app->restore();
    }
};

/**
 * Runs an UPDATE login whose mapping asks for one Craft group, on an installation whose edition
 * either keeps group memberships or does not.
 *
 * Update rather than SignInOnly because applyGroups() is only reached on a decision that writes,
 * and the group write is the whole subject here.
 *
 * @return array{0: SignInResult, 1: StubCraftUserSource, 2: StubCraftUserGroups}
 */
$loginMappingOneGroup = static function (bool $craftKeepsUserGroups, array $siteGroups): array {
    $app = StubCraftApplication::install(true);

    try {
        $users = new StubCraftUserSource();
        // A username as well as the e-mail: StubCraftElements copies Craft's real "username
        // cannot be blank" rule, and this case is about groups, not about that rule.
        $users->user = PermissionedCraftUser::with(['accessCp'], ['username' => 'person']);

        $groups = new StubCraftUserGroups($siteGroups);

        $signIn = new CraftSignIn(
            new StubCraftSession(),
            $users,
            $groups,
            new StubCraftElements(),
            KEYWAY_TEST_SESSION_DURATION,
            true,
            $craftKeepsUserGroups
        );

        $decision = new ProvisioningDecision(
            ProvisioningAction::Update,
            ProvisioningDecision::UPDATE_ON_LOGIN,
            'The account matched and the mapped values are written on every login.',
            new MappedAttributes([]),
            new GroupAssignment(
                ['editors'],
                ['idp-editors'],
                [],
                false,
                false,
                false,
                false,
                GroupSyncMode::Append
            ),
            UserMatchKey::Email,
            'person@example.test',
            '41'
        );

        return [$signIn->signIn($decision), $users, $groups];
    } finally {
        $app->restore();
    }
};

return [
    // The case the mutation test exists for. Everything else in this file is context.
    'an account without accessCp is refused AND never gets a session' => static function () use ($login): void {
        [$result, $session] = $login([]);

        Assert::false($result->ok);
        Assert::same(SignInResult::NO_CP_ACCESS, $result->reasonCode);
        Assert::contains('accessCp', $result->message, 'the administrator is told which permission');
        Assert::sameList(
            [],
            $session->logins,
            'the gate is worthless unless it runs BEFORE login(); a refusal that still starts a '
            . 'session is the bug this asserts against'
        );
        Assert::same(0, $session->returnUrlRemovals);
        Assert::null($result->userId);
    },

    // Why the gate is not belt and braces. Craft's own pre-login check, asked about the very
    // same account under the very same request, raises no objection at all.
    'Craft itself would have let the permissionless account in' => static function () use ($login): void {
        $app = StubCraftApplication::install(true);

        try {
            $user = PermissionedCraftUser::with([]);

            Assert::same('active', $user->getStatus(), 'Craft computes this, we do not set it');
            Assert::null(
                \craft\helpers\User::getAuthStatus($user),
                'on a non-control-panel request getAuthStatus() never asks about accessCp, which '
                . 'is the entire reason CraftSignIn asks itself'
            );
        } finally {
            $app->restore();
        }
    },

    'an account with accessCp is signed in, once, for the configured duration'
        => static function () use ($login): void {
            [$result, $session, $user] = $login(['accessCp']);

            Assert::true($result->ok, $result->message);
            Assert::same(SignInResult::SIGNED_IN, $result->reasonCode);
            Assert::same(41, $result->userId);
            Assert::same('/cp/dashboard', $result->returnUrl);
            Assert::same(1, count($session->logins), 'exactly one session start');
            Assert::same($user, $session->logins[0][0], 'the account that was resolved, not another');
            Assert::same(KEYWAY_TEST_SESSION_DURATION, $session->logins[0][1]);
            Assert::same(1, $session->returnUrlRemovals, 'the stored return URL is consumed');
        },

    'an offline system refuses an account that lacks accessCpWhenSystemIsOff'
        => static function () use ($login): void {
            // accessSiteWhenSystemIsOff is granted so that Craft's own offline check passes and
            // the refusal below is unambiguously ours.
            [$result, $session] = $login(['accessCp', 'accessSiteWhenSystemIsOff'], false);

            Assert::false($result->ok);
            Assert::same(SignInResult::NO_CP_ACCESS, $result->reasonCode);
            Assert::contains('accessCpWhenSystemIsOff', $result->message);
            Assert::sameList([], $session->logins);
        },

    'an offline system admits an account that has the offline permission'
        => static function () use ($login): void {
            [$result, $session] = $login(
                ['accessCp', 'accessCpWhenSystemIsOff', 'accessSiteWhenSystemIsOff'],
                false
            );

            Assert::true($result->ok, $result->message);
            Assert::same(1, count($session->logins));
        },

    'a session Craft refuses to start is reported as such, not as a successful login'
        => static function () use ($login): void {
            [$result, $session] = $login(['accessCp'], true, false);

            Assert::false($result->ok);
            Assert::same(SignInResult::SESSION_NOT_STARTED, $result->reasonCode);
            Assert::same(1, count($session->logins), 'it was attempted, and it was attempted once');
            Assert::same(0, $session->returnUrlRemovals);
        },

    'an account that vanished between the decision and the sign-in is refused'
        => static function () use ($signInOnly): void {
            // The stubbed lookup returns null, which is what Craft returns for an account
            // deleted while the login was in flight.
            $app = StubCraftApplication::install(true);

            try {
                $session = new StubCraftSession();
                $signIn = new CraftSignIn(
                    $session,
                    new StubCraftUserSource(),
                    (new ReflectionClass(\craft\services\UserGroups::class))->newInstanceWithoutConstructor(),
                    (new ReflectionClass(\craft\services\Elements::class))->newInstanceWithoutConstructor(),
                    KEYWAY_TEST_SESSION_DURATION
                );

                $result = $signIn->signIn($signInOnly());

                Assert::same(SignInResult::ACCOUNT_VANISHED, $result->reasonCode);
                Assert::sameList([], $session->logins);
            } finally {
                $app->restore();
            }
        },

    // ------------------------------------------------------------------------------------
    // JUST-IN-TIME CREATION. Measured on a live Craft 5 + Okta, 2026-09-15: the first case
    // below is the login that failed there, in the state it failed in.
    // ------------------------------------------------------------------------------------

    'a first login carrying only an e-mail address is created with the address as its username'
        => static function () use ($create): void {
            // An Okta profile mapping out of the box: an address, no username.
            [$result, $elements, $user] = $create(
                new MappedAttributes(['email' => 'jan@example.com'])
            );

            Assert::true(
                $result->ok,
                'this is the login that was refused in production with "Username cannot be '
                . 'blank"; the message here is: ' . $result->message
            );
            Assert::same(SignInResult::SIGNED_IN, $result->reasonCode);
            Assert::same(1, count($elements->saved), 'the account was saved, once');
            Assert::same($user, $elements->saved[0], 'the element handed to Craft is the account');
            Assert::same(
                'jan@example.com',
                $user->username,
                'Craft accepts an address as a username, and an account with no username at all '
                . 'cannot be saved on the default configuration'
            );
            Assert::same('jan@example.com', $user->email, 'the address is still the address');
            Assert::true($user->active, 'no activation e-mail: the IdP already vouched for them');
            Assert::same(StubCraftElements::ASSIGNED_ID, $result->userId);
        },

    'a username from the assertion is written as sent, not replaced by the address'
        => static function () use ($create): void {
            [$result, , $user] = $create(new MappedAttributes([
                'username' => 'jkowalski',
                'email' => 'jan@example.com',
            ]));

            Assert::true($result->ok, $result->message);
            Assert::same(
                'jkowalski',
                $user->username,
                'the fallback may only fill a username in, never overwrite a mapped one'
            );
            Assert::same('jan@example.com', $user->email);
        },

    'a mapping with neither a username nor an address is refused, not given an invented name'
        => static function () use ($create): void {
            // The provisioning policy denies an e-mail-less creation upstream, so this is the
            // defensive case - and it pins the decision that a blank identity is Craft's refusal
            // to report, not something this layer papers over with a made-up name.
            [$result, $elements, $user] = $create(new MappedAttributes([]));

            Assert::false($result->ok);
            Assert::same(SignInResult::USER_NOT_SAVED, $result->reasonCode);
            Assert::contains('Username cannot be blank', $result->message);
            Assert::same(1, count($elements->saved), 'Craft was asked, and Craft said no');
            Assert::null($user->username, 'nothing was invented to get past the validator');
            Assert::null($result->userId);
        },

    'an install that uses the address as the username keeps working, on Craft\'s terms'
        => static function () use ($create): void {
            // `useEmailAsUsername = true` is the configuration the administrator switched on by
            // hand to work around the bug. What this pins is that it must not become a
            // REQUIREMENT - the login still succeeds and the fallback does not fight Craft.
            //
            // And the column holds the address even though a username WAS mapped, which is not
            // our doing and must not be read as a bug in the fallback: User::beforeSave()
            // (elements/User.php:2579-2581) assigns `$this->username = $this->email`
            // unconditionally on such an install, before validation. Asserting 'jkowalski' here
            // would pass only against a stub that lied about Craft.
            [$result, , $user] = $create(
                new MappedAttributes(['username' => 'jkowalski', 'email' => 'jan@example.com']),
                true
            );

            Assert::true($result->ok, $result->message);
            Assert::same(
                'jan@example.com',
                $user->username,
                'on this install the column is Craft\'s decision, not the mapping\'s'
            );
        },
    // WHAT THIS GUARDS IS A DESTRUCTIVE NO-OP, not a missing feature. Below Craft Pro the CMS
    // answers `getGroups()` with `[]` whatever the account is really in, and no handle resolves,
    // so the straightforward code path hands `assignUserToGroups()` an EMPTY set - a call that
    // replaces the whole set and would therefore strip the built-in group Craft assigns while
    // saving the account, on every login. Without the guard this case records one write of `[]`.
    'below Craft Pro a mapped group is reported, and membership is not touched' => static function () use ($loginMappingOneGroup): void {
        [$result, $users, $groups] = $loginMappingOneGroup(false, []);

        Assert::true($result->ok, 'the login still succeeds - this degrades one feature, not sign-in');
        Assert::sameList([], $users->groupWrites, 'no group write at all, not even an empty one');
        Assert::sameList([], $groups->asked, 'and no lookup either: there is nothing to look up');

        $notes = implode(' | ', $result->notes());
        Assert::contains('editors', $notes, 'the handle that was asked for is named');
        Assert::contains('Craft Pro', $notes, 'and so is what it would take to honour it');
    },

    // The control that makes the case above mean something: same decision, same stubs, only the
    // edition fact flipped. If the guard ever widened to "never write groups", this goes red.
    'on an edition that keeps groups the same decision writes the membership' => static function () use ($loginMappingOneGroup): void {
        [$result, $users, $groups] = $loginMappingOneGroup(true, ['editors' => 9]);

        Assert::true($result->ok);
        Assert::sameList(['editors'], $groups->asked);
        Assert::same(1, count($users->groupWrites), 'exactly one write');
        Assert::sameList([9], $users->groupWrites[0][1]);
        Assert::sameList([], $result->notes(), 'nothing to explain when it simply worked');
    },
];
