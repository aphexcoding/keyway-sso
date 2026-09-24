<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftUserDirectory;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CraftUserFixture;
use Keyway\Sso\Test\Support\StubCraftUsers;

/**
 * CraftUserDirectory against a REAL craft\elements\User and a real craft\services\Users subclass.
 *
 * The previous turn left this class uncovered on the strength of a wrong measurement - `new User()`
 * does fail outside a booted Craft, but newInstanceWithoutConstructor() does not, and the six
 * properties the adapter reads are all public. The gap that excuse left behind was not cosmetic:
 * five separate mutations survived the whole suite, including "every account is active" and "no
 * account is ever locked", which are precisely the two failures UserDirectoryInterface spends a
 * paragraph warning about.
 *
 * The statuses here are not written down as strings; they are produced by User::getStatus() from
 * the flags, so this suite pins Craft's own precedence (suspended before pending before active)
 * rather than our reading of it.
 *
 * Skipped loudly without `vendor/`, like the other Craft-side suites.
 */
if (!class_exists(\craft\elements\User::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_user_directory', 'skipped: vendor absent (run composer install)'));

    return [];
}

/** @return array{0: CraftUserDirectory, 1: StubCraftUsers} */
$build = static function (?array $row = null): array {
    $users = new StubCraftUsers();
    $users->row = $row === null ? null : CraftUserFixture::make($row);

    return [new CraftUserDirectory($users), $users];
};

return [
    // THE case. getUserByUsernameOrEmail() matches `username` OR `email`, so a lookup for the
    // victim's address can come back holding somebody else's account that merely uses that
    // address as its username. Believing it hands the identity provider's user the wrong
    // account - and in this fixture, an admin one.
    'a lookup by e-mail refuses a row that only matched on the username' => static function () use ($build): void {
        [$directory] = $build([
            'id' => 99,
            'email' => 'attacker@evil.example',
            'username' => 'victim@example.com',
            'admin' => true,
            'active' => true,
            'locked' => false,
        ]);

        Assert::null($directory->findByEmail('victim@example.com'));
    },

    // The mirror image, so neither lookup can be wired to the other's column.
    'a lookup by username refuses a row that only matched on the e-mail' => static function () use ($build): void {
        [$directory] = $build([
            'id' => 98,
            'email' => 'boss',
            'username' => 'someone-else',
            'admin' => false,
            'active' => true,
            'locked' => false,
        ]);

        Assert::null($directory->findByUsername('boss'));
    },

    'an honest hit comes back, matched case-insensitively' => static function () use ($build): void {
        [$directory] = $build([
            'id' => 7,
            'email' => 'Jan.Kowalski@Example.com',
            'username' => 'jan',
            'admin' => false,
            'active' => true,
            'locked' => false,
        ]);

        $user = $directory->findByEmail('jan.kowalski@example.com');

        Assert::notNull($user);
        Assert::same('7', $user->id);
        Assert::same('jan.kowalski@example.com', $user->email);
        Assert::same('jan', $user->username);
    },

    'a lookup that found nothing is null' => static function () use ($build): void {
        [$directory] = $build();

        Assert::null($directory->findByEmail('nobody@example.com'));
        Assert::null($directory->findByUsername('nobody'));
    },

    // Craft computes the status from these flags; the adapter must hand it over unchanged. A
    // directory that reports every account as Active is how SSO signs in somebody an
    // administrator deactivated, suspended or never activated.
    'the account status is carried verbatim, whatever Craft computes it to be' => static function () use ($build): void {
        $cases = [
            ['active' => true, 'expected' => AccountStatus::Active],
            ['pending' => true, 'expected' => AccountStatus::Pending],
            ['suspended' => true, 'expected' => AccountStatus::Suspended],
            ['active' => false, 'expected' => AccountStatus::Inactive],
            ['archived' => true, 'expected' => AccountStatus::Inactive],
        ];

        foreach ($cases as $case) {
            $expected = $case['expected'];
            unset($case['expected']);

            [$directory] = $build($case + [
                'id' => 5,
                'email' => 'someone@example.com',
                'username' => 'someone',
                'admin' => false,
                'locked' => false,
            ]);

            $user = $directory->findByEmail('someone@example.com');

            Assert::notNull($user, json_encode($case));
            Assert::same($expected, $user->status, json_encode($case));
        }
    },

    // ProvisioningPolicy refuses a locked account; it has no other source for that fact.
    'the lockout flag is carried verbatim' => static function () use ($build): void {
        foreach ([true, false] as $locked) {
            [$directory] = $build([
                'id' => 5,
                'email' => 'someone@example.com',
                'username' => 'someone',
                'admin' => false,
                'active' => true,
                'locked' => $locked,
            ]);

            $user = $directory->findByEmail('someone@example.com');

            Assert::notNull($user);
            Assert::same($locked, $user->isLocked, 'locked=' . var_export($locked, true));
        }
    },

    // The admin gate: linking an SSO identity to an existing admin account is refused unless
    // the site owner turned it on, and the refusal needs this flag to be true.
    'the admin flag is carried verbatim' => static function () use ($build): void {
        foreach ([true, false] as $admin) {
            [$directory] = $build([
                'id' => 5,
                'email' => 'someone@example.com',
                'username' => 'someone',
                'admin' => $admin,
                'active' => true,
                'locked' => false,
            ]);

            $user = $directory->findByEmail('someone@example.com');

            Assert::notNull($user);
            Assert::same($admin, $user->isAdmin, 'admin=' . var_export($admin, true));
        }
    },

    // An empty identifier must not reach the database, where it can match an account whose
    // username column is empty. Nobody signs in as "".
    'an empty identifier never reaches the database' => static function () use ($build): void {
        [$directory, $users] = $build([
            'id' => 1,
            'email' => '',
            'username' => '',
            'admin' => true,
            'active' => true,
            'locked' => false,
        ]);

        Assert::null($directory->findByEmail(''));
        Assert::null($directory->findByUsername('   '));
        Assert::sameList([], $users->asked, 'no query was issued');
    },
];
