<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftUserSnapshot;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Test\Support\Assert;

/**
 * The two decisions CraftUserDirectory delegates: is this row really the account we asked for,
 * and what is the core told about it.
 *
 * No vendor directory is needed and none is checked for: these rules take scalars, so they are
 * verifiable on a host where `composer install` cannot even run. The adapter that feeds them is
 * covered separately, against real Craft objects, in test/craft_user_directory_test.php.
 */
return [
    // The mapping the port spells out. Every one of these four is a gate in ProvisioningPolicy.
    'Craft statuses map onto the core statuses one to one' => static function (): void {
        Assert::same(AccountStatus::Active, CraftUserSnapshot::status('active'));
        Assert::same(AccountStatus::Pending, CraftUserSnapshot::status('pending'));
        Assert::same(AccountStatus::Suspended, CraftUserSnapshot::status('suspended'));
        Assert::same(AccountStatus::Inactive, CraftUserSnapshot::status('inactive'));
    },

    // User::getStatus() also answers with the element-level states, and a future Craft may add
    // more. "I do not recognise this state" must never come out as "let them in".
    'a status the core does not model fails closed to Inactive' => static function (): void {
        foreach ([null, '', 'archived', 'disabled', 'locked', 'enabled', 'something-new'] as $status) {
            $mapped = CraftUserSnapshot::status($status);

            Assert::same(AccountStatus::Inactive, $mapped, 'status ' . var_export($status, true));
            Assert::false($mapped->allowsSignIn(), 'unknown status does not sign in');
        }
    },

    // The failure the port describes in full: a deactivated account described as Active is how
    // single sign-on reinstates somebody an administrator deprovisioned on purpose.
    'a deactivated account is not signable' => static function (): void {
        $user = CraftUserSnapshot::map(41, 'gone@example.com', 'gone', false, 'inactive', false);

        Assert::same(AccountStatus::Inactive, $user->status);
        Assert::false($user->status->allowsSignIn());
    },

    'every flag is carried verbatim, none is guessed' => static function (): void {
        $user = CraftUserSnapshot::map(7, 'boss@example.com', 'boss', true, 'suspended', true);

        Assert::same('7', $user->id);
        Assert::same('boss@example.com', $user->email);
        Assert::same('boss', $user->username);
        Assert::true($user->isAdmin);
        Assert::true($user->isLocked);
        Assert::true($user->isSuspended());
    },

    // Craft stores the address as typed; the core compares it with a mapped attribute that has
    // been lower-cased. Skipping the normalisation would create a duplicate on every login.
    'the address is normalised the way the core normalises mapped attributes' => static function (): void {
        $user = CraftUserSnapshot::map(3, ' Jan.Kowalski@Example.COM ', 'jan', false, 'active', false);

        Assert::same('jan.kowalski@example.com', $user->email);
    },

    // An install with useEmailAsUsername has no username to speak of; that is allowed, and
    // is not the same thing as a missing id.
    'an account without a username still maps' => static function (): void {
        $user = CraftUserSnapshot::map(9, 'solo@example.com', null, false, 'active', false);

        Assert::same('', $user->username);
        Assert::same(AccountStatus::Active, $user->status);
    },

    'an element with no id is refused rather than described as an account' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn() => CraftUserSnapshot::map(null, 'ghost@example.com', 'ghost', false, 'active', false)
        );
    },

    'an identifier matches its own column, case and padding aside' => static function (): void {
        Assert::true(CraftUserSnapshot::matchesIdentifier('jan@example.com', 'jan@example.com'));
        Assert::true(CraftUserSnapshot::matchesIdentifier('jan@example.com', 'Jan@Example.COM'));
        Assert::true(CraftUserSnapshot::matchesIdentifier(' jan ', "jan\n"));
    },

    // THE security case. getUserByUsernameOrEmail() matches either column, so a lookup by
    // e-mail can come back holding an account that merely uses that address as its username -
    // with somebody else's address in the e-mail column. Believing it would hand the identity
    // provider's user the wrong account.
    'a hit on the other column is reported as no hit' => static function (): void {
        // Asked for the e-mail 'victim@example.com'; the row Craft returned has that string as
        // its username and a different address of its own.
        Assert::false(CraftUserSnapshot::matchesIdentifier('victim@example.com', 'attacker@example.com'));
    },

    'nothing matches an empty identifier or an empty column' => static function (): void {
        Assert::false(CraftUserSnapshot::matchesIdentifier('', ''));
        Assert::false(CraftUserSnapshot::matchesIdentifier('', 'jan'));
        Assert::false(CraftUserSnapshot::matchesIdentifier('jan', ''));
        Assert::false(CraftUserSnapshot::matchesIdentifier('jan', null));
        Assert::false(CraftUserSnapshot::matchesIdentifier('   ', '   '));
    },
];
