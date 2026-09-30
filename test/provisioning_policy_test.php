<?php

declare(strict_types=1);

use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Attribute\UserField;
use Keyway\Sso\Core\Group\AdminRule;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Group\GroupRule;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Core\Provisioning\ProvisioningAction;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;
use Keyway\Sso\Core\Provisioning\ProvisioningPolicy;
use Keyway\Sso\Core\Provisioning\ProvisioningSettings;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Test\Support\Assert;

$attributes = static fn (array $values): MappedAttributes => new MappedAttributes($values);

$groupsFor = static function (array $idpGroups, array $rules = []): object {
    $map = new GroupMap($rules === [] ? [GroupRule::exact('Editors', 'editors')] : $rules);

    return (new GroupMapper($map))->mapGroups($idpGroups);
};

/**
 * The same mapping WITH an admin rule and escalation switched on - i.e. the configuration in
 * which this plugin is the thing that makes somebody an administrator. Step 4b now distinguishes
 * that from an account a human promoted in the control panel, so the two helpers are not
 * interchangeable.
 */
$adminGranting = static function (array $idpGroups): object {
    $map = new GroupMap(
        [GroupRule::exact('Editors', 'editors')],
        [AdminRule::exact('Admins')],
        null,
        GroupSyncMode::Append,
        false,
        true
    );

    return (new GroupMapper($map))->mapGroups($idpGroups);
};

return [
    'a new identity is created when JIT is on' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(new ProvisioningSettings());

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            null
        );

        Assert::same(ProvisioningAction::Create, $decision->action);
        Assert::same(ProvisioningDecision::JIT_CREATE, $decision->reasonCode);
        Assert::true($decision->writesUser());
        Assert::same('jan@example.com', $decision->matchValue);
    },

    'JIT off means an unknown identity is refused, not created' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(new ProvisioningSettings(false));

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            null
        );

        Assert::same(ProvisioningAction::Deny, $decision->action);
        Assert::same(ProvisioningDecision::JIT_DISABLED, $decision->reasonCode);
        Assert::false($decision->writesUser());
        Assert::false($decision->isAllowed());
    },

    'an existing account is updated when sync on login is on' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, linkExistingAccounts: true)
        );
        $user = new ExistingUser('42', 'jan@example.com', 'jkowalski', false, AccountStatus::Active, false);

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            $user
        );

        Assert::same(ProvisioningAction::Update, $decision->action);
        Assert::same('42', $decision->userId);
        Assert::true($decision->writesUser());
    },

    'an existing account is left alone when sync on login is off' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, false, linkExistingAccounts: true)
        );
        $user = new ExistingUser('42', 'jan@example.com', '', false, AccountStatus::Active, false);

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            $user
        );

        Assert::same(ProvisioningAction::SignInOnly, $decision->action);
        Assert::same(ProvisioningDecision::EXISTING_UNCHANGED, $decision->reasonCode);
        Assert::false($decision->writesUser());
        Assert::true($decision->isAllowed());
    },

    'a suspended account is not signed in by SSO' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(linkExistingAccounts: true)
        );
        $user = new ExistingUser('42', 'jan@example.com', 'jkowalski', false, AccountStatus::Suspended, false);

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            $user
        );

        Assert::same(ProvisioningAction::Deny, $decision->action);
        Assert::same(ProvisioningDecision::ACCOUNT_SUSPENDED, $decision->reasonCode);
        Assert::same('42', $decision->userId);
    },

    'the domain allow list blocks an outside address' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, false, UserMatchKey::Email, ['example.com'])
        );

        $inside = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            null
        );
        $outside = $policy->decide(
            $attributes([UserField::EMAIL => 'attacker@evil.com']),
            $groupsFor(['Editors']),
            null
        );

        Assert::same(ProvisioningAction::Create, $inside->action);
        Assert::same(ProvisioningAction::Deny, $outside->action);
        Assert::same(ProvisioningDecision::DOMAIN_NOT_ALLOWED, $outside->reasonCode);
    },

    'a domain-restricted connection refuses an identity with no address at all' =>
        static function () use ($attributes, $groupsFor): void {
            // The branch the mutation probe found uncovered: with an allow list configured, a
            // missing e-mail must be a denial, not a fall-through to "no restriction applies".
            $policy = new ProvisioningPolicy(new ProvisioningSettings(
                true,
                true,
                false,
                UserMatchKey::Username,
                ['example.com']
            ));

            $decision = $policy->decide(
                $attributes([UserField::USERNAME => 'jkowalski']),
                $groupsFor(['Editors']),
                null
            );

            Assert::same(ProvisioningAction::Deny, $decision->action);
            Assert::same(ProvisioningDecision::EMAIL_MISSING, $decision->reasonCode);
            Assert::contains('configured domains', $decision->message);
            Assert::false($decision->writesUser());
        },

    'the allow list is not a suffix match' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, false, UserMatchKey::Email, ['example.com'])
        );

        foreach (['jan@notexample.com', 'jan@example.com.evil.com', 'jan@sub.example.com'] as $email) {
            $decision = $policy->decide($attributes([UserField::EMAIL => $email]), $groupsFor([]), null);
            Assert::same(ProvisioningAction::Deny, $decision->action, $email);
        }
    },

    'a dotted allow list entry matches sub-domains only' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, false, UserMatchKey::Email, ['*.example.com'])
        );

        $sub = $policy->decide($attributes([UserField::EMAIL => 'jan@eu.example.com']), $groupsFor([]), null);
        $apex = $policy->decide($attributes([UserField::EMAIL => 'jan@example.com']), $groupsFor([]), null);
        $fake = $policy->decide($attributes([UserField::EMAIL => 'jan@notexample.com']), $groupsFor([]), null);

        Assert::same(ProvisioningAction::Create, $sub->action);
        Assert::same(ProvisioningAction::Deny, $apex->action);
        Assert::same(ProvisioningAction::Deny, $fake->action);
    },

    'domain entries are normalised, case and @ included' => static function (): void {
        $settings = new ProvisioningSettings(
            true,
            true,
            false,
            UserMatchKey::Email,
            ['@Example.COM', 'example.com', ' ']
        );

        Assert::sameList(['example.com'], $settings->allowedDomains());
        Assert::true($settings->allowsDomain('EXAMPLE.com'));
        Assert::false($settings->allowsDomain(null));
        Assert::false($settings->allowsDomain(''));
    },

    'no allow list means any domain passes' => static function (): void {
        $settings = new ProvisioningSettings();

        Assert::false($settings->restrictsDomains());
        Assert::true($settings->allowsDomain('whatever.example'));
        Assert::true($settings->allowsDomain(null));
    },

    'the domain check runs before the account lookup' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(new ProvisioningSettings(
            true,
            true,
            false,
            UserMatchKey::Email,
            ['example.com'],
            linkExistingAccounts: true
        ));
        $user = new ExistingUser('42', 'attacker@evil.com', '', false, AccountStatus::Active, false);

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'attacker@evil.com']),
            $groupsFor(['Editors']),
            $user
        );

        Assert::same(ProvisioningAction::Deny, $decision->action);
        Assert::same(ProvisioningDecision::DOMAIN_NOT_ALLOWED, $decision->reasonCode);
    },

    'requiring a group match refuses a login with no matching group' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(new ProvisioningSettings(true, true, true));

        $matched = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            null
        );
        $unmatched = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Sales']),
            null
        );

        Assert::same(ProvisioningAction::Create, $matched->action);
        Assert::same(ProvisioningAction::Deny, $unmatched->action);
        Assert::same(ProvisioningDecision::NO_GROUP_MATCH, $unmatched->reasonCode);
    },

    'a default group does not satisfy the group requirement' => static function () use ($attributes): void {
        $map = new GroupMap([GroupRule::exact('Editors', 'editors')], [], 'members');
        $assignment = (new GroupMapper($map))->mapGroups(['Sales']);
        $policy = new ProvisioningPolicy(new ProvisioningSettings(true, true, true));

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $assignment,
            null
        );

        Assert::true($assignment->usedDefaultGroup());
        Assert::same(ProvisioningAction::Deny, $decision->action);
        Assert::same(ProvisioningDecision::NO_GROUP_MATCH, $decision->reasonCode);
    },

    'matching by username uses the username, not the address' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, false, UserMatchKey::Username)
        );
        $mapped = $attributes([
            UserField::EMAIL => 'jan@example.com',
            UserField::USERNAME => 'jkowalski',
        ]);

        Assert::same('jkowalski', $policy->lookupKeyFor($mapped));

        $decision = $policy->decide($mapped, $groupsFor(['Editors']), null);
        Assert::same('jkowalski', $decision->matchValue);
        Assert::same(UserMatchKey::Username, $decision->matchBy);
    },

    'matching by username fails cleanly when the IdP sends none' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, false, UserMatchKey::Username)
        );

        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com']),
            $groupsFor(['Editors']),
            null
        );

        Assert::same(ProvisioningAction::Deny, $decision->action);
        Assert::same(ProvisioningDecision::USERNAME_MISSING, $decision->reasonCode);
        Assert::null($decision->matchValue);
    },

    'creating an account without an address is refused' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(
            new ProvisioningSettings(true, true, false, UserMatchKey::Username)
        );

        $decision = $policy->decide(
            $attributes([UserField::USERNAME => 'jkowalski']),
            $groupsFor(['Editors']),
            null
        );

        Assert::same(ProvisioningAction::Deny, $decision->action);
        Assert::same(ProvisioningDecision::EMAIL_MISSING, $decision->reasonCode);
    },

    'a blank match value is treated as missing' => static function () use ($attributes): void {
        $policy = new ProvisioningPolicy(new ProvisioningSettings());

        Assert::null($policy->lookupKeyFor($attributes([UserField::EMAIL => '   '])));
        Assert::null($policy->lookupKeyFor($attributes([])));
    },

    'signing in to an account we did not create needs an explicit yes' =>
        static function () use ($attributes, $groupsFor): void {
            $user = new ExistingUser('42', 'jan@example.com', 'jkowalski', false, AccountStatus::Active, false);

            $closed = (new ProvisioningPolicy(new ProvisioningSettings()))->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                $user
            );

            Assert::same(ProvisioningAction::Deny, $closed->action, 'default must be fail-closed');
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $closed->reasonCode);
            Assert::false($closed->writesUser(), 'a refused link never writes');
            Assert::same('42', $closed->userId);

            $opened = (new ProvisioningPolicy(
                new ProvisioningSettings(linkExistingAccounts: true)
            ))->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                $user
            );

            Assert::same(ProvisioningAction::Update, $opened->action);
        },

    // ------------------------------------------------------------------------------------
    // The account this plugin created itself. Measured against a live Craft with Okta: on stock
    // settings the SECOND login of the same person was refused, because nothing recorded that
    // the FIRST one had created the account.
    // ------------------------------------------------------------------------------------

    'an account this connection created signs in again with linking off' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings());
            $jitAccount = new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Active, false);

            $second = $policy->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                $jitAccount,
                true
            );

            Assert::same(ProvisioningAction::Update, $second->action, 'the second login must work');
            Assert::same(ProvisioningDecision::UPDATE_ON_LOGIN, $second->reasonCode);
            Assert::same('42', $second->userId);

            // And with sync off it is a plain sign-in, still not a refusal.
            $noSync = (new ProvisioningPolicy(new ProvisioningSettings(true, false)))->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                $jitAccount,
                true
            );

            Assert::same(ProvisioningAction::SignInOnly, $noSync->action);
        },

    // THE REGRESSION TEST FOR THE TAKEOVER GUARD. If somebody ever widens step 4a, this is the
    // case that has to go red: an account created by a human in the control panel is not ours,
    // and no amount of link bookkeeping may let an identity provider into it.
    'an account created in the control panel is still refused with linking off' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings());

            $decision = $policy->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Active, false),
                false
            );

            Assert::same(ProvisioningAction::Deny, $decision->action);
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $decision->reasonCode);
            Assert::false($decision->writesUser(), 'a refused link never writes');
            // The message used to claim knowledge the code did not have. What it reports now is
            // the absence of a record, which is also true when the link store cannot be read.
            Assert::contains('no record of having created it', $decision->message);
        },

    'the linked flag is the default and the default is closed' =>
        static function () use ($attributes, $groupsFor): void {
            // Three arguments, as every caller wrote it before the fix: the account must stay
            // refused, never linked by omission.
            $decision = (new ProvisioningPolicy(new ProvisioningSettings()))->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Active, false)
            );

            Assert::same(ProvisioningAction::Deny, $decision->action);
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $decision->reasonCode);
        },

    'an administrator provisioned by this plugin is not locked out of its second login' =>
        static function () use ($attributes, $adminGranting, $groupsFor): void {
            // 4b defends administrators Craft already had. It has nothing to defend when the
            // account was created here AND THIS RESPONSE grants admin through the site owner's
            // own AdminRule - the same rule that made the account an admin in the first place
            // fires on every login that person makes. Without that, this is the 4a bug one step
            // down: the just-in-time administrator is refused from their second login onwards.
            $policy = new ProvisioningPolicy(new ProvisioningSettings());
            $mapped = $attributes([UserField::EMAIL => 'owner@example.com']);
            $ourAdmin = new ExistingUser('1', 'owner@example.com', 'owner', true, AccountStatus::Active, false);

            Assert::same(
                ProvisioningAction::Update,
                $policy->decide($mapped, $adminGranting(['Admins']), $ourAdmin, true)->action
            );

            // An administrator account we did NOT create is refused exactly as before - and by
            // 4a, because linking is off here at all.
            $theirAdmin = $policy->decide($mapped, $adminGranting(['Admins']), $ourAdmin, false);

            Assert::same(ProvisioningAction::Deny, $theirAdmin->action);
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $theirAdmin->reasonCode);

            // And with linking on but the admin switch off, an unlinked administrator still
            // stops at 4b.
            $linkingOnly = (new ProvisioningPolicy(
                new ProvisioningSettings(linkExistingAccounts: true)
            ))->decide($mapped, $adminGranting(['Admins']), $ourAdmin, false);

            Assert::same(ProvisioningDecision::ADMIN_LINK_NOT_ALLOWED, $linkingOnly->reasonCode);
        },

    // THE REGRESSION TEST FOR STEP 4b. Measured on these very classes: an account created by
    // this plugin and then promoted BY HAND in the control panel was linked and updated on the
    // next login, with `linkAdminAccounts` off - a switch the owner cannot even turn on on its
    // own, because ProvisioningSettings forces it to false while linking is off. The link says
    // where the account came from; it says nothing about who made it an administrator.
    'an administrator promoted in the control panel is refused even with a link' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings());
            $promotedByHand = new ExistingUser(
                '1',
                'owner@example.com',
                'owner',
                true,
                AccountStatus::Active,
                false
            );

            // The response carries no admin rule match at all - this person's `admin` flag did
            // not come from single sign-on.
            $groups = $groupsFor(['Editors']);
            Assert::false($groups->grantsAdmin(), 'the premise: this response does not grant admin');

            $decision = $policy->decide(
                $attributes([UserField::EMAIL => 'owner@example.com']),
                $groups,
                $promotedByHand,
                true
            );

            Assert::same(
                ProvisioningDecision::ADMIN_LINK_NOT_ALLOWED,
                $decision->reasonCode,
                'a link says where the account came from, not who made it an administrator'
            );
            Assert::same(ProvisioningAction::Deny, $decision->action, 'the login must not be allowed');
            Assert::false($decision->writesUser(), 'a refused link never writes');
        },

    'a link does not lift a suspension, a deactivation or a lockout' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings());
            $mapped = $attributes([UserField::EMAIL => 'jan@example.com']);

            foreach ([
                ProvisioningDecision::ACCOUNT_SUSPENDED
                    => new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Suspended, false),
                ProvisioningDecision::ACCOUNT_INACTIVE
                    => new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Inactive, false),
                ProvisioningDecision::ACCOUNT_LOCKED
                    => new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Active, true),
            ] as $expected => $user) {
                $decision = $policy->decide($mapped, $groupsFor(['Editors']), $user, true);

                Assert::same(ProvisioningAction::Deny, $decision->action, $expected);
                Assert::same($expected, $decision->reasonCode, 'a link is not a reinstatement');
                Assert::same(
                    ProvisioningDecision::PUBLIC_DENIED_MESSAGE,
                    $decision->publicMessage()
                );
            }
        },

    'createsUser() separates making an account from writing to one' =>
        static function () use ($attributes, $groupsFor): void {
            $mapped = $attributes([UserField::EMAIL => 'jan@example.com']);
            $policy = new ProvisioningPolicy(new ProvisioningSettings());
            $user = new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Active, false);

            $created = $policy->decide($mapped, $groupsFor(['Editors']), null);
            $updated = $policy->decide($mapped, $groupsFor(['Editors']), $user, true);
            $refused = $policy->decide($mapped, $groupsFor(['Editors']), $user, false);

            Assert::true($created->createsUser());
            // An Update writes, but it did not create the account - so it is not a fact an
            // identity link may be recorded from.
            Assert::false($updated->createsUser());
            Assert::true($updated->writesUser());
            Assert::false($refused->createsUser());
        },

    'matching by username cannot be used to walk into someone else\'s account' =>
        static function () use ($attributes, $groupsFor): void {
            // No domain allow list applies on this path, so without the opt-in the only thing
            // guarding an existing account would be the IdP's policy on preferred_username.
            $policy = new ProvisioningPolicy(
                new ProvisioningSettings(true, true, false, UserMatchKey::Username)
            );
            $victim = new ExistingUser('7', 'owner@example.com', 'jkowalski', false, AccountStatus::Active, false);

            $decision = $policy->decide(
                $attributes([
                    UserField::EMAIL => 'attacker@evil.com',
                    UserField::USERNAME => 'jkowalski',
                ]),
                $groupsFor(['Editors']),
                $victim
            );

            Assert::same(ProvisioningAction::Deny, $decision->action);
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $decision->reasonCode);
        },

    'an administrator account needs a second, separate yes' =>
        static function () use ($attributes, $groupsFor): void {
            $owner = new ExistingUser('1', 'owner@example.com', 'owner', true, AccountStatus::Active, false);
            $mapped = $attributes([
                UserField::EMAIL => 'owner@example.com',
                UserField::USERNAME => 'owner',
            ]);

            $linkingOnly = (new ProvisioningPolicy(
                new ProvisioningSettings(linkExistingAccounts: true)
            ))->decide($mapped, $groupsFor(['Editors']), $owner);

            Assert::same(ProvisioningAction::Deny, $linkingOnly->action);
            Assert::same(ProvisioningDecision::ADMIN_LINK_NOT_ALLOWED, $linkingOnly->reasonCode);
            Assert::same('1', $linkingOnly->userId);

            $bothOn = (new ProvisioningPolicy(new ProvisioningSettings(
                linkExistingAccounts: true,
                linkAdminAccounts: true
            )))->decide($mapped, $groupsFor(['Editors']), $owner);

            Assert::same(ProvisioningAction::Update, $bothOn->action);
        },

    'the admin switch alone does not enable linking' => static function (): void {
        $settings = new ProvisioningSettings(linkAdminAccounts: true);

        Assert::false($settings->linkExistingAccounts);
        Assert::false($settings->linkAdminAccounts, 'a half-enabled state must not exist');
    },

    'the same username under both match keys is refused without the opt-in' =>
        static function () use ($attributes, $groupsFor): void {
            foreach ([UserMatchKey::Email, UserMatchKey::Username] as $matchBy) {
                $policy = new ProvisioningPolicy(
                    new ProvisioningSettings(true, true, false, $matchBy)
                );

                $decision = $policy->decide(
                    $attributes([
                        UserField::EMAIL => 'jan@example.com',
                        UserField::USERNAME => 'jkowalski',
                    ]),
                    $groupsFor(['Editors']),
                    new ExistingUser('42', 'jan@example.com', 'jkowalski', false, AccountStatus::Active, false)
                );

                Assert::same(ProvisioningAction::Deny, $decision->action, $matchBy->value);
                Assert::same(
                    ProvisioningDecision::LINKING_DISABLED,
                    $decision->reasonCode,
                    $matchBy->value
                );
            }
        },

    'a deactivated account is not brought back to life by SSO' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true));

            $decision = $policy->decide(
                $attributes([UserField::EMAIL => 'leaver@example.com']),
                $groupsFor(['Editors']),
                new ExistingUser('42', 'leaver@example.com', 'leaver', false, AccountStatus::Inactive, false)
            );

            Assert::same(ProvisioningAction::Deny, $decision->action);
            Assert::same(ProvisioningDecision::ACCOUNT_INACTIVE, $decision->reasonCode);
            Assert::false($decision->writesUser());
        },

    'a locked account is not unlocked by signing in through the IdP' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true));

            $decision = $policy->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                new ExistingUser('42', 'jan@example.com', 'jan', false, AccountStatus::Active, true)
            );

            Assert::same(ProvisioningAction::Deny, $decision->action);
            Assert::same(ProvisioningDecision::ACCOUNT_LOCKED, $decision->reasonCode);
        },

    'a pending account is allowed in - the IdP is the verification' =>
        static function () use ($attributes, $groupsFor): void {
            $policy = new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true));

            $decision = $policy->decide(
                $attributes([UserField::EMAIL => 'new@example.com']),
                $groupsFor(['Editors']),
                new ExistingUser('42', 'new@example.com', 'new', false, AccountStatus::Pending, false)
            );

            Assert::same(ProvisioningAction::Update, $decision->action);
            Assert::true(AccountStatus::Pending->allowsSignIn());
            Assert::false(AccountStatus::Inactive->allowsSignIn());
            Assert::false(AccountStatus::Suspended->allowsSignIn());
        },

    'a refusal tells the visitor nothing about the account it matched' =>
        static function () use ($attributes, $groupsFor): void {
            $mapped = $attributes([
                UserField::EMAIL => 'owner@example.com',
                UserField::USERNAME => 'owner',
            ]);
            $owner = new ExistingUser('1', 'owner@example.com', 'owner', true, AccountStatus::Active, false);

            /** @var list<array{0: ProvisioningPolicy, 1: ?ExistingUser}> $scenarios */
            $scenarios = [
                // exists / exists and is an admin / suspended / deactivated / locked
                [new ProvisioningPolicy(new ProvisioningSettings()), $owner],
                [new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true)), $owner],
                [
                    new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true)),
                    new ExistingUser('2', 'owner@example.com', 'owner', false, AccountStatus::Suspended, false),
                ],
                [
                    new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true)),
                    new ExistingUser('3', 'owner@example.com', 'owner', false, AccountStatus::Inactive, false),
                ],
                [
                    new ProvisioningPolicy(new ProvisioningSettings(linkExistingAccounts: true)),
                    new ExistingUser('4', 'owner@example.com', 'owner', false, AccountStatus::Active, true),
                ],
                // and the refusals that happen with no account at all
                [new ProvisioningPolicy(new ProvisioningSettings(false)), null],
                [new ProvisioningPolicy(new ProvisioningSettings(true, true, true)), null],
                [
                    new ProvisioningPolicy(new ProvisioningSettings(
                        true,
                        true,
                        false,
                        UserMatchKey::Email,
                        ['example.org']
                    )),
                    null,
                ],
            ];

            $seenReasons = [];
            foreach ($scenarios as [$policy, $user]) {
                $decision = $policy->decide($mapped, $groupsFor(['Sales']), $user);

                Assert::true($decision->isDenied(), $decision->reasonCode);
                $seenReasons[$decision->reasonCode] = true;

                Assert::same(
                    ProvisioningDecision::PUBLIC_DENIED_MESSAGE,
                    $decision->publicMessage(),
                    'every refusal must read the same: ' . $decision->reasonCode
                );

                foreach ([
                    'administrator',
                    'already exists',
                    'suspended',
                    'deactivated',
                    'locked',
                    'domain',
                    'owner@example.com',
                    'owner',
                ] as $leak) {
                    Assert::notContains(
                        $leak,
                        $decision->publicMessage(),
                        $decision->reasonCode . ' leaks "' . $leak . '"'
                    );
                }
            }

            Assert::true(count($seenReasons) >= 6, 'the scenarios must really differ underneath');

            // The administrator still gets the specific wording - that is what the panel is for.
            $adminFacing = (new ProvisioningPolicy(
                new ProvisioningSettings(linkExistingAccounts: true)
            ))->decide($mapped, $groupsFor(['Sales']), $owner);

            Assert::same(ProvisioningDecision::ADMIN_LINK_NOT_ALLOWED, $adminFacing->reasonCode);
            Assert::contains('administrator account', $adminFacing->message);
        },

    'an allowed decision has a harmless public message too' =>
        static function () use ($attributes, $groupsFor): void {
            $decision = (new ProvisioningPolicy(new ProvisioningSettings()))->decide(
                $attributes([UserField::EMAIL => 'jan@example.com']),
                $groupsFor(['Editors']),
                null
            );

            Assert::false($decision->isDenied());
            Assert::notSame(ProvisioningDecision::PUBLIC_DENIED_MESSAGE, $decision->publicMessage());
            Assert::notContains('jan@example.com', $decision->publicMessage());
        },

    'the flags that carry the security gates cannot be left out' => static function (): void {
        // An adapter written as `new ExistingUser($id, $email, $username)` used to describe every
        // account as "not an admin, active, not locked" and walk past all four gates at once.
        // A missing argument has to fail at integration time, not quietly allow a login.
        $parameters = [];
        foreach ((new ReflectionMethod(ExistingUser::class, '__construct'))->getParameters() as $p) {
            $parameters[$p->getName()] = $p;
        }

        foreach (['isAdmin', 'status', 'isLocked'] as $name) {
            Assert::true(isset($parameters[$name]), $name);
            Assert::false(
                $parameters[$name]->isOptional(),
                $name . ' must not have a permissive default: it decides access'
            );
        }

        Assert::throws(
            ArgumentCountError::class,
            static fn () => new ExistingUser('42', 'jan@example.com', 'jkowalski')
        );
    },

    'an account address is compared in normalised form' => static function (): void {
        $user = new ExistingUser(' 42 ', '  Jan.Kowalski@Example.COM ', ' jkowalski ', false, AccountStatus::Active, false);

        Assert::same('42', $user->id);
        Assert::same('jan.kowalski@example.com', $user->email, 'or every login makes a duplicate');
        Assert::same('jkowalski', $user->username);
        Assert::false($user->isSuspended());
        Assert::same(AccountStatus::Active, $user->status);
        Assert::false($user->isLocked);
    },

    'a decision serialises without leaking values' => static function () use ($attributes, $groupsFor): void {
        $policy = new ProvisioningPolicy(new ProvisioningSettings());
        $decision = $policy->decide(
            $attributes([UserField::EMAIL => 'jan@example.com', UserField::FIRST_NAME => 'Jan']),
            $groupsFor(['Editors']),
            null
        );

        $array = $decision->toArray();
        $json = json_encode($array);

        Assert::same('create', $array['action']);
        Assert::sameList([UserField::EMAIL, UserField::FIRST_NAME], $array['fields']);
        Assert::notSame(false, $json);
        Assert::notContains('jan@example.com', (string)$json);
    },
];
