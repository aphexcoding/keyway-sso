<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

use Keyway\Sso\Core\Attribute\EmailNormalizer;
use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Group\GroupAssignment;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Decides create / update / sign in / deny for one login attempt.
 *
 * Checks run deny-first: everything that can refuse the login is evaluated before anything that
 * can create an account, so a denied identity never reaches the "does this user exist" branch
 * and never causes a write.
 *
 * Matching an account is not the same as being allowed into it. Attaching an IdP identity to an
 * account Craft already had is an explicit opt-in (`linkExistingAccounts`), and doing it to an
 * administrator account is a second, separate opt-in (`linkAdminAccounts`) - see
 * ProvisioningSettings. A refused link denies the login outright; it never falls through to
 * "create a new account instead", because that would just be the same takeover with an extra
 * row in the users table.
 *
 * AN ACCOUNT THIS PLUGIN CREATED IS NOT "AN ACCOUNT CRAFT ALREADY HAD", and until 2026-09-15
 * this class could not tell the two apart. Measured against a live Craft with Okta on default
 * settings: the first login created the account, the second was refused with `linking_disabled`,
 * so every just-in-time account was good for exactly one sign-in. `$identityOwnsAccount` is that
 * missing fact - "this connection's issuer is the one that created this account", supplied by
 * Core\Port\IdentityLinkStoreInterface - and it opens step 4a for those accounts only. It
 * changes NOTHING for an account somebody made in the control panel: without a link, 4a still
 * refuses with `linkExistingAccounts` off, which is the takeover guard and stays whole. Step 4b
 * is NOT opened by the link (see the comment there): a link says where an account came from, not
 * who made it an administrator.
 */
final class ProvisioningPolicy
{
    private ProvisioningSettings $settings;

    public function __construct(ProvisioningSettings $settings)
    {
        $this->settings = $settings;
    }

    /**
     * Which field this connection matches accounts on.
     *
     * Exposed because the caller has to pick between findByEmail() and findByUsername() on
     * UserDirectoryInterface, and re-deriving that from settings at the call site is how the
     * lookup key and the column it is looked up in drift apart.
     */
    public function matchBy(): UserMatchKey
    {
        return $this->settings->matchBy;
    }

    /**
     * Value the Craft layer should look the user up by, or null when it is missing.
     */
    public function lookupKeyFor(MappedAttributes $attributes): ?string
    {
        $value = $this->settings->matchBy === UserMatchKey::Email
            ? $attributes->email()
            : $attributes->username();

        if ($value === null) {
            return null;
        }

        $value = Ascii::trim($value);

        return $value === '' ? null : $value;
    }

    /**
     * @param bool $identityOwnsAccount True when the matched account was created by THIS plugin
     *        for the issuer AND the subject of the response being processed
     *        (IdentityLinkStoreInterface - all three values, because (account, issuer) alone is
     *        satisfied by anybody else at the same identity provider). The default is false, and
     *        it is only acceptable as a default because it closes rather than opens: a caller
     *        that forgets to pass it gets the old, refusing behaviour for just-in-time accounts,
     *        never an unguarded link to an account it knows nothing about.
     */
    public function decide(
        MappedAttributes $attributes,
        GroupAssignment $groups,
        ?ExistingUser $user,
        bool $identityOwnsAccount = false
    ): ProvisioningDecision {
        $matchBy = $this->settings->matchBy;
        $matchValue = $this->lookupKeyFor($attributes);
        $email = $attributes->email();

        // 1. Domain allow list. Checked first because it is the site's outer boundary: an
        //    address outside it must not match, update or create anything.
        if ($this->settings->restrictsDomains()) {
            if ($email === null) {
                return $this->deny(
                    ProvisioningDecision::EMAIL_MISSING,
                    'The identity provider sent no e-mail address, and this connection only '
                    . 'accepts addresses from the configured domains.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue
                );
            }

            if (!$this->settings->allowsDomain(EmailNormalizer::domain($email))) {
                return $this->deny(
                    ProvisioningDecision::DOMAIN_NOT_ALLOWED,
                    sprintf(
                        'The domain of the address sent by the identity provider is not on the '
                        . 'allowed list (%s).',
                        implode(', ', $this->settings->allowedDomains())
                    ),
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue
                );
            }
        }

        // 2. Group requirement. The default group does not satisfy it on purpose: "deny when no
        //    group matches" is an access control, and a catch-all default would neutralise it.
        if ($this->settings->denyIfNoGroupMatch && !$groups->hasRuleMatch()) {
            return $this->deny(
                ProvisioningDecision::NO_GROUP_MATCH,
                'None of the groups sent by the identity provider matches a mapping rule, and '
                . 'this connection requires a group match to sign in.',
                $attributes,
                $groups,
                $matchBy,
                $matchValue
            );
        }

        // 3. Missing match key: we cannot safely find or create the account.
        if ($matchValue === null) {
            return $this->deny(
                $matchBy === UserMatchKey::Email
                    ? ProvisioningDecision::EMAIL_MISSING
                    : ProvisioningDecision::USERNAME_MISSING,
                sprintf(
                    'The identity provider sent no %s, which this connection uses to match '
                    . 'accounts.',
                    $matchBy->value
                ),
                $attributes,
                $groups,
                $matchBy,
                null
            );
        }

        // 4. Existing account.
        if ($user !== null) {
            // 4a. May an IdP identity attach itself to an account this site already has? This
            //     is the boundary an attacker crosses without touching a single byte of XML:
            //     they only need the IdP to emit a username or an address that matches. Off
            //     unless the site owner turned it on - EXCEPT for an account this connection
            //     created itself, which is not an account "this site already has" in any sense
            //     an attacker can use: it exists because this same issuer asked for it.
            if (!$identityOwnsAccount && !$this->settings->linkExistingAccounts) {
                return $this->deny(
                    ProvisioningDecision::LINKING_DISABLED,
                    // The wording used to say "accounts it did not create" while the code had no
                    // way of knowing what it had created, so it was printed over accounts this
                    // plugin had made minutes earlier. What is actually being reported is the
                    // absence of a record, which is also the honest answer when the link store
                    // is unreadable, so that is what it now says.
                    'A Craft account already exists for this identity, and this connection has '
                    . 'no record of having created it. Enable "link to existing accounts" for '
                    . 'this connection if it should sign in to accounts it did not create.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue,
                    $user->id
                );
            }

            // 4b. The owner's account needs its own yes. Linking the team is one decision;
            //     letting the identity provider hand out an administrator account is another.
            //
            //     A LINK ALONE DOES NOT OPEN THIS GATE, and the earlier version of this clause
            //     claiming otherwise was a hole. It reasoned that the `admin` flag on a linked
            //     account had been set by this plugin's own group mapping - but the link row
            //     records only that the account was CREATED here, never who promoted it. An
            //     administrator who created their account through SSO and was then made an admin
            //     BY HAND in the control panel is exactly the account 4b exists to defend, and
            //     the link made it linkable with `linkAdminAccounts` off - a setting the site
            //     owner cannot even turn on independently, because ProvisioningSettings forces
            //     it to false unless `linkExistingAccounts` is on as well.
            //
            //     What the plugin actually knows is on the right-hand side: THIS response grants
            //     admin through an AdminRule the site owner configured, with escalation switched
            //     on. That keeps the just-in-time administrator working - the same rule that
            //     made them an admin fires on every login they make - while an account promoted
            //     by a human still stops here.
            $adminGrantedByThisResponse = $identityOwnsAccount && $groups->grantsAdmin();

            if (!$adminGrantedByThisResponse && $user->isAdmin && !$this->settings->linkAdminAccounts) {
                return $this->deny(
                    ProvisioningDecision::ADMIN_LINK_NOT_ALLOWED,
                    'The matching Craft account is an administrator account. Single sign-on '
                    . 'does not take over administrator accounts unless that is enabled '
                    . 'separately for this connection.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue,
                    $user->id
                );
            }

            // 4c. Account state. Suspended was the only state the first version knew about,
            //     which meant single sign-on silently reactivated anyone an administrator had
            //     deactivated - the identity provider still knows them, so they would simply
            //     log back in. Every state that is not "may sign in" denies here.
            //
            //     UNCONDITIONAL, INCLUDING FOR LINKED ACCOUNTS, on purpose: suspending,
            //     deactivating or locking an account is a decision an administrator took about
            //     a person, and "we created this account ourselves" is not an argument against
            //     it. A link opens the two gates above, which are about ownership; it may not
            //     reach this one, which is about a standing instruction.
            if ($user->status === AccountStatus::Suspended) {
                return $this->deny(
                    ProvisioningDecision::ACCOUNT_SUSPENDED,
                    'The matching Craft account is suspended. Single sign-on does not lift a '
                    . 'suspension.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue,
                    $user->id
                );
            }

            if (!$user->status->allowsSignIn()) {
                return $this->deny(
                    ProvisioningDecision::ACCOUNT_INACTIVE,
                    'The matching Craft account has been deactivated. Single sign-on does not '
                    . 'reactivate an account somebody deactivated on purpose; reactivate it in '
                    . 'the control panel first.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue,
                    $user->id
                );
            }

            if ($user->isLocked) {
                return $this->deny(
                    ProvisioningDecision::ACCOUNT_LOCKED,
                    'The matching Craft account is locked after repeated failed sign-in '
                    . 'attempts. Single sign-on does not clear a lockout; unlock the account in '
                    . 'the control panel.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue,
                    $user->id
                );
            }

            if ($this->settings->updateOnLogin) {
                return new ProvisioningDecision(
                    ProvisioningAction::Update,
                    ProvisioningDecision::UPDATE_ON_LOGIN,
                    'Existing account matched; applying the mapped attributes and groups.',
                    $attributes,
                    $groups,
                    $matchBy,
                    $matchValue,
                    $user->id
                );
            }

            return new ProvisioningDecision(
                ProvisioningAction::SignInOnly,
                ProvisioningDecision::EXISTING_UNCHANGED,
                'Existing account matched; sync on login is off, so nothing is changed.',
                $attributes,
                $groups,
                $matchBy,
                $matchValue,
                $user->id
            );
        }

        // 5. No account yet.
        if (!$this->settings->allowJit) {
            return $this->deny(
                ProvisioningDecision::JIT_DISABLED,
                'No Craft account matches this identity and just-in-time provisioning is '
                . 'disabled for this connection.',
                $attributes,
                $groups,
                $matchBy,
                $matchValue
            );
        }

        if ($email === null) {
            return $this->deny(
                ProvisioningDecision::EMAIL_MISSING,
                'A new Craft account cannot be created without an e-mail address.',
                $attributes,
                $groups,
                $matchBy,
                $matchValue
            );
        }

        return new ProvisioningDecision(
            ProvisioningAction::Create,
            ProvisioningDecision::JIT_CREATE,
            'No account matched; creating a new one from the mapped attributes.',
            $attributes,
            $groups,
            $matchBy,
            $matchValue
        );
    }

    private function deny(
        string $reasonCode,
        string $message,
        MappedAttributes $attributes,
        GroupAssignment $groups,
        UserMatchKey $matchBy,
        ?string $matchValue,
        ?string $userId = null
    ): ProvisioningDecision {
        return new ProvisioningDecision(
            ProvisioningAction::Deny,
            $reasonCode,
            $message,
            $attributes,
            $groups,
            $matchBy,
            $matchValue,
            $userId
        );
    }
}
