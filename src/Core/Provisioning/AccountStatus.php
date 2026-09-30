<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

/**
 * The state of a Craft account, as far as signing in is concerned.
 *
 * Craft 5 has more than the single "suspended" flag the first version of the core modelled, and
 * the difference matters: `inactive` is what an administrator sets when they deprovision
 * somebody (Users -> Deactivate). An SSO plugin that only looked at `suspended` would sign that
 * person straight back in on their next visit to the login screen, because the identity provider
 * still knows them.
 */
enum AccountStatus: string
{
    /** Normal account. */
    case Active = 'active';

    /** Registered but never activated - e-mail not verified yet. */
    case Pending = 'pending';

    /** Suspended by an administrator. */
    case Suspended = 'suspended';

    /** Deactivated by an administrator: deprovisioned, kept for the record. */
    case Inactive = 'inactive';

    /**
     * May single sign-on put somebody into this account at all?
     *
     * Pending is the only non-active state that says yes, because pre-provisioning is how teams
     * actually roll SSO out: accounts are created ahead of time and the first SSO login is what
     * activates them. Refusing Pending would break the standard deployment.
     *
     * The risk it carries is NOT "the address was never verified" - the IdP verifies that far
     * better than a confirmation e-mail. It is that a Pending account may already have a
     * PASSWORD set by whoever created it. On a site with public registration open, somebody can
     * register `victim@example.com`, choose their own password, never verify; the victim then
     * signs in through the IdP, gets linked to that account, and the attacker keeps a working
     * password to it. Two things stand in the way and both must stay: `linkExistingAccounts` is
     * off by default (the link never happens unless the site owner allowed it), and the Craft
     * layer should clear the stored password when SSO links a Pending account. Whoever builds
     * the settings screen: this is the warning that belongs next to the linking checkbox.
     */
    public function allowsSignIn(): bool
    {
        return $this === self::Active || $this === self::Pending;
    }
}
