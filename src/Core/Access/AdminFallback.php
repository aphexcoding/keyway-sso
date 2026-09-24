<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Access;

use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Provisioning\ExistingUser;

/**
 * Keeps a bad IdP configuration from locking the client out of their own control panel.
 *
 * The rule the whole plugin is sold on: turning on SSO-only mode must never be a one-way door.
 * Stated precisely, because the difference matters when you configure a site: what is
 * guaranteed is that AT LEAST ONE PERMANENT way back in survives, not that any given
 * administrator keeps their password.
 *
 * The guard counts exactly two permanent routes - the admin password fallback and the
 * emergency account list - and SSO-only with both of them off is the one combination that
 * would close the door. AdminFallbackSettings refuses to build it: it turns the password
 * fallback back on and records that it did, via lockoutGuardApplied().
 *
 * Break-glass is NOT a third route for the purposes of that count, and the omission is
 * deliberate rather than an oversight: it expires, and a door that closes on a timer is not
 * a way back in. Turning it on therefore does not buy you the right to switch the password
 * fallback off - the guard will still rewrite that configuration. See the reasoning in
 * AdminFallbackSettings, which is where the window is enforced.
 *
 * So an administrator who is not on the emergency list, on a site that has deliberately
 * turned the password fallback off while keeping an emergency account, IS refused - and
 * that refusal is correct. While a break-glass window is open, that same administrator is
 * let in; when it closes, they are refused again.
 */
final class AdminFallback
{
    private AdminFallbackSettings $settings;
    private ClockInterface $clock;

    public function __construct(AdminFallbackSettings $settings, ClockInterface $clock)
    {
        $this->settings = $settings;
        $this->clock = $clock;
    }

    public function settings(): AdminFallbackSettings
    {
        return $this->settings;
    }

    /**
     * @param string $submittedIdentifier What was typed into the login form; may not resolve to
     *                                    an account, which is why it is checked separately from
     *                                    the resolved user.
     */
    public function decidePasswordLogin(
        ?ExistingUser $user = null,
        string $submittedIdentifier = ''
    ): PasswordLoginDecision {
        if (!$this->settings->ssoOnly) {
            return PasswordLoginDecision::allow(
                PasswordLoginDecision::PASSWORD_LOGIN_ENABLED,
                'Password login is enabled for this site.'
            );
        }

        $now = $this->clock->now();
        $remaining = $this->settings->breakGlassRemaining($now);
        if ($remaining !== null) {
            return PasswordLoginDecision::allow(
                PasswordLoginDecision::BREAK_GLASS,
                sprintf(
                    'Emergency password login is temporarily enabled (about %d minute(s) left).',
                    (int)ceil($remaining / 60)
                )
            );
        }

        if ($this->matchesEmergencyAccount($user, $submittedIdentifier)) {
            return PasswordLoginDecision::allow(
                PasswordLoginDecision::EMERGENCY_ACCOUNT,
                'This account is on the emergency access list.'
            );
        }

        if ($user !== null && $user->isAdmin && $this->settings->allowPasswordForAdmins) {
            return PasswordLoginDecision::allow(
                PasswordLoginDecision::ADMIN_FALLBACK,
                'Administrators may sign in with a password while SSO-only mode is on.'
            );
        }

        return PasswordLoginDecision::deny(
            PasswordLoginDecision::SSO_REQUIRED,
            'This site requires single sign-on. Use the SSO button to sign in.'
        );
    }

    public function isPasswordLoginAllowed(
        ?ExistingUser $user = null,
        string $submittedIdentifier = ''
    ): bool {
        return $this->decidePasswordLogin($user, $submittedIdentifier)->allowed;
    }

    /**
     * True when the login form should still render the password fields.
     *
     * At render time nobody has been identified yet, so this is intentionally permissive: the
     * real decision happens on submit. Hiding the form from an admin who has not typed anything
     * yet is exactly how clients get locked out.
     */
    public function shouldOfferPasswordForm(): bool
    {
        if (!$this->settings->ssoOnly) {
            return true;
        }

        if ($this->settings->isBreakGlassActive($this->clock->now())) {
            return true;
        }

        return $this->settings->allowPasswordForAdmins
            || $this->settings->emergencyAccounts() !== [];
    }

    private function matchesEmergencyAccount(?ExistingUser $user, string $submittedIdentifier): bool
    {
        if ($this->settings->isEmergencyAccount($submittedIdentifier)) {
            return true;
        }

        if ($user === null) {
            return false;
        }

        return $this->settings->isEmergencyAccount($user->email)
            || $this->settings->isEmergencyAccount($user->username);
    }
}
