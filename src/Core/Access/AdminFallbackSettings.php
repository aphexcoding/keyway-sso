<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Access;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Configuration of the "can anyone still get in with a password" escape hatch.
 *
 * This object carries a hard safety net. If the settings would leave nobody able to reach the
 * control panel when the identity provider breaks - SSO-only, admins blocked, no emergency
 * account - the constructor does NOT throw: it silently re-enables password login for admins
 * and flags it via lockoutGuardApplied(). A throw here would be worse than useless, because
 * these settings are read while rendering the login page; failing to build them would replace a
 * misconfigured login screen with a fatal error, and the client would be locked out by the very
 * guard meant to prevent it.
 *
 * The break-glass switch deliberately does not count as an escape hatch for the guard, and that
 * reasoning only holds because the window is enforced here rather than promised in a comment.
 * Two layers, because this object is built both on the settings screen and on every render of
 * the login page:
 *
 *  - `assertBreakGlassWindow()` is the strict one, called when settings are SAVED: enabling
 *    break-glass without an expiry, with an expiry in the past, or with a window longer than
 *    BREAK_GLASS_MAX_TTL is an error the administrator sees immediately;
 *  - the constructor is the forgiving one, because throwing while rendering a login page is how
 *    a client gets locked out of their own site. It does not throw - it CLOSES the switch,
 *    flags `breakGlassGuardApplied()`, and the site simply stays SSO-only.
 *
 * Either way the outcome is the same for security: `breakGlassEnabled = true` with no expiry is
 * never an open door. An emergency switch flipped at 2am during an IdP outage has to stop being
 * an emergency switch by itself, or the plugin's whole "SSO only" promise is decoration - and
 * this was a real defect, not a hypothetical: the previous version treated a null expiry as
 * "open forever" while telling the user it was enabled "temporarily".
 */
final class AdminFallbackSettings
{
    /**
     * Longest break-glass window we will honour: one day. Long enough to survive an outage and
     * a night's sleep, short enough that forgetting about it is not a permanent password door.
     */
    public const BREAK_GLASS_MAX_TTL = 86400;

    public readonly bool $ssoOnly;
    public readonly bool $allowPasswordForAdmins;
    public readonly bool $breakGlassEnabled;
    public readonly ?int $breakGlassExpiresAt;

    /** @var list<string> lower-cased identifiers */
    private array $emergencyAccounts;

    private bool $lockoutGuardApplied = false;
    private bool $breakGlassGuardApplied = false;

    /**
     * @param list<string> $emergencyAccounts E-mail addresses or usernames that may always use
     *                                        a password, regardless of SSO-only mode.
     */
    public function __construct(
        bool $ssoOnly = false,
        bool $allowPasswordForAdmins = true,
        array $emergencyAccounts = [],
        bool $breakGlassEnabled = false,
        ?int $breakGlassExpiresAt = null
    ) {
        $accounts = [];
        foreach ($emergencyAccounts as $account) {
            $account = Ascii::lower(Ascii::trim((string)$account));
            if ($account !== '' && !in_array($account, $accounts, true)) {
                $accounts[] = $account;
            }
        }

        if (self::wouldLockOut($ssoOnly, $allowPasswordForAdmins, $accounts)) {
            $allowPasswordForAdmins = true;
            $this->lockoutGuardApplied = true;
        }

        if ($breakGlassEnabled && $breakGlassExpiresAt === null) {
            // Fail closed rather than throw: see the class docblock. An emergency switch with
            // no end is not an emergency switch, so we treat it as off.
            $breakGlassEnabled = false;
            $this->breakGlassGuardApplied = true;
        }

        $this->ssoOnly = $ssoOnly;
        $this->allowPasswordForAdmins = $allowPasswordForAdmins;
        $this->emergencyAccounts = $accounts;
        $this->breakGlassEnabled = $breakGlassEnabled;
        $this->breakGlassExpiresAt = $breakGlassEnabled ? $breakGlassExpiresAt : null;
    }

    /**
     * Validation for the settings screen: refuses to SAVE a break-glass switch that would not
     * close by itself.
     *
     * @throws InvalidArgumentException when the requested window is missing, already over or
     *                                  longer than BREAK_GLASS_MAX_TTL.
     */
    public static function assertBreakGlassWindow(
        bool $breakGlassEnabled,
        ?int $breakGlassExpiresAt,
        int $now
    ): void {
        if (!$breakGlassEnabled) {
            return;
        }

        if ($breakGlassExpiresAt === null) {
            throw new InvalidArgumentException(
                'Emergency password login must be given an expiry time. A break-glass switch '
                . 'that never closes is a permanent password door on a site configured for '
                . 'single sign-on only.'
            );
        }

        if ($breakGlassExpiresAt <= $now) {
            throw new InvalidArgumentException(
                'The emergency password login expiry is in the past, so turning it on would do '
                . 'nothing. Pick a time in the future.'
            );
        }

        if ($breakGlassExpiresAt - $now > self::BREAK_GLASS_MAX_TTL) {
            throw new InvalidArgumentException(sprintf(
                'Emergency password login can be enabled for at most %d hours at a time. '
                . 'Turn it on again if the identity provider is still down.',
                intdiv(self::BREAK_GLASS_MAX_TTL, 3600)
            ));
        }
    }

    /**
     * True when the constructor had to close a break-glass switch that would never have closed
     * by itself. The settings screen shows this as a warning.
     */
    public function breakGlassGuardApplied(): bool
    {
        return $this->breakGlassGuardApplied;
    }

    /**
     * Seconds of emergency access left, or null when it is not active at all. Used by the
     * settings screen and the diagnostics panel to say something truthful.
     */
    public function breakGlassRemaining(int $now): ?int
    {
        if (!$this->isBreakGlassActive($now)) {
            return null;
        }

        return (int)$this->breakGlassExpiresAt - $now;
    }

    /**
     * Used by the settings screen to warn before saving, and by the constructor to self-heal.
     *
     * @param list<string> $emergencyAccounts
     */
    public static function wouldLockOut(
        bool $ssoOnly,
        bool $allowPasswordForAdmins,
        array $emergencyAccounts
    ): bool {
        if (!$ssoOnly) {
            return false;
        }

        if ($allowPasswordForAdmins) {
            return false;
        }

        foreach ($emergencyAccounts as $account) {
            if (Ascii::trim((string)$account) !== '') {
                return false;
            }
        }

        return true;
    }

    public function lockoutGuardApplied(): bool
    {
        return $this->lockoutGuardApplied;
    }

    /** @return list<string> */
    public function emergencyAccounts(): array
    {
        return $this->emergencyAccounts;
    }

    public function isEmergencyAccount(string $identifier): bool
    {
        $identifier = Ascii::lower(Ascii::trim($identifier));

        if ($identifier === '') {
            return false;
        }

        return in_array($identifier, $this->emergencyAccounts, true);
    }

    public function isBreakGlassActive(int $now): bool
    {
        if (!$this->breakGlassEnabled || $this->breakGlassExpiresAt === null) {
            return false;
        }

        if ($now >= $this->breakGlassExpiresAt) {
            return false;
        }

        // An expiry further out than the maximum window is a misconfiguration (hand-edited
        // project config, a legacy row, a timestamp in milliseconds). Closed, not honoured.
        return $this->breakGlassExpiresAt - $now <= self::BREAK_GLASS_MAX_TTL;
    }
}
