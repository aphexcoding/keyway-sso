<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Access;

use Keyway\Sso\Core\Provisioning\ExistingUser;

/**
 * Turns AdminFallback's answer into something an authentication hook may act on.
 *
 * AdminFallback decides WHETHER a password may be used. This class decides whether that question
 * is even being asked, and what happens when working it out goes wrong - the two things that
 * separate a rule from an enforced rule, and the two things that were missing until now: both
 * AdminFallback and PasswordLoginDecision were dead code outside the settings screen, so five
 * switches on the settings screen did nothing at all.
 *
 * ALL THREE RULES LIVE HERE RATHER THAN IN THE CRAFT ADAPTER, and that is the whole point of the
 * class. The adapter half is a handler that reads a request and writes an error onto an element;
 * it cannot be exercised without booting a CMS, so anything with a decision in it that is left
 * there is a decision no test ever asks about. This was measured on this very plugin once
 * before: the `accessCp` check sitting inside CraftSignIn could be deleted with the whole suite
 * still green, which is why ControlPanelAccess exists. Same shape, same reason.
 *
 * RULE 1 - CONTROL PANEL ONLY. The setting is labelled "on the control panel" and that is the
 * only place it may act. Craft's `EVENT_BEFORE_AUTHENTICATE` is global: it fires for every
 * `craft\elements\User::authenticate()` in the installation, including front-end member logins
 * on the client's own shop or website. A gate without this narrowing would lock a site's
 * customers out of a storefront nobody bought single sign-on for.
 *
 * RULE 2 - PASSWORDS ONLY. The same event is fired by `authenticateWithPasskey()`
 * (vendor/craftcms/cms/src/elements/User.php:1433), which is NOT a password login. Craft
 * distinguishes the two by `AuthenticateUserEvent::$password`, documented as "the password that
 * was submitted, or null if a passkey is being used". A passkey holder shut out by a switch
 * labelled "password fallback" is a lockout wearing a different hat, so a non-password attempt
 * is passed through untouched.
 *
 * RULE 3 - FAIL OPEN, ALWAYS. Every input is taken as a callable and every call is wrapped,
 * because each one can fail on a real installation: the settings may be unreadable or
 * half-written, the clock may be wrong, the account lookup is a database query that can throw.
 * If ANY of that happens the password login proceeds unchanged. This is not defensive
 * decoration - it is the single difference between "the plugin refuses a password" and "the
 * plugin locked the client out of their own CMS, and the way back in is the thing that broke".
 * The product is sold on one promise, that turning on SSO-only is never a one-way door, and an
 * exception is exactly the moment a promise like that is tested.
 */
final class PasswordLoginGate
{
    /**
     * What is written onto `craft\elements\User::$authError` when a password is refused and the
     * installation has not asked for silence. Our own code, unknown to Craft, which falls through
     * `craft\helpers\User::getLoginFailureMessage()` to the generic "Invalid username or
     * password."; the Craft layer recognises it again on `EVENT_LOGIN_FAILURE` and replaces the
     * message with something truthful.
     *
     * DO NOT USE THIS CONSTANT DIRECTLY - go through authError(). The code does not only pick a
     * message: Craft publishes it. `_handleLoginFailure()` passes it to `asFailure()` as
     * `data: ['errorCode' => $authError]`, and `web\Controller::asFailure()` returns that as JSON
     * whenever the request accepts JSON - which the control panel's own login always does, since
     * it posts through `Craft.sendActionRequest`. A distinct code is therefore just as readable
     * to a script as a distinct message is to a person.
     */
    public const AUTH_ERROR = 'keywaySsoRequired';

    /**
     * Craft's own code for "wrong username or password", used when the installation has asked
     * that nothing distinguish one failure from another.
     *
     * The literal rather than `craft\elements\User::AUTH_INVALID_CREDENTIALS`, because `Core\`
     * has no Composer dependency and must stay testable with no `vendor/` at all;
     * password_login_gate_test.php pins the two together whenever Craft IS present, so a rename
     * upstream is caught by the suite rather than in production.
     *
     * BORROWING THIS CODE IS SAFE, and that was measured rather than assumed - the earlier
     * version of this file warned that Craft's codes "feed account-lockout accounting", which is
     * true of the lockout MECHANISM but not of this value. Every use of it in the CMS only ever
     * selects a message: `helpers/User.php:30` and `:118`, `elements/User.php:1374`, `:1449` and
     * `:2775`, and `services/Auth.php:278`, which reads `getAuthStatus()` and never our field.
     * The failed-attempt counter is kept by `handleInvalidLoginParam()`, which `authenticate()`
     * skips entirely when a handler has already set `$authError` - so a refusal here still costs
     * the account nothing, whichever of the two codes is written.
     */
    public const GENERIC_AUTH_ERROR = 'invalid_credentials';

    /** Not a control-panel request: rule 1 sent it through. */
    public const NOT_CONTROL_PANEL = 'not_control_panel';

    /** Not a password attempt (a passkey): rule 2 sent it through. */
    public const NOT_A_PASSWORD = 'not_a_password';

    /** Something needed to decide threw, so rule 3 sent it through. */
    public const GATE_UNAVAILABLE = 'gate_unavailable';

    private function __construct()
    {
    }

    /**
     * May this authentication attempt proceed as a password login?
     *
     * The two collaborators are callables rather than ready-made objects for one reason: they
     * are the parts that can throw, and passing them in already-built would move the failure out
     * of the try block and out of the tests - the fail-open promise would then only be as good
     * as the adapter's own error handling, which is the code nobody can test here. Handing them
     * in lazily keeps the dangerous work inside the guarded region, where a stub that throws can
     * prove the promise holds.
     *
     * @param bool     $isCpRequest          What `craft\web\Request::getIsCpRequest()` said, read
     *                                       in the Craft layer and passed down, never read here.
     * @param bool     $isPasswordSubmission False for a passkey; from `AuthenticateUserEvent`.
     * @param string   $submittedIdentifier  What was typed into the login form. Checked in its
     *                                       own right because the emergency list may name an
     *                                       account this installation cannot resolve.
     * @param callable():AdminFallback  $fallback May throw; treated as "allow".
     * @param callable():?ExistingUser  $user     May throw; treated as "allow".
     */
    public static function decide(
        bool $isCpRequest,
        bool $isPasswordSubmission,
        string $submittedIdentifier,
        callable $fallback,
        callable $user
    ): PasswordLoginDecision {
        if (!$isCpRequest) {
            return PasswordLoginDecision::allow(
                self::NOT_CONTROL_PANEL,
                'Password login outside the control panel is not this plugin\'s business.'
            );
        }

        if (!$isPasswordSubmission) {
            return PasswordLoginDecision::allow(
                self::NOT_A_PASSWORD,
                'This sign-in is not a password login, so the password fallback rules do not apply.'
            );
        }

        try {
            return $fallback()->decidePasswordLogin($user(), $submittedIdentifier);
        } catch (\Throwable $e) {
            // Deliberately swallowed, and deliberately not narrowed to a specific exception
            // type. Whatever went wrong - unreadable settings, a failing database, a bug of ours
            // - the answer is the same and has to be the same: let the password through. A gate
            // that refuses when it cannot think is a gate that locks the client out on the worst
            // possible day.
            return PasswordLoginDecision::allow(
                self::GATE_UNAVAILABLE,
                'The password fallback rules could not be evaluated, so password login was left alone.'
            );
        }
    }

    /**
     * The code to write onto `craft\elements\User::$authError` for a refusal.
     *
     * THE POINT OF THIS METHOD IS THAT THE CODE IS PUBLISHED, NOT PRIVATE. Craft hands it to
     * `asFailure()` as `data: ['errorCode' => $authError]`, and that is returned as JSON to any
     * request accepting JSON - which the control panel login always is. So an installation with
     * `preventUserEnumeration` on, which sees the generic *message*, would still have been able
     * to read `{"errorCode":"keywaySsoRequired"}` for an account that exists and
     * `{"errorCode":"invalid_credentials"}` for one that does not. That is precisely the oracle
     * the flag exists to close, so under the flag we answer with Craft's own generic code and
     * become indistinguishable from an ordinary bad password.
     *
     * @param bool $preventUserEnumeration Craft's general config flag, read in the Craft layer.
     */
    public static function authError(bool $preventUserEnumeration): string
    {
        return $preventUserEnumeration ? self::GENERIC_AUTH_ERROR : self::AUTH_ERROR;
    }

    /**
     * What the login screen should say instead of "Invalid username or password", or null to
     * leave Craft's own message alone.
     *
     * WHY A REPLACEMENT IS NEEDED. AUTH_ERROR is a code Craft does not know, so
     * `craft\helpers\User::getLoginFailureMessage()` falls through to its `default` branch and
     * tells an administrator their password was wrong when it was in fact correct - the single
     * most misleading thing this feature could do, and the message they would take to support.
     * Craft does allow a replacement: `UsersController::_handleLoginFailure()` fires
     * `EVENT_LOGIN_FAILURE` and then takes `$event->message` back
     * (vendor/craftcms/cms/src/controllers/UsersController.php, the LoginFailureEvent block).
     *
     * WHY `preventUserEnumeration` IS OBEYED, and this is the part worth reading twice. A
     * specific answer is only ever reached for an account that EXISTS: `actionLogin()` answers
     * an unknown login name with AUTH_INVALID_CREDENTIALS before `authenticate()` - and so
     * before this gate - is reached at all. So anything distinctive here is, by construction, a
     * way to ask the login screen "does this account exist?" and get a straight answer. On an
     * installation that has asked Craft to prevent exactly that, clarity loses to the setting
     * the administrator chose.
     *
     * MESSAGE AND CODE MUST BE SILENCED TOGETHER - see authError(). Craft draws the same
     * distinction under this flag, but it closes BOTH: `getLoginFailureInfo()` rewrites
     * `$authError` itself before deriving the message, so the published `errorCode` changes too.
     * Silencing only the message, as the first version of this class did, leaves the code as an
     * account-existence oracle in the JSON response and is strictly worse than not having the
     * feature.
     *
     * @param bool $preventUserEnumeration Craft's general config flag, read in the Craft layer.
     */
    public static function failureMessage(?string $authError, bool $preventUserEnumeration): ?string
    {
        if ($authError !== self::AUTH_ERROR) {
            return null;
        }

        if ($preventUserEnumeration) {
            return null;
        }

        // Spelled out here rather than taken from PasswordLoginDecision::$message, even though
        // that carries a near-identical sentence. The two have different audiences and different
        // lifetimes: the decision's message explains an outcome to whoever is reading the code or
        // a diagnostics row, and is produced during authentication, while this one is rendered on
        // a login screen by a SEPARATE Craft event that never sees the decision object. Passing
        // it across would mean holding the decision in request state between two events - a
        // stale-state bug waiting to happen, in the one code path that must not have one.
        return 'This site requires single sign-on. Use the sign-in button on this screen.';
    }
}
