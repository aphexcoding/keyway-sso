<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

/**
 * The SSO button on the control panel login screen: whether to draw it, and the markup for it.
 *
 * Pure on purpose, like CraftUserSnapshot next door. The two rules worth getting right - when
 * the button must NOT appear, and what shape the markup has to have to be visible at all - are
 * both testable here without a CMS, and both were wrong-by-default before they were measured.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THE MARKUP LOOKS LIKE THIS, AND WHY IT IS NOT A STYLE CHOICE
 * ------------------------------------------------------------------------------------------
 *
 * Craft's login screen does not put the sign-in form in the page. `login.twig` builds it into a
 * Twig variable and hands it to the browser inside a `<script>` as
 * `document.write({{ formHtml|json_encode|raw }})`, after a cookie test (Craft 5,
 * `vendor/craftcms/cms/src/templates/login.twig:49-69`). So anything appended to the page's
 * body, or spliced into the finished HTML after rendering, lands OUTSIDE the container the form
 * is written into - which is both the wrong place visually and, more decisively, the wrong place
 * functionally: see the next paragraph.
 *
 * The one mechanism that works is the template hook `cp.login.alternative-login-methods`, which
 * sits inside `_special/login.twig` and is therefore rendered SERVER-SIDE, into the string that
 * `document.write()` later emits. The markup below is written to satisfy the condition Craft's
 * own JavaScript applies to that container: `LoginForm` un-hides `.alternative-login-methods`
 * only when it has a direct child matching `.btn:not(.hidden)` (measured in the shipped bundle,
 * `web/assets/cp/dist/cp.js`). A `<div>`, a `<p>` or a `<button class="sso-button">` would render
 * into the page and stay invisible forever, because the container keeps its `hidden` class. Hence
 * `btn`, hence a direct child, hence no wrapper element.
 *
 * It is a link and not a form, which settles the CSRF question before it is asked: starting a
 * login is a GET, it carries no token, and there is nothing for a cross-site page to forge that
 * the browser binding does not already cover.
 */
final class SsoLoginButton
{
    /**
     * The context key Craft sets when the login form is rendered for RE-VERIFICATION rather than
     * for signing in (`_special/login-modal.twig` via `UsersController::actionLoginModal()`).
     */
    public const CONTEXT_ELEVATED_SESSION = 'forElevatedSession';

    private function __construct()
    {
    }

    /**
     * @param bool $ready Whether single sign-on is configured AND usable right now.
     * @param array<string, mixed> $context The Twig context the hook was invoked with.
     */
    public static function shouldRender(bool $ready, array $context = []): bool
    {
        if (!$ready) {
            // The product promise, and the reason this is the first condition: with single
            // sign-on off - or configured in a way that would not sign anybody in - the login
            // screen must look exactly as it did before the plugin was installed. A broken
            // identity provider cannot be allowed to lock a client out of their own panel.
            return false;
        }

        // The same hook fires for the "confirm your identity" modal, where a redirect to the
        // identity provider cannot do what is being asked: Craft grants an elevated session for
        // a password or a passkey it just checked, not for a session that already exists. A
        // button that silently does nothing useful is worse than no button.
        return ($context[self::CONTEXT_ELEVATED_SESSION] ?? false) !== true;
    }

    /**
     * The markup for the button. `$label` comes from the settings screen and `$url` is built by
     * Craft's own URL helper; both are escaped anyway, because "it came from an administrator"
     * is how stored cross-site scripting gets written.
     */
    public static function html(string $label, string $url): string
    {
        return sprintf(
            '<a class="btn keyway-sso-btn" href="%s" rel="nofollow">%s</a>',
            self::escape($url),
            self::escape($label)
        );
    }

    /**
     * The page the visitor should land on after signing in, as a LOCAL path this site can be
     * asked to return to - or null when there is nothing useful to carry.
     *
     * WHY THIS EXISTS AT ALL. Core\State\RedirectGuard replaces anything it will not follow with
     * its default path ("/"), so a login started with no return URL lands on the site root -
     * which, for a plugin whose entire purpose is getting people into the CONTROL PANEL, is the
     * wrong door. Craft already knows the right answer: `craft\web\User::getReturnUrl()` holds
     * the page the visitor was bounced off, or the configured post-login redirect. It just hands
     * it over as an absolute URL, which the guard refuses on principle.
     *
     * So the origin is dropped and the path kept. That is not a weakening of the guard: an
     * absolute URL pointing somewhere else would otherwise be refused outright, and what survives
     * here can only ever be a path on this site. The result still goes through the guard.
     */
    public static function returnTarget(?string $url): ?string
    {
        if ($url === null || trim($url) === '') {
            return null;
        }

        $parts = parse_url(trim($url));

        if ($parts === false || !isset($parts['path']) || !str_starts_with($parts['path'], '/')) {
            return null;
        }

        return $parts['path']
            . (isset($parts['query']) ? '?' . $parts['query'] : '')
            . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
