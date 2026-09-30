<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\SsoLoginButton;
use Keyway\Sso\Test\Support\Assert;

/**
 * The button on the control panel login screen.
 *
 * Two rules, both of which would otherwise only be checkable by loading a CMS and looking at a
 * page: WHEN it appears, and whether the markup is the shape Craft's own login script requires
 * in order to show it at all.
 *
 * The markup assertion is not cosmetic. Craft 5's `LoginForm` un-hides the
 * `.alternative-login-methods` container only when it has a direct child matching
 * `.btn:not(.hidden)` (measured in `web/assets/cp/dist/cp.js`). Markup that renders perfectly
 * well but is not a `.btn` produces a button that is in the page and invisible forever - the
 * kind of defect that passes every review and fails at the client.
 */
return [
    'no button when single sign-on is not usable' => static function (): void {
        // The product promise: a broken identity provider configuration cannot be allowed to
        // change the login screen, because the person who needs that screen is the one who has
        // to go and fix the configuration.
        Assert::false(SsoLoginButton::shouldRender(false));
        Assert::false(SsoLoginButton::shouldRender(false, ['forElevatedSession' => false]));
    },

    'a button when single sign-on is ready' => static function (): void {
        Assert::true(SsoLoginButton::shouldRender(true));
        Assert::true(SsoLoginButton::shouldRender(true, ['showResetPassword' => true]));
    },

    'no button in the "confirm your identity" modal' => static function (): void {
        // The same partial - and therefore the same hook - is included by
        // `_special/login-modal.twig`. Craft grants an elevated session for a credential it has
        // just checked; a redirect to the identity provider cannot satisfy that, so the button
        // would be a control that silently does nothing useful.
        Assert::false(SsoLoginButton::shouldRender(true, ['forElevatedSession' => true]));
    },

    'the expired-session modal still gets the button' => static function (): void {
        // Same template, different job: here signing in again is exactly what is being asked
        // for, and `forElevatedSession` is false.
        Assert::true(SsoLoginButton::shouldRender(true, ['forElevatedSession' => false]));
    },

    'the markup is a direct .btn, which is what makes it visible' => static function (): void {
        $html = SsoLoginButton::html('Sign in with SSO', 'https://site.example.com/admin/sso/start');

        Assert::true(str_starts_with($html, '<a class="btn'), 'a direct .btn child, no wrapper');
        Assert::contains('href="https://site.example.com/admin/sso/start"', $html);
        Assert::contains('>Sign in with SSO</a>', $html);
        Assert::notContains('hidden', $html, 'a hidden child keeps the whole container hidden');
    },

    // RedirectGuard replaces anything it will not follow with "/", so a login started with no
    // return URL lands on the site root - the wrong door for a control-panel plugin. Craft knows
    // the right answer and states it as an absolute URL, which the guard refuses on principle.
    'an absolute return URL is reduced to a local path' => static function (): void {
        Assert::same(
            '/admin/entries/pages',
            SsoLoginButton::returnTarget('https://site.example.com/admin/entries/pages')
        );
    },

    'the query and fragment survive, because they are part of where somebody was' =>
        static function (): void {
            Assert::same(
                '/index.php?p=actions/users/redirect',
                SsoLoginButton::returnTarget('https://site.example.com/index.php?p=actions/users/redirect')
            );
            Assert::same('/admin/settings#tab2', SsoLoginButton::returnTarget('/admin/settings#tab2'));
        },

    'nothing usable comes back as nothing, not as a guess' => static function (): void {
        Assert::null(SsoLoginButton::returnTarget(null));
        Assert::null(SsoLoginButton::returnTarget('   '));
        Assert::null(SsoLoginButton::returnTarget('https://site.example.com'));
        Assert::null(SsoLoginButton::returnTarget('mailto:someone@example.com'));
    },

    // The origin is dropped rather than trusted: what comes out is a path on THIS site, so a
    // foreign host in the session's return URL cannot become an off-site redirect. The result
    // still goes through RedirectGuard afterwards.
    'a foreign origin cannot survive as an origin' => static function (): void {
        Assert::same('/admin', SsoLoginButton::returnTarget('https://evil.example.net/admin'));
        Assert::null(SsoLoginButton::returnTarget('//evil.example.net'));
    },

    'the label and the URL are escaped' => static function (): void {
        // The label is typed by an administrator on the settings screen. "It came from an
        // administrator" is how stored cross-site scripting gets written.
        $html = SsoLoginButton::html('"><script>alert(1)</script>', 'https://x/?a=1&b=2');

        Assert::notContains('<script>', $html);
        Assert::contains('&amp;b=2', $html);
        Assert::contains('&quot;&gt;', $html);
    },
];
