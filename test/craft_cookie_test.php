<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftCookie;
use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * CookieDirective -> `yii\web\Cookie`, against the real Yii class.
 *
 * Six lines of mapping, and every one of them is a way for the browser binding to be believed in
 * and not actually held: a relative `maxAge` sent as an absolute `expire`, a deletion that
 * forgets the attributes the cookie was keyed on, `expire = 0` (session cookie) where a deletion
 * was meant. None of those throw and none of them show up in a code review; they show up as
 * `binding_cookie_missing` at a client site, which reads like a proxy stripping cookies.
 *
 * The directives below are built by the REAL BrowserBinding rather than by hand, so the case
 * also pins the two attribute sets that matter: a cross-site POST callback over HTTPS needs
 * `SameSite=None; Secure`, and the deletion has to repeat them.
 */
if (!class_exists(\yii\web\Cookie::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_cookie', 'skipped: vendor absent (run composer install)'));

    return [];
}

if (!class_exists(\Yii::class, false)) {
    require __DIR__ . '/../vendor/yiisoft/yii2/Yii.php';
}

$binding = static fn (): BrowserBinding => new BrowserBinding(new SequenceRandomSource());

$https = 'https://site.example.com/actions/keyway-sso/sso/acs';

return [
    'maxAge becomes an absolute expiry, not a literal' => static function () use ($binding, $https): void {
        $clock = new FixedClock(1_700_000_000);
        $issued = $binding()->issue($https, CallbackStyle::CrossSitePost, 600);

        $cookie = CraftCookie::from($issued->cookie, $clock);

        Assert::same(BrowserBinding::COOKIE_NAME, $cookie->name);
        Assert::same(1_700_000_600, $cookie->expire, 'seconds-from-now are not a timestamp');
        Assert::same($issued->cookie->value, $cookie->value, 'the secret is passed through untouched');
        Assert::same('/actions/keyway-sso/sso/acs', $cookie->path);
    },

    'a cross-site POST binding keeps SameSite=None; Secure' => static function () use ($binding, $https): void {
        $issued = $binding()->issue($https, CallbackStyle::CrossSitePost, 600);
        $cookie = CraftCookie::from($issued->cookie, new FixedClock());

        Assert::same('None', $cookie->sameSite, 'a Lax cookie is not sent on a cross-site POST');
        Assert::true($cookie->secure, 'SameSite=None without Secure is discarded by the browser');
        Assert::true($cookie->httpOnly);
    },

    'a deletion expires in the past and repeats the original attributes' =>
        static function () use ($binding, $https): void {
            $directive = $binding()->clear($https, CallbackStyle::CrossSitePost);
            $cookie = CraftCookie::from($directive, new FixedClock(1_700_000_000));

            Assert::same(1, $cookie->expire, 'zero would mean "until the browser closes"');
            Assert::same('/actions/keyway-sso/sso/acs', $cookie->path);
            Assert::same('None', $cookie->sameSite, 'a deletion that drops them removes nothing');
            Assert::true($cookie->secure);
            Assert::same('', $cookie->value);
        },

    'an OIDC top-level redirect keeps Lax' => static function () use ($binding): void {
        $issued = $binding()->issue(
            'http://site.example.com/actions/keyway-sso/sso/callback',
            CallbackStyle::TopLevelRedirect,
            600
        );
        $cookie = CraftCookie::from($issued->cookie, new FixedClock());

        Assert::same('Lax', $cookie->sameSite);
        Assert::false($cookie->secure, 'plain HTTP cannot set a Secure cookie');
    },
];
