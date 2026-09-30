<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Keyway\Sso\Core\Login\CookieDirective;
use Keyway\Sso\Core\Port\ClockInterface;
use yii\web\Cookie;

/**
 * Turns a CookieDirective into the `yii\web\Cookie` the response understands.
 *
 * Six lines of mapping with three ways to be quietly wrong, which is exactly why they are here
 * and not inline in the controller:
 *
 *  1. `maxAge` (seconds from now) versus `expire` (an absolute timestamp). Yii wants the second,
 *     the core speaks the first, and a directive handed over with `expire = 600` is a cookie
 *     that expired in January 1970 - i.e. a login that starts unbound and fails at the callback
 *     with `binding_cookie_missing`, which looks like a proxy problem and is not one.
 *  2. A deletion has to repeat the ORIGINAL attributes (path, secure, sameSite). A browser keyed
 *     the cookie on those, so a deletion that drops them removes nothing and leaves a stale
 *     binding for the next login to trip over. CookieDirective carries the right ones already;
 *     this class must not "tidy" them.
 *  3. `expire = 1`, not `0`. Zero means "until the browser closes", which is a session cookie,
 *     not a deletion.
 *
 * WHAT THIS CLASS DELIBERATELY DOES NOT DO: touch the value. Craft runs with cookie validation
 * on, so Yii signs the value on the way out and strips the signature on the way in. That is
 * transparent as long as both halves go through the cookie collections - which is why the
 * controller reads the binding with `$request->getCookies()` and never from `$_COOKIE`.
 */
final class CraftCookie
{
    private function __construct()
    {
    }

    public static function from(CookieDirective $directive, ClockInterface $clock): Cookie
    {
        return new Cookie([
            'name' => $directive->name,
            'value' => $directive->value,
            'path' => $directive->path,
            'expire' => $directive->expiresAt($clock->now()),
            'secure' => $directive->secure,
            'httpOnly' => $directive->httpOnly,
            'sameSite' => $directive->sameSite,
        ]);
    }
}
