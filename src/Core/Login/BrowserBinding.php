<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use Keyway\Sso\Core\Port\RandomSourceInterface;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Ties a login in flight to the browser that started it.
 *
 * THE HOLE THIS CLOSES. The login state (Core\State\StateStore) is unguessable, single use and
 * bounded in time, and none of that helps against login-CSRF: there the attacker HOLDS a
 * perfectly valid token, because the attacker is the one who started the flow. RFC 6749 s10.12,
 * RFC 6819 s5.3.5 and OpenID Connect Core s15.5.2 all ask for `state` to be bound to the user
 * agent, and CraftStateStorage's docblock names this class as the missing half of that.
 *
 * HOW. At the start of a login we mint 32 random bytes, send them to the browser in a cookie and
 * keep only `sha256(secret)` in the state record. On the way back the cookie is compared with
 * `hash_equals()`. The secret never exists server-side in the clear, so a dump of the cache does
 * not let anyone forge a binding, and the token alone - lifted from a proxy log, a Referer
 * header or a shared screen - is no longer enough to complete the login.
 *
 * WHY THE ATTRIBUTES DIFFER PER PROTOCOL, AND WHY THAT IS NOT A DOUBLE STANDARD. The protection
 * is the same in both; only the cookie attributes change, because the callbacks are different
 * browser events (CallbackStyle). A SAML HTTP-POST callback is a cross-site POST, where a `Lax`
 * cookie is simply not sent - so the binding needs `SameSite=None`, which browsers accept only
 * with `Secure`. An OIDC callback is a top-level redirect, where `Lax` arrives normally and is
 * the stronger choice.
 *
 * THE HONEST LIMIT, stated here rather than discovered later: on a site served over plain HTTP,
 * a cross-site POST callback CANNOT be bound at all. `None` without `Secure` is discarded by
 * every current browser, and a cookie the browser throws away would give us a binding we
 * believe in and do not have. So on that combination we issue no binding - and we write that
 * decision into the state (MODE_UNBOUND), record a diagnostic event for it and warn on the
 * settings screen. A degradation nobody can see is worse than the degradation itself.
 *
 * THE RULE THAT MAKES ALL OF THIS WORK, and the one that is easy to get wrong: whether a login
 * is bound is decided WHEN THE STATE IS ISSUED and is written into the state. It is never
 * inferred at the callback from the fact that no cookie arrived. An implementation that infers
 * it has a protection with an off switch, and the switch is "send nothing".
 */
final class BrowserBinding
{
    /**
     * One name for both protocols. The attributes differ, the name does not: two names would
     * mean two cookies to reason about, two ways to leave one behind, and a callback that could
     * be satisfied by the wrong one.
     */
    public const COOKIE_NAME = 'CRAFT_KEYWAY_SSO_BINDING';

    public const CONTEXT_MODE = 'binding_mode';
    public const CONTEXT_HASH = 'binding';

    public const MODE_BOUND = 'bound';
    public const MODE_UNBOUND = 'unbound';

    /** Same size, and the same reasoning, as the state secret in StateStore. */
    private const SECRET_BYTES = 32;

    private RandomSourceInterface $random;

    public function __construct(RandomSourceInterface $random)
    {
        $this->random = $random;
    }

    /**
     * Mints a binding for a login that is about to start.
     *
     * @param string $callbackUrl The absolute URL the identity provider will return to - the ACS
     *                            URL or the OIDC redirect URI, straight from settings. Both the
     *                            cookie `Path` and the "is this HTTPS" decision come from it,
     *                            which keeps the runtime decision and the settings-screen
     *                            warning reading the same value.
     * @param int    $ttl         Seconds; match the login state's TTL so the cookie cannot
     *                            outlive the login it binds.
     */
    public function issue(string $callbackUrl, CallbackStyle $style, int $ttl): IssuedBinding
    {
        $secure = self::isHttps($callbackUrl);

        if ($style->requiresSecureTransport() && !$secure) {
            return IssuedBinding::unbound();
        }

        $secret = self::encode($this->random->bytes(self::SECRET_BYTES));

        return IssuedBinding::bound(
            new CookieDirective(
                self::COOKIE_NAME,
                $secret,
                self::pathOf($callbackUrl),
                max(1, $ttl),
                $secure,
                true,
                $style->sameSite()
            ),
            self::hash($secret)
        );
    }

    /**
     * Checks a returning login against the cookie the browser presented.
     *
     * @param array<string, string> $context        The consumed state's context.
     * @param string|null           $presentedSecret Cookie value, or null when none arrived.
     */
    public function verify(array $context, ?string $presentedSecret): BindingStatus
    {
        $mode = $context[self::CONTEXT_MODE] ?? '';

        if ($mode === self::MODE_UNBOUND) {
            return BindingStatus::NotIssued;
        }

        if ($mode !== self::MODE_BOUND) {
            return BindingStatus::Undeclared;
        }

        $expected = $context[self::CONTEXT_HASH] ?? '';
        if ($expected === '') {
            return BindingStatus::Inconsistent;
        }

        $presented = $presentedSecret === null ? '' : Ascii::trim($presentedSecret);
        if ($presented === '') {
            return BindingStatus::CookieMissing;
        }

        return hash_equals($expected, self::hash($presented))
            ? BindingStatus::Verified
            : BindingStatus::Mismatch;
    }

    /**
     * Removes the binding cookie once the round trip is over, successful or not.
     *
     * The cookie is worthless after the state is burnt, and a browser that keeps one around is
     * a browser that sends it on the next login, where it can only be wrong.
     */
    public function clear(string $callbackUrl, CallbackStyle $style): CookieDirective
    {
        $secure = self::isHttps($callbackUrl);

        return new CookieDirective(
            self::COOKIE_NAME,
            '',
            self::pathOf($callbackUrl),
            0,
            $secure,
            true,
            // A deletion must repeat the attributes of the cookie it deletes, or the browser
            // treats it as a different cookie and leaves the original in place. `None` still
            // needs `Secure`, so on plain HTTP we fall back to the attribute that is legal
            // there - and on plain HTTP nothing bound was ever set under `None` anyway.
            $secure ? $style->sameSite() : CallbackStyle::TopLevelRedirect->sameSite()
        );
    }

    public static function hash(string $secret): string
    {
        return hash('sha256', $secret);
    }

    private static function isHttps(string $url): bool
    {
        $scheme = parse_url(Ascii::trim($url), PHP_URL_SCHEME);

        return is_string($scheme) && Ascii::lower($scheme) === 'https';
    }

    /**
     * The callback's own path, so the cookie is not offered to every request on the site.
     *
     * A malformed or relative callback URL yields "/". That is deliberately the widest value:
     * a wrong narrow path would mean the cookie is never sent back and every login fails
     * closed on a configuration typo, which looks exactly like a security fault and is not one.
     */
    private static function pathOf(string $url): string
    {
        $path = parse_url(Ascii::trim($url), PHP_URL_PATH);

        if (!is_string($path) || $path === '' || !str_starts_with($path, '/')) {
            return '/';
        }

        // Second line of defence, and honestly labelled as one. PHP's own parse_url() already
        // replaces C0 control characters with "_" before we ever see the path - measured, not
        // assumed: parse_url("https://h/call\nback", PHP_URL_PATH) returns "/call_back" - so
        // this branch is not reachable through parse_url today. It stays because the invariant
        // that matters is "no control character reaches a Set-Cookie header", and that must not
        // depend on a detail of somebody else's URL parser.
        return Ascii::hasControlCharacters($path) ? '/' : $path;
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
