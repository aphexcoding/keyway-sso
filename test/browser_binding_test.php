<?php

declare(strict_types=1);

use Keyway\Sso\Core\Login\BindingStatus;
use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Core\Login\CookieDirective;
use Keyway\Sso\Core\Support\Ascii;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * The browser binding: the half of state handling that the specifications ask for and that an
 * unguessable token does not provide.
 *
 * What is actually being pinned here, in order of how much a regression would cost:
 *
 *  1. The secret never reaches the server side in the clear. Only its SHA-256 goes into the
 *     state context, and the comparison is constant time.
 *  2. "No binding was issued" is a WORD in the state, not the absence of one. Every case below
 *     that distinguishes Undeclared from NotIssued exists because inferring "unbound" from a
 *     missing value gives an attacker an off switch operated by sending nothing.
 *  3. The cookie attributes follow the callback STYLE, not the protocol name, and the one
 *     combination browsers discard (SameSite=None without Secure) cannot be constructed at all.
 *
 * No vendor directory needed: this is Core.
 */
$binding = static fn (): BrowserBinding => new BrowserBinding(new SequenceRandomSource());

$https = 'https://site.example.com/actions/keyway-sso/sso/callback';
$http = 'http://site.example.com/actions/keyway-sso/sso/callback';

return [
    'a SAML-style binding over HTTPS is None + Secure + HttpOnly on the callback path'
        => static function () use ($binding, $https): void {
            $issued = $binding()->issue($https, CallbackStyle::CrossSitePost, 300);

            Assert::true($issued->bound);
            $cookie = $issued->cookie;
            Assert::notNull($cookie);
            /** @var CookieDirective $cookie */
            Assert::same('None', $cookie->sameSite, 'a cross-site POST withholds Lax cookies');
            Assert::true($cookie->secure);
            Assert::true($cookie->httpOnly);
            Assert::same('/actions/keyway-sso/sso/callback', $cookie->path);
            Assert::same(300, $cookie->maxAge);
            Assert::same(BrowserBinding::COOKIE_NAME, $cookie->name);
        },

    'an OIDC-style binding is Lax, because a top-level redirect carries Lax cookies'
        => static function () use ($binding, $https): void {
            $cookie = $binding()->issue($https, CallbackStyle::TopLevelRedirect, 300)->cookie;

            Assert::notNull($cookie);
            /** @var CookieDirective $cookie */
            Assert::same('Lax', $cookie->sameSite);
            Assert::true($cookie->secure);
        },

    // The degradation decision O6 accepts, and the reason it is written down rather than felt.
    'a cross-site POST callback on plain HTTP cannot be bound, and says so in the state'
        => static function () use ($binding, $http): void {
            $issued = $binding()->issue($http, CallbackStyle::CrossSitePost, 300);

            Assert::false($issued->bound);
            Assert::null($issued->cookie);
            Assert::same(
                [BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND],
                $issued->context(),
                'the state must carry the word "unbound", not an absence'
            );
        },

    'a top-level redirect on plain HTTP is still bound, just without Secure'
        => static function () use ($binding, $http): void {
            $issued = $binding()->issue($http, CallbackStyle::TopLevelRedirect, 300);

            Assert::true($issued->bound, 'Lax needs no Secure, so there is protection to be had');
            Assert::false($issued->cookie?->secure ?? true);
            Assert::same('Lax', $issued->cookie?->sameSite);
        },

    'the state carries the hash and never the secret' => static function () use ($binding, $https): void {
        $issued = $binding()->issue($https, CallbackStyle::CrossSitePost, 300);
        $secret = (string)$issued->cookie?->value;
        $context = $issued->context();

        Assert::same(BrowserBinding::MODE_BOUND, $context[BrowserBinding::CONTEXT_MODE]);
        Assert::same(hash('sha256', $secret), $context[BrowserBinding::CONTEXT_HASH]);
        Assert::notSame($secret, $context[BrowserBinding::CONTEXT_HASH]);
        Assert::same(64, strlen($context[BrowserBinding::CONTEXT_HASH]));
        Assert::notContains($secret, json_encode($context, JSON_THROW_ON_ERROR));
    },

    'the secret is at least 32 bytes of entropy' => static function () use ($binding, $https): void {
        $secret = (string)$binding()->issue($https, CallbackStyle::CrossSitePost, 300)->cookie?->value;

        // base64url of 32 bytes, unpadded.
        Assert::same(43, strlen($secret));
        Assert::same(1, preg_match('/^[A-Za-z0-9_-]+$/', $secret), 'cookie-safe alphabet');
    },

    'two logins get two different secrets' => static function () use ($https): void {
        $binding = new BrowserBinding(new SequenceRandomSource());

        $first = $binding->issue($https, CallbackStyle::CrossSitePost, 300);
        $second = $binding->issue($https, CallbackStyle::CrossSitePost, 300);

        Assert::notSame($first->cookie?->value, $second->cookie?->value);
        Assert::notSame(
            $first->context()[BrowserBinding::CONTEXT_HASH],
            $second->context()[BrowserBinding::CONTEXT_HASH]
        );
    },

    'the matching cookie verifies' => static function () use ($binding, $https): void {
        $subject = $binding();
        $issued = $subject->issue($https, CallbackStyle::CrossSitePost, 300);

        Assert::same(
            BindingStatus::Verified,
            $subject->verify($issued->context(), $issued->cookie?->value)
        );
    },

    'another login\'s cookie is a mismatch, not a pass' => static function () use ($https): void {
        $subject = new BrowserBinding(new SequenceRandomSource());
        $mine = $subject->issue($https, CallbackStyle::CrossSitePost, 300);
        $theirs = $subject->issue($https, CallbackStyle::CrossSitePost, 300);

        Assert::same(
            BindingStatus::Mismatch,
            $subject->verify($mine->context(), $theirs->cookie?->value)
        );
    },

    // The core of decision O6: these two cases must never collapse into each other.
    'a bound login with no cookie is refused, and a distinct case from an unbound one'
        => static function () use ($binding, $https): void {
            $subject = $binding();
            $bound = $subject->issue($https, CallbackStyle::CrossSitePost, 300)->context();
            $unbound = [BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND];

            Assert::same(BindingStatus::CookieMissing, $subject->verify($bound, null));
            Assert::same(BindingStatus::CookieMissing, $subject->verify($bound, ''));
            Assert::same(BindingStatus::CookieMissing, $subject->verify($bound, "  \t "));

            Assert::same(BindingStatus::NotIssued, $subject->verify($unbound, null));
            Assert::true(BindingStatus::NotIssued->allowsLogin());
            Assert::false(BindingStatus::CookieMissing->allowsLogin());
        },

    'the attacker cannot switch the check off by sending nothing' => static function () use ($binding, $https): void {
        $subject = $binding();
        $bound = $subject->issue($https, CallbackStyle::CrossSitePost, 300)->context();

        // Sending no cookie at all is the whole attack. It must not read as "this login was
        // never bound", which is what a check driven by the presence of the hash would do.
        Assert::false($subject->verify($bound, null)->allowsLogin());
    },

    'a state with no binding decision at all is refused' => static function () use ($binding): void {
        $subject = $binding();

        Assert::same(BindingStatus::Undeclared, $subject->verify([], null));
        Assert::same(BindingStatus::Undeclared, $subject->verify(['connection' => 'oidc'], 'anything'));
        Assert::same(BindingStatus::Undeclared, $subject->verify([BrowserBinding::CONTEXT_MODE => ''], 'x'));
        Assert::same(
            BindingStatus::Undeclared,
            $subject->verify([BrowserBinding::CONTEXT_MODE => 'yes'], 'x'),
            'an unknown mode is not a licence'
        );
    },

    'a hash-only state - mode lost, hash kept - is refused as inconsistent'
        => static function () use ($binding): void {
            $subject = $binding();

            Assert::same(
                BindingStatus::Undeclared,
                $subject->verify([BrowserBinding::CONTEXT_HASH => hash('sha256', 'x')], 'x')
            );
            Assert::same(
                BindingStatus::Inconsistent,
                $subject->verify([BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_BOUND], 'x')
            );
            Assert::same(
                BindingStatus::Inconsistent,
                $subject->verify([
                    BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_BOUND,
                    BrowserBinding::CONTEXT_HASH => '',
                ], 'x')
            );
        },

    'the cookie the browser sends is hashed before comparison, never used raw'
        => static function () use ($binding, $https): void {
            $subject = $binding();
            $issued = $subject->issue($https, CallbackStyle::CrossSitePost, 300);
            $hash = $issued->context()[BrowserBinding::CONTEXT_HASH];

            // Presenting the stored hash itself must fail: it is what a cache dump leaks, and a
            // comparison done the wrong way round would accept it.
            Assert::same(BindingStatus::Mismatch, $subject->verify($issued->context(), $hash));
        },

    'clearing repeats the attributes, so the browser drops the right cookie'
        => static function () use ($binding, $https, $http): void {
            $subject = $binding();

            $secure = $subject->clear($https, CallbackStyle::CrossSitePost);
            Assert::true($secure->isDeletion());
            Assert::same('', $secure->value);
            Assert::same('None', $secure->sameSite);
            Assert::true($secure->secure);
            Assert::same('/actions/keyway-sso/sso/callback', $secure->path);
            Assert::same(1, $secure->expiresAt(1_000_000), 'an expiry in the past');

            // On plain HTTP nothing was ever set under None, and None without Secure cannot be
            // emitted, so the deletion falls back to the attribute that is legal there.
            $plain = $subject->clear($http, CallbackStyle::CrossSitePost);
            Assert::same('Lax', $plain->sameSite);
            Assert::false($plain->secure);
        },

    'a cookie browsers would discard cannot be built' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new CookieDirective('x', 'v', '/', 300, false, true, 'None'),
            'SameSite=None without Secure is dropped by the browser'
        );
    },

    'a malformed callback URL widens the cookie path instead of narrowing it'
        => static function () use ($binding): void {
            $subject = $binding();

            foreach (['', 'not a url', 'https://site.example.com', 'https://site.example.com?a=b'] as $url) {
                $cookie = $subject->issue($url, CallbackStyle::TopLevelRedirect, 300)->cookie;
                Assert::same('/', $cookie?->path, 'configuration typo must not look like an attack');
            }
        },

    // Pins the invariant, not the mechanism. It turned out that PHP's parse_url() already
    // replaces control characters with "_", so the guard inside BrowserBinding is a second line
    // of defence rather than the first - which is worth knowing, and worth not depending on.
    'a control character in the path never reaches a Set-Cookie header'
        => static function () use ($binding): void {
            foreach (["https://site.example.com/call\nback", "https://site.example.com/a\rb\x00c"] as $url) {
                $path = (string)$binding()->issue($url, CallbackStyle::TopLevelRedirect, 300)->cookie?->path;

                Assert::false(Ascii::hasControlCharacters($path), 'no header injection via the path');
                Assert::true(str_starts_with($path, '/'));
            }
        },

    'the style, not the protocol name, decides the attributes' => static function (): void {
        Assert::same('None', CallbackStyle::CrossSitePost->sameSite());
        Assert::same('Lax', CallbackStyle::TopLevelRedirect->sameSite());
        Assert::true(CallbackStyle::CrossSitePost->requiresSecureTransport());
        Assert::false(CallbackStyle::TopLevelRedirect->requiresSecureTransport());
    },

    'a zero or negative TTL still produces a cookie that exists' => static function () use ($binding, $https): void {
        $cookie = $binding()->issue($https, CallbackStyle::CrossSitePost, 0)->cookie;

        Assert::same(1, $cookie?->maxAge, 'a session-length binding beats an immediate deletion');
        Assert::false($cookie?->isDeletion() ?? true);
    },
];
