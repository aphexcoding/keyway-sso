<?php

declare(strict_types=1);

use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Test\Support\Assert;

return [
    'plain local paths are accepted' => static function (): void {
        $guard = new RedirectGuard();

        foreach ([
            '/',
            '/admin',
            '/admin/entries?section=blog&page=2',
            '/admin/entries#tab',
            '/admin/zażółć',
            '/admin/../dashboard',
        ] as $url) {
            Assert::true($guard->isSafe($url), $url);
        }
    },

    'off-site targets are rejected' => static function (): void {
        $guard = new RedirectGuard();

        foreach ([
            'https://evil.com',
            'http://evil.com/admin',
            '//evil.com',
            '///evil.com',
            '/\\evil.com',
            '\\\\evil.com',
            '/admin\\..\\evil',
            'javascript:alert(document.cookie)',
            'JaVaScRiPt:alert(1)',
            'data:text/html;base64,PHNjcmlwdD4=',
            'admin',
            'mailto:someone@example.com',
            '',
            '   ',
        ] as $url) {
            Assert::false($guard->isSafe($url), $url);
        }
    },

    'null is not a safe redirect' => static function (): void {
        Assert::false((new RedirectGuard())->isSafe(null));
    },

    'header injection payloads are rejected' => static function (): void {
        $guard = new RedirectGuard();

        foreach ([
            "/admin\r\nSet-Cookie: a=b",
            "/admin\nLocation: https://evil.com",
            "/admin\tx",
            "/admin\0",
            '/admin%0d%0aSet-Cookie:%20a=b',
            '/admin%0D%0ALocation:%20https://evil.com',
            '/admin%00',
            '/admin%09',
        ] as $url) {
            Assert::false($guard->isSafe($url), $url);
        }
    },

    'absurdly long targets are rejected' => static function (): void {
        $guard = new RedirectGuard();

        Assert::true($guard->isSafe('/' . str_repeat('a', 2000)));
        Assert::false($guard->isSafe('/' . str_repeat('a', 4000)));
    },

    'sanitize falls back to the default path' => static function (): void {
        $guard = new RedirectGuard([], '/admin');

        Assert::same('/admin', $guard->sanitize('https://evil.com'));
        Assert::same('/admin', $guard->sanitize(null));
        Assert::same('/admin', $guard->sanitize('//evil.com'));
        Assert::same('/admin/entries', $guard->sanitize(' /admin/entries '));
    },

    'an unsafe default path is rejected at construction' => static function (): void {
        Assert::throws(InvalidArgumentException::class, static fn () => new RedirectGuard([], 'https://evil.com'));
        Assert::throws(InvalidArgumentException::class, static fn () => new RedirectGuard([], '//evil.com'));
        Assert::throws(InvalidArgumentException::class, static fn () => new RedirectGuard([], ''));
    },

    'configured origins are accepted and look-alikes are not' => static function (): void {
        $guard = new RedirectGuard(['https://intranet.example.com']);

        Assert::true($guard->isSafe('https://intranet.example.com'));
        Assert::true($guard->isSafe('https://intranet.example.com/admin'));
        Assert::true($guard->isSafe('https://intranet.example.com?next=1'));
        Assert::true($guard->isSafe('https://intranet.example.com#top'));
        Assert::true($guard->isSafe('HTTPS://INTRANET.EXAMPLE.COM/admin'));

        foreach ([
            'https://intranet.example.com.evil.com/admin',
            'https://intranet.example.com@evil.com/admin',
            'https://intranet.example.commander/admin',
            'http://intranet.example.com/admin',
            'https://other.example.com/admin',
            'https://intranet.example.com:8443/admin',
        ] as $url) {
            Assert::false($guard->isSafe($url), $url);
        }
    },

    'an origin with an explicit port is honoured exactly' => static function (): void {
        $guard = new RedirectGuard(['https://intranet.example.com:8443/']);

        Assert::sameList(['https://intranet.example.com:8443'], $guard->allowedOrigins());
        Assert::true($guard->isSafe('https://intranet.example.com:8443/admin'));
        Assert::false($guard->isSafe('https://intranet.example.com/admin'));
    },

    'malformed origins are rejected at construction' => static function (): void {
        foreach ([
            ['evil.com'],
            ['ftp://example.com'],
            ['https://example.com/admin'],
            ['https://user:pass@example.com'],
            ['https://*.example.com'],
        ] as $origins) {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new RedirectGuard($origins),
                json_encode($origins)
            );
        }
    },

    'without configured origins no absolute URL is safe' => static function (): void {
        $guard = new RedirectGuard();

        Assert::sameList([], $guard->allowedOrigins());
        Assert::false($guard->isSafe('https://intranet.example.com/admin'));
    },

    'a backslash inside an allowed origin URL is still rejected' => static function (): void {
        $guard = new RedirectGuard(['https://intranet.example.com']);

        foreach ([
            'https://intranet.example.com/admin\\..\\evil',
            'https://intranet.example.com/\\evil.com',
            'https://intranet.example.com?next=\\evil',
        ] as $url) {
            Assert::false($guard->isSafe($url), $url);
        }
    },

    'control characters inside an allowed origin URL are still rejected' => static function (): void {
        $guard = new RedirectGuard(['https://intranet.example.com']);

        foreach ([
            "https://intranet.example.com/admin\r\nSet-Cookie: a=b",
            "https://intranet.example.com/admin\tx",
            "https://intranet.example.com/admin\0",
        ] as $url) {
            Assert::false($guard->isSafe($url), $url);
        }
    },
];
