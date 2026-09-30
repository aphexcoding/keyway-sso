<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\State;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Decides whether a post-login return URL may be followed.
 *
 * Open redirect is the classic hole in single sign-on: the return address travels through the
 * identity provider as RelayState / `state`, so anything that reaches it is attacker-reachable.
 * A crafted RelayState turns the customer's own login flow into a redirector to a phishing copy
 * of the control panel, and the user sees a legitimate domain on the way in.
 *
 * The guard is an allow list, not a block list. Relative paths starting with a single `/` are
 * accepted; absolute URLs only when their origin was explicitly configured (multi-site Craft).
 * Everything else - schemes, protocol-relative `//host`, backslashes, control characters - is
 * rejected without trying to be clever about it.
 */
final class RedirectGuard
{
    private const MAX_LENGTH = 2048;

    /** @var list<string> */
    private array $allowedOrigins;

    private string $defaultPath;

    /**
     * @param list<string> $allowedOrigins e.g. ['https://intranet.example.com']
     */
    public function __construct(array $allowedOrigins = [], string $defaultPath = '/')
    {
        $origins = [];
        foreach ($allowedOrigins as $origin) {
            $origin = Ascii::lower(Ascii::trim((string)$origin));
            $origin = rtrim($origin, '/');

            if ($origin === '') {
                continue;
            }

            if (preg_match('~^https?://[a-z0-9.\-]+(:[0-9]{1,5})?$~', $origin) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'Allowed origin "%s" must look like https://host[:port].',
                    $origin
                ));
            }

            if (!in_array($origin, $origins, true)) {
                $origins[] = $origin;
            }
        }

        $defaultPath = Ascii::trim($defaultPath);
        if ($defaultPath === '' || !self::isSafeRelativePath($defaultPath)) {
            throw new InvalidArgumentException(
                'The default redirect path must be a local path starting with a single "/".'
            );
        }

        $this->allowedOrigins = $origins;
        $this->defaultPath = $defaultPath;
    }

    public function defaultPath(): string
    {
        return $this->defaultPath;
    }

    /** @return list<string> */
    public function allowedOrigins(): array
    {
        return $this->allowedOrigins;
    }

    public function isSafe(?string $url): bool
    {
        if ($url === null) {
            return false;
        }

        // Only plain spaces are stripped. Ascii::trim() would also strip NUL/CR/LF/TAB, which
        // would quietly turn "/admin\0" into a value this method calls safe while the caller
        // still holds the original string - the guard must not create that gap.
        $url = trim($url, ' ');

        if ($url === '' || strlen($url) > self::MAX_LENGTH) {
            return false;
        }

        if (Ascii::hasControlCharacters($url)) {
            return false;
        }

        // Percent-encoded CR/LF/TAB/NUL: harmless in a path, but they are the payload of header
        // and log injection once the value is copied into a Location header.
        if (preg_match('/%(00|09|0a|0d)/i', $url) === 1) {
            return false;
        }

        // Browsers normalise backslash to slash, so "/\evil.com" is off-site.
        if (str_contains($url, '\\')) {
            return false;
        }

        if (str_starts_with($url, '/')) {
            return self::isSafeRelativePath($url);
        }

        return $this->matchesAllowedOrigin($url);
    }

    /**
     * Returns the URL when it is safe, otherwise the configured default path.
     */
    public function sanitize(?string $url): string
    {
        return $this->isSafe($url) ? trim((string)$url, ' ') : $this->defaultPath;
    }

    private static function isSafeRelativePath(string $url): bool
    {
        if (!str_starts_with($url, '/')) {
            return false;
        }

        // "//evil.com" and "/\evil.com" are both off-site despite starting with a slash.
        if (str_starts_with($url, '//')) {
            return false;
        }

        if (Ascii::hasControlCharacters($url) || str_contains($url, '\\')) {
            return false;
        }

        return true;
    }

    private function matchesAllowedOrigin(string $url): bool
    {
        if ($this->allowedOrigins === []) {
            return false;
        }

        foreach ($this->allowedOrigins as $origin) {
            $length = strlen($origin);

            if (strncasecmp($url, $origin, $length) !== 0) {
                continue;
            }

            // The character right after the origin decides whether this is really that origin.
            // "https://example.com.evil.com" and "https://example.com@evil.com" both share the
            // prefix; only "/", "?", "#" or end-of-string mean we are still on the same host.
            if (strlen($url) === $length) {
                return true;
            }

            $next = $url[$length];
            if ($next === '/' || $next === '?' || $next === '#') {
                return true;
            }
        }

        return false;
    }
}
