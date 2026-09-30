<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use InvalidArgumentException;

/**
 * "Set this cookie" as a value, not as an effect.
 *
 * The core decides what the cookie must look like; the Craft layer turns it into a
 * `yii\web\Cookie` and puts it on the response. That split is the same one ProvisioningDecision
 * makes for user writes, and it exists for the same reason: the attributes below are a security
 * decision (see CallbackStyle), and a security decision that can only be exercised by booting a
 * CMS is a security decision nobody re-tests.
 *
 * `$value` is the binding SECRET when this directive sets a cookie. It is short-lived, it never
 * goes anywhere near the state record - only its SHA-256 does - and it must never be logged.
 */
final class CookieDirective
{
    public readonly string $name;
    public readonly string $value;
    public readonly string $path;
    public readonly int $maxAge;
    public readonly bool $secure;
    public readonly bool $httpOnly;
    public readonly string $sameSite;

    public function __construct(
        string $name,
        string $value,
        string $path,
        int $maxAge,
        bool $secure,
        bool $httpOnly,
        string $sameSite
    ) {
        if ($name === '') {
            throw new InvalidArgumentException('A cookie directive needs a cookie name.');
        }

        if ($sameSite === 'None' && !$secure) {
            // Not a style rule. A browser drops this combination on the floor, so building one
            // would mean believing a login is bound when the cookie was never stored.
            throw new InvalidArgumentException(
                'SameSite=None requires Secure; a cookie with both would be discarded by the browser.'
            );
        }

        $this->name = $name;
        $this->value = $value;
        $this->path = $path === '' ? '/' : $path;
        $this->maxAge = $maxAge;
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
        $this->sameSite = $sameSite;
    }

    /**
     * True when this directive removes the cookie rather than setting one.
     */
    public function isDeletion(): bool
    {
        return $this->maxAge <= 0;
    }

    /**
     * Expiry as a Unix timestamp, which is what Yii's cookie wants.
     */
    public function expiresAt(int $now): int
    {
        return $this->isDeletion() ? 1 : $now + $this->maxAge;
    }
}
