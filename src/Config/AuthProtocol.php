<?php

declare(strict_types=1);

namespace Keyway\Sso\Config;

/**
 * Which protocol this installation signs people in with.
 *
 * `Disabled` is the default and it is not a placeholder: a freshly installed plugin must not
 * change the login screen at all until somebody has finished configuring an identity provider.
 * Anything else would mean that `composer require` alone can put a half-configured SSO button
 * in front of a working site.
 *
 * One protocol at a time, on purpose. Two live connections would mean two answers to "who is
 * the issuer we trust", and the settings screen is not the place to introduce that ambiguity;
 * a second connection is a feature with its own data model, not a checkbox.
 */
enum AuthProtocol: string
{
    case Disabled = 'disabled';
    case Saml = 'saml';
    case Oidc = 'oidc';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn(self $case): string => $case->value, self::cases());
    }

    /**
     * Unknown or empty input collapses to `Disabled` rather than throwing.
     *
     * This is read while rendering the login screen. A settings row that somebody hand-edited
     * in project config must leave the site with password login, not with a fatal error on the
     * page people use to get in.
     */
    public static function fromValue(mixed $value): self
    {
        if ($value instanceof self) {
            return $value;
        }

        if (!is_string($value)) {
            return self::Disabled;
        }

        return self::tryFrom(strtolower(trim($value))) ?? self::Disabled;
    }

    public function isEnabled(): bool
    {
        return $this !== self::Disabled;
    }
}
