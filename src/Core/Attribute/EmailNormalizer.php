<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use Keyway\Sso\Core\Support\Ascii;

/**
 * E-mail normalisation without ext-mbstring.
 *
 * Both parts are lower-cased. The domain must be, per RFC 1035. The local part is
 * case-sensitive on paper, but every IdP in scope (Okta, Entra ID, Keycloak, Google) treats it
 * as case-insensitive, and *not* folding it would let the same person be provisioned twice -
 * once as `Jan.Kowalski@x.com`, once as `jan.kowalski@x.com` - each with their own Craft
 * account and group set. Duplicate accounts are the worse failure for an SSO plugin, so we fold.
 */
final class EmailNormalizer
{
    private function __construct()
    {
    }

    public static function normalize(string $email): string
    {
        return Ascii::lower(Ascii::trim($email));
    }

    public static function isValid(string $email): bool
    {
        if ($email === '' || Ascii::hasControlCharacters($email)) {
            return false;
        }

        if (strlen($email) > 254) {
            return false;
        }

        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Domain part, lower-cased, or null when the address has no usable domain.
     */
    public static function domain(string $email): ?string
    {
        $at = strrpos($email, '@');
        if ($at === false) {
            return null;
        }

        $domain = Ascii::lower(substr($email, $at + 1));

        return $domain === '' ? null : $domain;
    }
}
