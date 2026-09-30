<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Which user fields an attribute rule may write to.
 *
 * ALLOW LIST, NOT DENY LIST - and the difference is the whole point. Attribute mapping is
 * configured by a site administrator but *fed* by whatever the identity provider sends, so the
 * set of writable fields has to be closed by default. The earlier version of this class kept a
 * deny list, which meant every Craft property nobody had thought of was writable: `enabled`
 * (a deliberately disabled account comes back to life from an IdP attribute),
 * `invalidLoginCount` and `lockoutDate` (an attribute value resets the brute-force counter),
 * `archived`, `currentPassword`. None of those were on the list, all of them were accepted.
 *
 * Writable targets are therefore exactly:
 *  - the five identity fields below (e-mail, username, first/last/full name), and
 *  - custom Craft fields, addressed as `field:<handle>`, which live on the user's own field
 *    layout and cannot grant access by construction.
 *
 * Admin status keeps its single route into this plugin: an explicit AdminRule in GroupMap,
 * guarded by its own opt-in flag. FORBIDDEN survives only so that the most likely mistakes get
 * an error message that explains itself instead of the generic "unknown field".
 */
final class UserField
{
    public const EMAIL = 'email';
    public const USERNAME = 'username';
    public const FIRST_NAME = 'firstName';
    public const LAST_NAME = 'lastName';
    public const FULL_NAME = 'fullName';

    public const CUSTOM_PREFIX = 'field:';

    /**
     * Every built-in field an attribute rule may write, in canonical spelling.
     *
     * @var list<string>
     */
    private const ALLOWED = [
        self::EMAIL,
        self::USERNAME,
        self::FIRST_NAME,
        self::LAST_NAME,
        self::FULL_NAME,
    ];

    /**
     * Not a security control any more - the allow list is. This is a better error message for
     * the targets an administrator is most likely to reach for, each of which would hand the
     * identity provider control over access, account state or the brute-force counter.
     *
     * @var list<string>
     */
    private const FORBIDDEN = [
        'admin',
        'id',
        'uid',
        'groups',
        'grouphandles',
        'permissions',
        'password',
        'newpassword',
        'currentpassword',
        'passwordresetrequired',
        'suspended',
        'locked',
        'pending',
        'active',
        'enabled',
        'archived',
        'invalidlogincount',
        'lockoutdate',
        'authkey',
        'verificationcode',
        'unverifiedemail',
        'lastlogindate',
    ];

    private function __construct()
    {
    }

    /**
     * @throws InvalidArgumentException when the target is not a legal mapping destination.
     */
    public static function assertWritable(string $target): void
    {
        self::canonical($target);
    }

    /**
     * The canonical spelling of a writable target, or an exception.
     *
     * Canonicalising rather than merely accepting matters: a rule written as `Email` used to be
     * accepted and then stored under a key nothing reads, so the mapping silently did nothing.
     * Now it is stored as `email`.
     *
     * @throws InvalidArgumentException when the target is not a legal mapping destination.
     */
    public static function canonical(string $target): string
    {
        $target = Ascii::trim($target);

        if ($target === '') {
            throw new InvalidArgumentException('Mapping target must not be empty.');
        }

        if (str_starts_with(Ascii::lower($target), self::CUSTOM_PREFIX)) {
            $handle = substr($target, strlen(self::CUSTOM_PREFIX));
            if (preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/', $handle) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'Custom field handle "%s" is not a valid Craft field handle.',
                    $handle
                ));
            }

            return self::CUSTOM_PREFIX . $handle;
        }

        $lowered = Ascii::lower($target);

        foreach (self::ALLOWED as $allowed) {
            if ($lowered === Ascii::lower($allowed)) {
                return $allowed;
            }
        }

        if (in_array($lowered, self::FORBIDDEN, true)) {
            throw new InvalidArgumentException(sprintf(
                'Mapping to "%s" is not allowed: account state and access-granting user '
                . 'properties cannot be driven by identity provider attributes.',
                $target
            ));
        }

        throw new InvalidArgumentException(sprintf(
            'Mapping target "%s" is not a writable user field. Allowed: %s, or a custom field '
            . 'as "%s<handle>".',
            $target,
            implode(', ', self::ALLOWED),
            self::CUSTOM_PREFIX
        ));
    }

    /**
     * @return list<string>
     */
    public static function allowed(): array
    {
        return self::ALLOWED;
    }

    public static function isWritable(string $target): bool
    {
        try {
            self::canonical($target);
        } catch (InvalidArgumentException) {
            return false;
        }

        return true;
    }

    public static function isCustom(string $target): bool
    {
        return str_starts_with(Ascii::lower($target), self::CUSTOM_PREFIX);
    }
}
