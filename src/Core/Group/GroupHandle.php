<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

final class GroupHandle
{
    private function __construct()
    {
    }

    public static function assertValid(string $handle): void
    {
        if (preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/', $handle) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Craft user group handle "%s" is invalid: use a letter followed by letters, '
                . 'digits or underscores (max 64 characters).',
                $handle
            ));
        }
    }

    public static function assertPattern(GroupMatchType $type, string $pattern): void
    {
        $pattern = Ascii::trim($pattern);

        if ($pattern === '') {
            throw new InvalidArgumentException(
                'Group match pattern must not be empty: an empty prefix or suffix matches '
                . 'every group the identity provider sends.'
            );
        }

        if ($type !== GroupMatchType::Exact && strlen($pattern) < 2) {
            throw new InvalidArgumentException(sprintf(
                'Prefix/suffix pattern "%s" is too short to be a meaningful filter '
                . '(minimum 2 characters).',
                $pattern
            ));
        }
    }
}
