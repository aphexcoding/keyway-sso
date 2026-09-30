<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

use Keyway\Sso\Core\Support\Ascii;

final class GroupMatcher
{
    private function __construct()
    {
    }

    public static function matches(
        GroupMatchType $type,
        string $pattern,
        string $subject,
        bool $caseSensitive
    ): bool {
        $subject = Ascii::trim($subject);

        if ($subject === '' || $pattern === '') {
            return false;
        }

        if (!$caseSensitive) {
            $pattern = Ascii::lower($pattern);
            $subject = Ascii::lower($subject);
        }

        return match ($type) {
            GroupMatchType::Exact => $pattern === $subject,
            GroupMatchType::Prefix => str_starts_with($subject, $pattern),
            GroupMatchType::Suffix => str_ends_with($subject, $pattern),
        };
    }
}
