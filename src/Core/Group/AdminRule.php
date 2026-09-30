<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

use Keyway\Sso\Core\Support\Ascii;

/**
 * "Membership in IdP group X means Craft admin".
 *
 * A separate type from GroupRule on purpose. Granting admin is a privilege escalation driven by
 * data an external system sends us, so it must be impossible to configure by accident: it needs
 * its own rule object, its own list in GroupMap, and the GroupMap-level `allowAdminEscalation`
 * switch turned on. Two keys, both explicit.
 */
final class AdminRule
{
    public readonly GroupMatchType $matchType;
    public readonly string $pattern;

    public function __construct(GroupMatchType $matchType, string $pattern)
    {
        $pattern = Ascii::trim($pattern);
        GroupHandle::assertPattern($matchType, $pattern);

        $this->matchType = $matchType;
        $this->pattern = $pattern;
    }

    public static function exact(string $pattern): self
    {
        return new self(GroupMatchType::Exact, $pattern);
    }

    public static function prefix(string $pattern): self
    {
        return new self(GroupMatchType::Prefix, $pattern);
    }

    public static function suffix(string $pattern): self
    {
        return new self(GroupMatchType::Suffix, $pattern);
    }

    public function matches(string $idpGroup, bool $caseSensitive): bool
    {
        return GroupMatcher::matches($this->matchType, $this->pattern, $idpGroup, $caseSensitive);
    }
}
