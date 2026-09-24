<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

use Keyway\Sso\Core\Support\Ascii;

/**
 * "IdP group X -> Craft user group Y".
 */
final class GroupRule
{
    public readonly GroupMatchType $matchType;
    public readonly string $pattern;
    public readonly string $targetGroup;

    public function __construct(GroupMatchType $matchType, string $pattern, string $targetGroup)
    {
        $pattern = Ascii::trim($pattern);
        $targetGroup = Ascii::trim($targetGroup);

        GroupHandle::assertPattern($matchType, $pattern);
        GroupHandle::assertValid($targetGroup);

        $this->matchType = $matchType;
        $this->pattern = $pattern;
        $this->targetGroup = $targetGroup;
    }

    public static function exact(string $pattern, string $targetGroup): self
    {
        return new self(GroupMatchType::Exact, $pattern, $targetGroup);
    }

    public static function prefix(string $pattern, string $targetGroup): self
    {
        return new self(GroupMatchType::Prefix, $pattern, $targetGroup);
    }

    public static function suffix(string $pattern, string $targetGroup): self
    {
        return new self(GroupMatchType::Suffix, $pattern, $targetGroup);
    }

    public function matches(string $idpGroup, bool $caseSensitive): bool
    {
        return GroupMatcher::matches($this->matchType, $this->pattern, $idpGroup, $caseSensitive);
    }
}
