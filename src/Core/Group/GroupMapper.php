<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Turns the IdP's group claims into a GroupAssignment.
 */
final class GroupMapper
{
    private GroupMap $map;

    public function __construct(GroupMap $map)
    {
        $this->map = $map;
    }

    public function map(IdentityPayload $payload): GroupAssignment
    {
        return $this->mapGroups($this->collectIdpGroups($payload));
    }

    /**
     * @param list<string> $idpGroups
     */
    public function mapGroups(array $idpGroups): GroupAssignment
    {
        $caseSensitive = $this->map->isCaseSensitive();

        $groups = [];
        $matched = [];
        $unmatched = [];

        foreach ($idpGroups as $idpGroup) {
            $hit = false;

            foreach ($this->map->rules() as $rule) {
                if (!$rule->matches($idpGroup, $caseSensitive)) {
                    continue;
                }

                $hit = true;
                if (!in_array($rule->targetGroup, $groups, true)) {
                    $groups[] = $rule->targetGroup;
                }
            }

            if ($hit) {
                $matched[] = $idpGroup;
            } else {
                $unmatched[] = $idpGroup;
            }
        }

        $usedDefault = false;
        $defaultGroup = $this->map->defaultGroup();
        if ($groups === [] && $defaultGroup !== null) {
            $groups[] = $defaultGroup;
            $usedDefault = true;
        }

        $adminRuleMatched = $this->matchesAdminRule($idpGroups, $caseSensitive);
        $escalationAllowed = $this->map->allowsAdminEscalation();

        return new GroupAssignment(
            $groups,
            $matched,
            $unmatched,
            $escalationAllowed && $adminRuleMatched,
            $escalationAllowed && !$adminRuleMatched && $this->map->revokesAdminWhenUnmatched(),
            $usedDefault,
            $adminRuleMatched,
            $this->map->syncMode()
        );
    }

    /**
     * @param list<string> $idpGroups
     */
    private function matchesAdminRule(array $idpGroups, bool $caseSensitive): bool
    {
        foreach ($this->map->adminRules() as $rule) {
            foreach ($idpGroups as $idpGroup) {
                if ($rule->matches($idpGroup, $caseSensitive)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function collectIdpGroups(IdentityPayload $payload): array
    {
        $groups = [];

        foreach ($this->map->sourceAttributes() as $attribute) {
            foreach ($payload->values($attribute) as $value) {
                $value = Ascii::trim($value);
                if ($value !== '' && !in_array($value, $groups, true)) {
                    $groups[] = $value;
                }
            }
        }

        return $groups;
    }
}
