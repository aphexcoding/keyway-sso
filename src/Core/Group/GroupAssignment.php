<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

/**
 * Outcome of group mapping: what the Craft layer should do, and why.
 *
 * Immutable and inert - it describes an intent. Nothing here has been applied to a user yet.
 */
final class GroupAssignment
{
    /** @var list<string> */
    private array $groups;

    /** @var list<string> */
    private array $matchedIdpGroups;

    /** @var list<string> */
    private array $unmatchedIdpGroups;

    private bool $grantsAdmin;
    private bool $revokesAdmin;
    private bool $usedDefaultGroup;
    private bool $adminRuleMatched;
    private GroupSyncMode $syncMode;

    /**
     * @param list<string> $groups
     * @param list<string> $matchedIdpGroups
     * @param list<string> $unmatchedIdpGroups
     */
    public function __construct(
        array $groups,
        array $matchedIdpGroups,
        array $unmatchedIdpGroups,
        bool $grantsAdmin,
        bool $revokesAdmin,
        bool $usedDefaultGroup,
        bool $adminRuleMatched,
        GroupSyncMode $syncMode
    ) {
        $this->groups = array_values($groups);
        $this->matchedIdpGroups = array_values($matchedIdpGroups);
        $this->unmatchedIdpGroups = array_values($unmatchedIdpGroups);
        $this->grantsAdmin = $grantsAdmin;
        $this->revokesAdmin = $revokesAdmin;
        $this->usedDefaultGroup = $usedDefaultGroup;
        $this->adminRuleMatched = $adminRuleMatched;
        $this->syncMode = $syncMode;
    }

    /** @return list<string> Craft group handles. */
    public function groups(): array
    {
        return $this->groups;
    }

    /** @return list<string> */
    public function matchedIdpGroups(): array
    {
        return $this->matchedIdpGroups;
    }

    /** @return list<string> */
    public function unmatchedIdpGroups(): array
    {
        return $this->unmatchedIdpGroups;
    }

    /**
     * True only when an admin rule matched AND admin escalation is enabled on the map.
     */
    public function grantsAdmin(): bool
    {
        return $this->grantsAdmin;
    }

    /**
     * True when the Craft layer should take admin away. Off unless explicitly configured -
     * demoting by default would let an IdP outage strip the site owner of their own panel.
     */
    public function revokesAdmin(): bool
    {
        return $this->revokesAdmin;
    }

    /**
     * True when an admin rule matched, regardless of the escalation switch. Diagnostics use it
     * to explain "your rule matched but escalation is off".
     */
    public function adminRuleMatched(): bool
    {
        return $this->adminRuleMatched;
    }

    public function usedDefaultGroup(): bool
    {
        return $this->usedDefaultGroup;
    }

    public function syncMode(): GroupSyncMode
    {
        return $this->syncMode;
    }

    public function hasRuleMatch(): bool
    {
        return $this->matchedIdpGroups !== [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'groups' => $this->groups,
            'matched' => $this->matchedIdpGroups,
            'unmatched' => $this->unmatchedIdpGroups,
            'grantsAdmin' => $this->grantsAdmin,
            'revokesAdmin' => $this->revokesAdmin,
            'adminRuleMatched' => $this->adminRuleMatched,
            'usedDefaultGroup' => $this->usedDefaultGroup,
            'syncMode' => $this->syncMode->value,
        ];
    }
}
