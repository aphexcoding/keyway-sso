<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Group mapping configuration for one connection.
 */
final class GroupMap
{
    /** @var list<GroupRule> */
    private array $rules;

    /** @var list<AdminRule> */
    private array $adminRules;

    private ?string $defaultGroup;

    /** @var list<string> */
    private array $sourceAttributes;

    private GroupSyncMode $syncMode;
    private bool $caseSensitive;
    private bool $allowAdminEscalation;
    private bool $revokeAdminWhenUnmatched;

    /**
     * @param list<GroupRule> $rules
     * @param list<AdminRule> $adminRules
     * @param list<string> $sourceAttributes IdP attributes carrying group membership.
     */
    public function __construct(
        array $rules = [],
        array $adminRules = [],
        ?string $defaultGroup = null,
        GroupSyncMode $syncMode = GroupSyncMode::Append,
        bool $caseSensitive = false,
        bool $allowAdminEscalation = false,
        bool $revokeAdminWhenUnmatched = false,
        array $sourceAttributes = ['groups']
    ) {
        foreach ($rules as $rule) {
            if (!$rule instanceof GroupRule) {
                throw new InvalidArgumentException('GroupMap rules must be GroupRule objects.');
            }
        }

        foreach ($adminRules as $rule) {
            if (!$rule instanceof AdminRule) {
                throw new InvalidArgumentException(
                    'Admin rules must be AdminRule objects; a GroupRule cannot grant admin.'
                );
            }
        }

        if ($defaultGroup !== null) {
            $defaultGroup = Ascii::trim($defaultGroup);
            if ($defaultGroup === '') {
                $defaultGroup = null;
            } else {
                GroupHandle::assertValid($defaultGroup);
            }
        }

        $sources = [];
        foreach ($sourceAttributes as $attribute) {
            $attribute = Ascii::trim((string)$attribute);
            if ($attribute !== '' && !in_array($attribute, $sources, true)) {
                $sources[] = $attribute;
            }
        }

        if ($sources === []) {
            throw new InvalidArgumentException(
                'At least one source attribute is required for group mapping.'
            );
        }

        if ($revokeAdminWhenUnmatched && !$allowAdminEscalation) {
            throw new InvalidArgumentException(
                'Revoking admin on unmatched logins only makes sense together with admin '
                . 'escalation; otherwise the plugin would remove admins it never granted.'
            );
        }

        $this->rules = array_values($rules);
        $this->adminRules = array_values($adminRules);
        $this->defaultGroup = $defaultGroup;
        $this->syncMode = $syncMode;
        $this->caseSensitive = $caseSensitive;
        $this->allowAdminEscalation = $allowAdminEscalation;
        $this->revokeAdminWhenUnmatched = $revokeAdminWhenUnmatched;
        $this->sourceAttributes = $sources;
    }

    /** @return list<GroupRule> */
    public function rules(): array
    {
        return $this->rules;
    }

    /** @return list<AdminRule> */
    public function adminRules(): array
    {
        return $this->adminRules;
    }

    public function defaultGroup(): ?string
    {
        return $this->defaultGroup;
    }

    /** @return list<string> */
    public function sourceAttributes(): array
    {
        return $this->sourceAttributes;
    }

    public function syncMode(): GroupSyncMode
    {
        return $this->syncMode;
    }

    public function isCaseSensitive(): bool
    {
        return $this->caseSensitive;
    }

    public function allowsAdminEscalation(): bool
    {
        return $this->allowAdminEscalation;
    }

    public function revokesAdminWhenUnmatched(): bool
    {
        return $this->revokeAdminWhenUnmatched;
    }
}
