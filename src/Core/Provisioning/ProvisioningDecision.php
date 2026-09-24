<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Group\GroupAssignment;

/**
 * What should happen with this login - as a value, not as an effect.
 *
 * The core decides; the Craft layer executes. Keeping the two apart is what lets the whole
 * provisioning policy be unit-tested without a database, and what lets the diagnostics panel
 * replay a decision and show the administrator the reason it was made.
 *
 * TWO AUDIENCES, TWO MESSAGES - do not mix them up:
 *
 *  - `$message` and `$reasonCode` are for the ADMINISTRATOR: the diagnostics panel, the log,
 *    a support ticket. They are deliberately specific and therefore say things like "a Craft
 *    account already exists for this identity" or "the matching account is an administrator
 *    account". **Never render `$message` to the person logging in.** The match key comes from
 *    the identity provider, so an attacker who can influence it would otherwise get a free
 *    account-enumeration oracle - and not just "does this account exist" but "is it an admin".
 *  - `publicMessage()` is for the PERSON LOGGING IN: one wording for every refusal, carrying no
 *    information about whether the account exists, what state it is in or who owns it.
 *
 * This mirrors IdentityReaderException, whose docblock says its message is safe to show to an
 * end user. This class says the opposite about `$message`, on purpose, and says it here so that
 * the Craft layer does not have to infer it.
 */
final class ProvisioningDecision
{
    public const DOMAIN_NOT_ALLOWED = 'domain_not_allowed';
    public const EMAIL_MISSING = 'email_missing';
    public const USERNAME_MISSING = 'username_missing';
    public const NO_GROUP_MATCH = 'no_group_match';
    public const JIT_DISABLED = 'jit_disabled';
    public const ACCOUNT_SUSPENDED = 'account_suspended';
    public const ACCOUNT_INACTIVE = 'account_inactive';
    public const ACCOUNT_LOCKED = 'account_locked';
    public const LINKING_DISABLED = 'linking_disabled';
    public const ADMIN_LINK_NOT_ALLOWED = 'admin_link_not_allowed';
    public const JIT_CREATE = 'jit_create';
    public const UPDATE_ON_LOGIN = 'update_on_login';
    public const EXISTING_UNCHANGED = 'existing_unchanged';

    /**
     * The only thing a refused visitor is ever told. One string for every denial reason: any
     * variation between reasons is itself the oracle we are closing.
     */
    public const PUBLIC_DENIED_MESSAGE = 'We could not sign you in with single sign-on. If you '
        . 'believe this is a mistake, ask the person who runs this site to check the single '
        . 'sign-on diagnostics.';

    private const PUBLIC_ALLOWED_MESSAGE = 'Signing you in.';

    public readonly ProvisioningAction $action;
    public readonly string $reasonCode;
    public readonly string $message;
    public readonly ?string $userId;
    public readonly ?string $matchValue;
    public readonly UserMatchKey $matchBy;

    private MappedAttributes $attributes;
    private GroupAssignment $groups;

    public function __construct(
        ProvisioningAction $action,
        string $reasonCode,
        string $message,
        MappedAttributes $attributes,
        GroupAssignment $groups,
        UserMatchKey $matchBy,
        ?string $matchValue = null,
        ?string $userId = null
    ) {
        $this->action = $action;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
        $this->attributes = $attributes;
        $this->groups = $groups;
        $this->matchBy = $matchBy;
        $this->matchValue = $matchValue;
        $this->userId = $userId;
    }

    public function isAllowed(): bool
    {
        return $this->action !== ProvisioningAction::Deny;
    }

    public function isDenied(): bool
    {
        return $this->action === ProvisioningAction::Deny;
    }

    /**
     * True when the Craft layer must write something (create or update).
     */
    public function writesUser(): bool
    {
        return $this->action === ProvisioningAction::Create
            || $this->action === ProvisioningAction::Update;
    }

    /**
     * True only when this decision MAKES the account, as opposed to writing to one that already
     * existed.
     *
     * Separate from writesUser() because the difference decides whether an identity link may be
     * recorded (Core\Login\IdentityLink): "we created this" is a fact about the account's
     * origin, while an Update may be a link the site owner switched on and can switch off again.
     */
    public function createsUser(): bool
    {
        return $this->action === ProvisioningAction::Create;
    }

    /**
     * Safe to show on the login screen. Deliberately free of anything the identity provider
     * could use to probe the user table: the same sentence for a blocked domain, a missing
     * group, an account that exists, an account that is suspended and an account that is an
     * administrator.
     */
    public function publicMessage(): string
    {
        return $this->isDenied() ? self::PUBLIC_DENIED_MESSAGE : self::PUBLIC_ALLOWED_MESSAGE;
    }

    public function attributes(): MappedAttributes
    {
        return $this->attributes;
    }

    public function groups(): GroupAssignment
    {
        return $this->groups;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'action' => $this->action->value,
            'reason' => $this->reasonCode,
            // Administrator-facing by contract; this array feeds the diagnostics panel, never
            // the login screen.
            'message' => $this->message,
            'matchBy' => $this->matchBy->value,
            'userId' => $this->userId,
            'groups' => $this->groups->toArray(),
            'fields' => array_keys($this->attributes->toArray()),
        ];
    }
}
