<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Group\GroupAssignment;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\DiagnosticsSinkInterface;
use Keyway\Sso\Core\Port\RandomSourceInterface;
use Keyway\Sso\Core\Provisioning\ProvisioningAction;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;

/**
 * Builds diagnostic events and hands them to the sink.
 *
 * Masking happens on the way in, not in the template: a panel that masks at render time leaks
 * the moment somebody adds an export button. The masking of the payload itself lives in
 * DiagnosticEvent's constructor, so an event built without this recorder is masked too; what
 * this class adds is the mapping/decision summary and the sink call.
 */
final class DiagnosticsRecorder
{
    private DiagnosticsSinkInterface $sink;
    private ClockInterface $clock;
    private RandomSourceInterface $random;

    public function __construct(
        DiagnosticsSinkInterface $sink,
        ClockInterface $clock,
        RandomSourceInterface $random
    ) {
        $this->sink = $sink;
        $this->clock = $clock;
        $this->random = $random;
    }

    /**
     * Records the outcome of a fully processed login attempt.
     */
    public function recordDecision(
        string $protocol,
        IdentityPayload $payload,
        ProvisioningDecision $decision
    ): DiagnosticEvent {
        $outcome = $decision->isDenied() ? LoginOutcome::Denied : LoginOutcome::Success;

        $event = new DiagnosticEvent(
            $this->nextId(),
            $this->clock->now(),
            $protocol,
            DiagnosticEvent::STAGE_PROVISIONING,
            $outcome,
            $decision->reasonCode,
            $decision->message,
            $payload->issuer(),
            $payload->nameId(),
            $payload->all(),
            $this->describeMapping($decision->attributes(), $decision->groups()),
            $this->describeDecision($decision)
        );

        $this->sink->record($event);

        return $event;
    }

    /**
     * Records that a session was actually started: the last row of a login that worked.
     *
     * recordDecision() is written when the provisioning policy ACCEPTS a login, which is before
     * the account is saved and before Craft starts a session - and either of those can still
     * fail (`user_not_saved`, `no_cp_access`). A panel whose only green row is the decision
     * therefore shows "success" next to the red row that says the person never got in. This is
     * the row that means what it says, and it is written only after the sign-in returned.
     *
     * `$issuer` and `$subject` so the row is found by the same search as the rest of the
     * attempt; the subject is masked by DiagnosticEvent like every other.
     */
    public function recordSignedIn(
        string $protocol,
        string $reasonCode,
        string $message,
        string $issuer = '',
        string $subject = '',
        ?int $userId = null
    ): DiagnosticEvent {
        $event = new DiagnosticEvent(
            $this->nextId(),
            $this->clock->now(),
            $protocol,
            DiagnosticEvent::STAGE_SESSION,
            LoginOutcome::Success,
            $reasonCode,
            $message,
            $issuer,
            $subject,
            [],
            [],
            ['userId' => $userId]
        );

        $this->sink->record($event);

        return $event;
    }

    /**
     * Records a failure before a decision could be made: bad signature, bad state, missing
     * required claim. `$payload` is optional because the earliest failures happen before there
     * is anything to show.
     */
    public function recordFailure(
        string $protocol,
        string $stage,
        string $reasonCode,
        string $message,
        ?IdentityPayload $payload = null,
        string $issuer = '',
        string $subject = ''
    ): DiagnosticEvent {
        // `$issuer`/`$subject` are for the one caller that has no payload but does know whose
        // attempt it was: the session stage, after the decision. Without them its red row
        // (`no_cp_access`, `user_not_saved`) is the only row of the attempt a search by subject
        // does not find - and it is the row that says the person never got in.
        $event = new DiagnosticEvent(
            $this->nextId(),
            $this->clock->now(),
            $protocol,
            $stage,
            LoginOutcome::Error,
            $reasonCode,
            $message,
            $payload?->issuer() ?? $issuer,
            $payload?->nameId() ?? $subject,
            $payload?->all() ?? []
        );

        $this->sink->record($event);

        return $event;
    }

    /**
     * Records something that did NOT stop the login but that an administrator should see.
     *
     * Separate from recordFailure() because the outcome is the whole point: a row marked Error
     * for a login that succeeded teaches the panel's reader to ignore errors, and a degradation
     * folded into the success row is a degradation nobody notices.
     */
    public function recordNotice(
        string $protocol,
        string $stage,
        string $reasonCode,
        string $message,
        ?IdentityPayload $payload = null
    ): DiagnosticEvent {
        $event = new DiagnosticEvent(
            $this->nextId(),
            $this->clock->now(),
            $protocol,
            $stage,
            LoginOutcome::Notice,
            $reasonCode,
            $message,
            $payload?->issuer() ?? '',
            $payload?->nameId() ?? '',
            $payload?->all() ?? []
        );

        $this->sink->record($event);

        return $event;
    }

    /**
     * @return array<string, mixed>
     */
    private function describeMapping(
        MappedAttributes $attributes,
        GroupAssignment $groups
    ): array {
        $fields = [];
        foreach ($attributes->toArray() as $target => $value) {
            $fields[$target] = Masker::maskValue($value);
        }

        return [
            'fields' => $fields,
            'skippedSources' => Masker::groupList($attributes->skipped()),
            'craftGroups' => Masker::groupList($groups->groups()),
            'matchedIdpGroups' => Masker::groupList($groups->matchedIdpGroups()),
            'unmatchedIdpGroups' => Masker::groupList($groups->unmatchedIdpGroups()),
            'usedDefaultGroup' => $groups->usedDefaultGroup(),
            'groupSyncMode' => $groups->syncMode()->value,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function describeDecision(ProvisioningDecision $decision): array
    {
        return [
            'action' => $decision->action->value,
            'willCreateUser' => $decision->action === ProvisioningAction::Create,
            'matchBy' => $decision->matchBy->value,
            'matchValue' => $decision->matchValue === null
                ? null
                : Masker::maskValue($decision->matchValue),
            'userId' => $decision->userId,
            'grantsAdmin' => $decision->groups()->grantsAdmin(),
            'adminRuleMatched' => $decision->groups()->adminRuleMatched(),
            'revokesAdmin' => $decision->groups()->revokesAdmin(),
        ];
    }

    private function nextId(): string
    {
        return bin2hex($this->random->bytes(8));
    }
}
