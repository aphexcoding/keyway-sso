<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

use Keyway\Sso\Core\Support\Ascii;

/**
 * One row of the diagnostics panel: what arrived, what it mapped to, what was decided, why.
 *
 * Immutable, masked, safe to persist and to show. The masking happens HERE, in the constructor,
 * which is the difference between a guarantee and a convention: the previous version relied on
 * DiagnosticsRecorder doing it on the way in, so an event built anywhere else - the Craft layer,
 * a migration, a future contributor holding a raw assertion - serialised that assertion straight
 * into the stored row, while this docblock claimed it could not happen. Now there is no way to
 * construct an unmasked event:
 *
 *  - `subject` is masked (partial, still recognisable);
 *  - `attributes` go through the attribute masker, credential-name deny list included;
 *  - `mapping` and `decision` are scrubbed structurally and bounded;
 *  - `message` and `issuer` are length-capped.
 *
 * The panel still shows what support needs: claim names in full, group names in full, the
 * e-mail domain.
 */
final class DiagnosticEvent
{
    public const STAGE_PROTOCOL = 'protocol';
    public const STAGE_STATE = 'state';
    public const STAGE_ATTRIBUTES = 'attributes';
    public const STAGE_GROUPS = 'groups';
    public const STAGE_PROVISIONING = 'provisioning';
    public const STAGE_SESSION = 'session';

    public readonly string $id;
    public readonly int $timestamp;
    public readonly string $protocol;
    public readonly string $stage;
    public readonly LoginOutcome $outcome;
    public readonly string $reasonCode;
    public readonly string $message;
    public readonly string $issuer;
    public readonly string $subject;

    /** @var array<string, list<string>> */
    private array $attributes;

    /** @var array<string, mixed> */
    private array $mapping;

    /** @var array<string, mixed> */
    private array $decision;

    /**
     * @param array<string, list<string>> $attributes Raw or masked - masked here either way,
     *                                                so no caller has to remember to do it.
     * @param array<string, mixed> $mapping
     * @param array<string, mixed> $decision
     */
    public function __construct(
        string $id,
        int $timestamp,
        string $protocol,
        string $stage,
        LoginOutcome $outcome,
        string $reasonCode,
        string $message,
        string $issuer = '',
        string $subject = '',
        array $attributes = [],
        array $mapping = [],
        array $decision = []
    ) {
        $this->id = $id;
        $this->timestamp = $timestamp;
        $this->protocol = $protocol;
        $this->stage = $stage;
        $this->outcome = $outcome;
        $this->reasonCode = $reasonCode;
        $this->message = Ascii::truncateBytes($message, 1024);
        $this->issuer = Ascii::truncateBytes($issuer, 255);
        $this->subject = Masker::maskValue($subject);
        $this->attributes = Masker::maskAttributes($attributes);
        $this->mapping = Masker::scrubStructure($mapping);
        $this->decision = Masker::scrubStructure($decision);
    }

    /** @return array<string, list<string>> */
    public function attributes(): array
    {
        return $this->attributes;
    }

    /** @return array<string, mixed> */
    public function mapping(): array
    {
        return $this->mapping;
    }

    /** @return array<string, mixed> */
    public function decision(): array
    {
        return $this->decision;
    }

    public function isSuccess(): bool
    {
        return $this->outcome === LoginOutcome::Success;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'timestamp' => $this->timestamp,
            'protocol' => $this->protocol,
            'stage' => $this->stage,
            'outcome' => $this->outcome->value,
            'reason' => $this->reasonCode,
            'message' => $this->message,
            'issuer' => $this->issuer,
            'subject' => $this->subject,
            'attributes' => $this->attributes,
            'mapping' => $this->mapping,
            'decision' => $this->decision,
        ];
    }

    /**
     * Storage format for the Craft table behind the panel.
     */
    public function toJson(): string
    {
        $json = json_encode($this->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $json === false ? '{"error":"diagnostics_encoding_failed"}' : $json;
    }
}
