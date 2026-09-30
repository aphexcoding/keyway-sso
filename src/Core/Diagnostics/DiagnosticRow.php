<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

/**
 * One stored diagnostics row, on its way OUT of the table and onto the panel.
 *
 * Deliberately not a DiagnosticEvent, and the difference is the whole reason this class exists.
 * DiagnosticEvent masks in its constructor - that is its guarantee, and it is the right one on
 * the way in. Rebuilding an event from the table would therefore push already-masked text
 * through Masker a second time, and nobody has proved Masker is idempotent: `j***n@example.com`
 * re-masked is not guaranteed to still read as an address, and a mask applied twice can hide
 * the very thing support is looking at.
 *
 * So this class does exactly nothing to the data. It does not mask and it does not unmask. It
 * treats whatever is in the `payload` column as already safe, because the only writer is a sink
 * that stores DiagnosticEvent::toJson().
 *
 * THE OTHER HALF OF ITS JOB IS SURVIVING BAD INPUT. The panel shows rows written by every
 * version of the plugin that has ever run on that site - a row from an older schema, a row
 * truncated by a `text` column that was too small, a row half-written when the database went
 * away. One such row must not take the screen down, because the screen is what the
 * administrator opens precisely WHEN something is wrong. fromStoredJson() therefore has no
 * failure mode: anything it cannot read becomes a visible placeholder row carrying
 * REASON_UNREADABLE, never an exception and never a fatal.
 */
final class DiagnosticRow
{
    /** Marks a row the panel could not parse. Visible on purpose - a hidden row is a lie. */
    public const REASON_UNREADABLE = 'diagnostics_row_unreadable';

    private const UNREADABLE_MESSAGE = 'This diagnostics entry could not be read (stored by an '
        . 'older version, or truncated). The login it describes is not affected.';

    /** Mirrors the caps DiagnosticEvent applies on the way in; a stored row may predate them. */
    private const MAX_MESSAGE_BYTES = 4096;
    private const MAX_FIELD_BYTES = 512;

    public readonly string $id;
    public readonly int $timestamp;
    public readonly string $protocol;
    public readonly string $stage;

    /** A LoginOutcome value ('success'|'denied'|'error'|'notice'), kept as a string. */
    public readonly string $outcome;

    public readonly string $reasonCode;
    public readonly string $message;
    public readonly string $issuer;

    /** Already masked when it was written. Not masked again here, not unmasked either. */
    public readonly string $subject;

    /** @var array<string, list<string>> */
    private array $attributes;

    /** @var array<string, mixed> */
    private array $mapping;

    /** @var array<string, mixed> */
    private array $decision;

    /**
     * @param array<string, list<string>> $attributes
     * @param array<string, mixed>        $mapping
     * @param array<string, mixed>        $decision
     */
    public function __construct(
        string $id,
        int $timestamp,
        string $protocol,
        string $stage,
        string $outcome,
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
        $this->outcome = LoginOutcome::tryFrom($outcome)?->value ?? LoginOutcome::Error->value;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
        $this->issuer = $issuer;
        $this->subject = $subject;
        $this->attributes = $attributes;
        $this->mapping = $mapping;
        $this->decision = $decision;
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
        return $this->outcome === LoginOutcome::Success->value;
    }

    public function isUnreadable(): bool
    {
        return $this->reasonCode === self::REASON_UNREADABLE;
    }

    /**
     * Rebuilds a row from the `payload` column. Total function: every input returns a row.
     *
     * $fallbackTimestamp is the `occurredAt` column, which is stored separately from the JSON
     * precisely so an unreadable payload still has a time to show and to sort by.
     */
    public static function fromStoredJson(string $json, int $fallbackTimestamp = 0): self
    {
        /** @var mixed $decoded */
        $decoded = json_decode($json, true);

        if (!is_array($decoded) || array_is_list($decoded)) {
            return self::unreadable('', $fallbackTimestamp);
        }

        // An outcome outside the enum means the row was written by something we do not
        // understand, so nothing else in it can be trusted to mean what it says either.
        $outcome = $decoded['outcome'] ?? null;
        if (!is_string($outcome) || LoginOutcome::tryFrom($outcome) === null) {
            return self::unreadable(
                self::text($decoded['id'] ?? null, 64),
                self::integer($decoded['timestamp'] ?? null, $fallbackTimestamp)
            );
        }

        return new self(
            self::text($decoded['id'] ?? null, 64),
            self::integer($decoded['timestamp'] ?? null, $fallbackTimestamp),
            self::text($decoded['protocol'] ?? null, 32),
            self::text($decoded['stage'] ?? null, 64),
            $outcome,
            // `reason` and not `reasonCode`: that is the key DiagnosticEvent::toArray() writes.
            self::text($decoded['reason'] ?? null, 128),
            self::text($decoded['message'] ?? null, self::MAX_MESSAGE_BYTES),
            self::text($decoded['issuer'] ?? null, self::MAX_FIELD_BYTES),
            self::text($decoded['subject'] ?? null, self::MAX_FIELD_BYTES),
            self::attributeBag($decoded['attributes'] ?? null),
            self::structure($decoded['mapping'] ?? null),
            self::structure($decoded['decision'] ?? null)
        );
    }

    private static function unreadable(string $id, int $timestamp): self
    {
        return new self(
            $id,
            $timestamp,
            '',
            '',
            LoginOutcome::Error->value,
            self::REASON_UNREADABLE,
            self::UNREADABLE_MESSAGE
        );
    }

    /**
     * Scalars become strings; arrays, objects and null become ''. No exception, ever - this
     * runs over data that a previous schema may have shaped differently.
     */
    private static function text(mixed $value, int $maxBytes): string
    {
        if (is_string($value)) {
            return substr($value, 0, $maxBytes);
        }

        if (is_int($value) || is_float($value)) {
            return (string)$value;
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return '';
    }

    private static function integer(mixed $value, int $fallback): int
    {
        if (is_int($value)) {
            return $value;
        }

        // A JSON number that came back as a float or a numeric string is still a timestamp.
        if (is_float($value) || (is_string($value) && preg_match('/^-?\d{1,19}$/', $value) === 1)) {
            return (int)$value;
        }

        return $fallback;
    }

    /**
     * @return array<string, list<string>>
     */
    private static function attributeBag(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $bag = [];
        foreach ($value as $name => $values) {
            $name = is_string($name) ? $name : (string)$name;

            // A single scalar where a list was expected is the shape older rows used; keep it
            // rather than dropping the claim the administrator is looking for.
            if (!is_array($values)) {
                $bag[$name] = [self::text($values, self::MAX_FIELD_BYTES)];
                continue;
            }

            $list = [];
            foreach ($values as $entry) {
                if (is_array($entry)) {
                    continue;
                }

                $list[] = self::text($entry, self::MAX_FIELD_BYTES);
            }

            $bag[$name] = $list;
        }

        return $bag;
    }

    /**
     * @return array<string, mixed>
     */
    private static function structure(mixed $value): array
    {
        if (!is_array($value) || array_is_list($value)) {
            return [];
        }

        $structure = [];
        foreach ($value as $key => $entry) {
            $structure[is_string($key) ? $key : (string)$key] = $entry;
        }

        return $structure;
    }
}
