<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\State;

/**
 * Result of consuming a state token.
 */
final class StateValidation
{
    public const OK = 'ok';
    public const MALFORMED = 'malformed';
    public const UNKNOWN = 'unknown';
    public const EXPIRED = 'expired';
    public const ALREADY_USED = 'already_used';
    public const SECRET_MISMATCH = 'secret_mismatch';
    public const STORAGE_UNCONFIRMED = 'storage_unconfirmed';

    public readonly bool $valid;
    public readonly string $reasonCode;
    public readonly ?string $returnUrl;
    public readonly ?string $id;

    /** @var array<string, string> */
    private array $context;

    /**
     * @param array<string, string> $context
     */
    private function __construct(
        bool $valid,
        string $reasonCode,
        ?string $returnUrl = null,
        ?string $id = null,
        array $context = []
    ) {
        $this->valid = $valid;
        $this->reasonCode = $reasonCode;
        $this->returnUrl = $returnUrl;
        $this->id = $id;
        $this->context = $context;
    }

    /**
     * @param array<string, string> $context
     */
    public static function ok(string $id, string $returnUrl, array $context = []): self
    {
        return new self(true, self::OK, $returnUrl, $id, $context);
    }

    public static function fail(string $reasonCode, ?string $id = null): self
    {
        return new self(false, $reasonCode, null, $id);
    }

    /** @return array<string, string> */
    public function context(): array
    {
        return $this->context;
    }

    /**
     * Administrator-facing explanation for the diagnostics panel.
     */
    public function message(): string
    {
        return match ($this->reasonCode) {
            self::OK => 'Login state verified.',
            self::MALFORMED => 'The login state value sent back by the identity provider is not '
                . 'in the expected format.',
            self::UNKNOWN => 'The login state is not known to this site. It was most likely '
                . 'started on another server, or the cache was cleared mid-login.',
            self::EXPIRED => 'The login took longer than the allowed window. Start again from '
                . 'the Craft login screen.',
            self::ALREADY_USED => 'This login state has already been used. A single sign-on '
                . 'response can only be processed once.',
            self::SECRET_MISMATCH => 'The login state did not verify. The sign-in attempt was '
                . 'rejected.',
            self::STORAGE_UNCONFIRMED => 'The login state could not be marked as used, so it '
                . 'cannot be accepted: the cache or database backing single sign-on state is '
                . 'not storing what this site writes to it. Check the cache configuration.',
            default => 'Login state rejected.',
        };
    }
}
