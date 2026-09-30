<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\State;

/**
 * What a login state SAYS, read without burning it.
 *
 * READ THIS BEFORE USING IT: an inspection is not an authorisation. It proves the token is
 * well-formed, known, unexpired, unused and holds the right secret - and it changes nothing, so
 * the same token can still be inspected again. Nothing here signs anybody in.
 *
 * It exists for one reason. The context of a state carries which connection to validate against
 * and whether the login was bound to a browser, and both have to be known BEFORE the protocol
 * reader runs - because the reader is chosen by the first and must not run at all if the second
 * fails. But the readers consume the state themselves (they need the nonce, the PKCE verifier
 * and the SAML request id out of it, and consuming before the network call is what stops a
 * replayed callback from reaching the token endpoint). A state can only be consumed once, so
 * the gate in front of the reader has to read without burning.
 *
 * The deliberate consequence is that the burn moves one step later, into the reader. LoginFlow
 * closes that gap by asking StateStore::wasConsumed() afterwards and refusing the login if the
 * reader did not burn it - so an inspection can never turn into an accepted login that left a
 * reusable state behind.
 *
 * Kept as its own type rather than reusing StateValidation so that no call site can be copied
 * from a consume() path into an inspect() path and keep meaning what it used to mean.
 */
final class StateInspection
{
    public readonly bool $valid;
    public readonly string $reasonCode;
    public readonly ?string $id;
    public readonly ?string $returnUrl;

    /** @var array<string, string> */
    private array $context;

    /**
     * @param array<string, string> $context
     */
    private function __construct(
        bool $valid,
        string $reasonCode,
        ?string $id = null,
        ?string $returnUrl = null,
        array $context = []
    ) {
        $this->valid = $valid;
        $this->reasonCode = $reasonCode;
        $this->id = $id;
        $this->returnUrl = $returnUrl;
        $this->context = $context;
    }

    /**
     * @param array<string, string> $context
     */
    public static function ok(string $id, string $returnUrl, array $context): self
    {
        return new self(true, StateValidation::OK, $id, $returnUrl, $context);
    }

    public static function fail(string $reasonCode, ?string $id = null): self
    {
        return new self(false, $reasonCode, $id);
    }

    /** @return array<string, string> */
    public function context(): array
    {
        return $this->context;
    }

    /**
     * Administrator-facing explanation; the wording is shared with StateValidation so the
     * diagnostics panel does not grow a second vocabulary for the same rejections.
     */
    public function message(): string
    {
        return StateValidation::fail($this->reasonCode)->message();
    }
}
