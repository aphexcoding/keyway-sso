<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\State;

/**
 * The client-side half: what travels to the IdP as RelayState (SAML) or `state` (OIDC).
 */
final class StateToken
{
    public readonly string $id;
    public readonly string $value;
    public readonly string $returnUrl;
    public readonly int $expiresAt;

    public function __construct(string $id, string $value, string $returnUrl, int $expiresAt)
    {
        $this->id = $id;
        $this->value = $value;
        $this->returnUrl = $returnUrl;
        $this->expiresAt = $expiresAt;
    }

    /**
     * The opaque string to send. Never log it: it is a bearer value for one login round trip.
     */
    public function __toString(): string
    {
        return $this->value;
    }
}
