<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * Source of the current time, injected so that TTL and expiry logic is testable.
 *
 * Time is a Unix timestamp in seconds, UTC. Seconds are deliberate: SAML/OIDC lifetimes are
 * expressed in seconds and integer comparison avoids timezone and DST ambiguity.
 */
interface ClockInterface
{
    public function now(): int;
}
