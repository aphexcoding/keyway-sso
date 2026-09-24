<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use Keyway\Sso\Core\Port\AuthenticationStartInterface;
use Keyway\Sso\Core\State\StateToken;

/**
 * Where to send the browser, and the one-shot state that was issued for the trip.
 *
 * What this object deliberately does NOT carry: the nonce and the PKCE code verifier. They live
 * server-side in the state record and nowhere else (C7, C8). An object that exposed them would
 * sooner or later have them written into a cookie or a hidden form field by well-meaning glue
 * code, and both checks would become decorative.
 */
final class OidcAuthorizationRedirect implements AuthenticationStartInterface
{
    public readonly string $url;
    public readonly StateToken $state;

    public function __construct(string $url, StateToken $state)
    {
        $this->url = $url;
        $this->state = $state;
    }

    public function url(): string
    {
        return $this->url;
    }

    public function state(): StateToken
    {
        return $this->state;
    }
}
