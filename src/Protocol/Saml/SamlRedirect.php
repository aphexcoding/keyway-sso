<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use Keyway\Sso\Core\Port\AuthenticationStartInterface;
use Keyway\Sso\Core\State\StateToken;

/**
 * Where to send the browser for a SAML login, and the one-shot state issued for the trip.
 *
 * The same deliberate poverty as OidcAuthorizationRedirect: url() and state(), nothing else.
 * What it does NOT carry is the id of the AuthnRequest that was just built. That value lives in
 * the state record server-side, and an accessor for it here is how it would end up in a hidden
 * form field or a cookie the day somebody wires the InResponseTo check - at which point the
 * check would be comparing the IdP's answer against a value the IdP could have chosen.
 */
final class SamlRedirect implements AuthenticationStartInterface
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
