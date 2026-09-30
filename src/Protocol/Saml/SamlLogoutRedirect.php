<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use Keyway\Sso\Core\State\StateToken;

/**
 * Where to send the browser to log out, and - for an SP-initiated logout - the one-shot state
 * the IdP's answer will be correlated against.
 *
 * The same deliberate poverty as SamlRedirect, and for the same reason: the id of the
 * LogoutRequest we just sent is NOT exposed here. It lives in the state record server-side.
 * An accessor for it would end up in a hidden field or a cookie the day somebody "simplifies"
 * the callback, at which point the InResponseTo check would be comparing the IdP's answer
 * against a value the IdP itself could have chosen.
 *
 * `state` is null for an outgoing LogoutResponse: we are answering, not asking, so there is no
 * answer of ours to correlate.
 */
final class SamlLogoutRedirect
{
    public readonly string $url;
    public readonly ?StateToken $state;

    public function __construct(string $url, ?StateToken $state = null)
    {
        $this->url = $url;
        $this->state = $state;
    }

    public function url(): string
    {
        return $this->url;
    }

    public function state(): ?StateToken
    {
        return $this->state;
    }
}
