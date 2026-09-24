<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\State\StateToken;

/**
 * The result of starting a login: where to send the browser, and the state issued for the trip.
 *
 * What an implementation must NOT expose is the rest of what it generated - the OIDC nonce and
 * the PKCE code verifier live server-side in the state record and nowhere else (contracts C7 and
 * C8). An object that offered them would sooner or later have them written into a cookie or a
 * hidden field by well-meaning glue code, and both checks would become decorative.
 */
interface AuthenticationStartInterface
{
    public function url(): string;

    public function state(): StateToken;
}
