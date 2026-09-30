<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\Http\HttpResponse;
use Keyway\Sso\Core\Http\HttpTransportException;

/**
 * Outbound HTTP, injected so that the protocol layer is testable without a network.
 *
 * OIDC needs four back-channel calls (discovery, JWKS, token endpoint, userinfo) and every one
 * of them is a place where a test that "just hits the IdP" turns into a test suite that passes
 * or fails depending on somebody else's uptime. It is also the seam that lets the reader tests
 * feed a malicious discovery document or a rotated JWKS without standing up a server.
 *
 * Contract for implementations (see Protocol\Oidc\CurlHttpClient):
 *  - TLS certificate verification is ON and there is NO switch to turn it off. A "verify: false"
 *    option in a plugin setting is how an administrator downgrades every check in section C to
 *    nothing: the JWKS is the root of trust for the id token, so whoever can rewrite it in
 *    flight can mint identities.
 *  - Redirects are NOT followed. A redirect is the cheapest way to move a back-channel call from
 *    the configured issuer to an attacker's host, and nothing in OIDC needs one.
 *  - Both a connect timeout and a total timeout are set, so a hanging IdP cannot pin a PHP
 *    worker, and the response body is capped so a hostile endpoint cannot exhaust memory.
 *  - Non-2xx responses are RETURNED, not thrown: the token endpoint says "invalid_grant" with a
 *    400 and the caller needs to read that body. Only transport-level failures throw.
 */
interface HttpClientInterface
{
    /**
     * @param array<string, string> $headers
     * @throws HttpTransportException When the request could not be completed at all.
     */
    public function get(string $url, array $headers = []): HttpResponse;

    /**
     * `application/x-www-form-urlencoded` POST - the only body shape OAuth 2.0 token endpoints
     * accept (RFC 6749 section 4.1.3).
     *
     * @param array<string, string> $form
     * @param array<string, string> $headers
     * @throws HttpTransportException When the request could not be completed at all.
     */
    public function postForm(string $url, array $form, array $headers = []): HttpResponse;
}
