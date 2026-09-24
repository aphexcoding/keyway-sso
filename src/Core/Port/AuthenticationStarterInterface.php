<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * Builds the request that sends a person to their identity provider.
 *
 * The mirror image of IdentityReaderInterface: that one turns a protocol response into an
 * identity, this one turns "somebody clicked the SSO button" into a URL. The core needs the seam
 * because building the request is protocol work - an OIDC authorization URL, a SAML AuthnRequest
 * - and Core\ must not depend on Protocol\.
 *
 * HARD CONTRACT, and it is short but not negotiable:
 *
 *  1. The state is issued HERE, through Core\State\StateStore, because only the starter knows
 *     what else has to ride in it (the OIDC nonce and PKCE verifier, the SAML request id).
 *  2. THE CALLER'S CONTEXT MUST SURVIVE INTO THE STATE. LoginFlow passes the connection handle
 *     and the browser-binding decision through `$context`, and the callback refuses the login
 *     if either is missing. A starter that rebuilds the context instead of merging it turns
 *     both into a silent failure - so merge, and apply your own keys last so no caller can
 *     overwrite a nonce or a verifier.
 *  3. `connection()` is the handle written into the state as `connection` and used at the
 *     callback to choose the reader. It must be the same string the matching reader reports
 *     from `protocol()`, or the two halves of the flow will not find each other.
 */
interface AuthenticationStarterInterface
{
    public function connection(): string;

    /**
     * @param array<string, string> $context Bookkeeping that MUST end up in the state record.
     */
    public function start(?string $returnUrl, array $context): AuthenticationStartInterface;
}
