<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

/**
 * A verified answer to a LogoutRequest this site sent.
 *
 * The object only exists when the answer was signed by the configured IdP AND correlated to a
 * request id this site really issued (SamlLogoutResponseReader does both, in that order). It
 * carries no identity: the only fact it establishes is "the IdP answered our logout, and this is
 * what it said about it".
 *
 * `succeeded` is deliberately narrow - it is true for top-level Success and nothing else. A
 * partial logout is still Success at the top level (SAML 2.0 Core 3.7.3.2 puts PartialLogout in
 * the SECOND-level code), so `partial` is reported separately rather than folded into failure:
 * the local session should still end, but an operator reading diagnostics deserves to know that
 * some other service provider's session is still alive.
 */
final class InboundLogoutResponse
{
    public readonly string $id;

    /** The id of OUR LogoutRequest this answers. Already checked against the state record. */
    public readonly string $inResponseTo;

    public readonly string $statusCode;

    public readonly ?string $secondaryStatusCode;

    public readonly ?string $rawRelayState;

    public function __construct(
        string $id,
        string $inResponseTo,
        string $statusCode,
        ?string $secondaryStatusCode,
        ?string $rawRelayState
    ) {
        $this->id = $id;
        $this->inResponseTo = $inResponseTo;
        $this->statusCode = $statusCode;
        $this->secondaryStatusCode = $secondaryStatusCode;
        $this->rawRelayState = $rawRelayState;
    }

    public function succeeded(): bool
    {
        return $this->statusCode === SamlLogoutResponse::STATUS_SUCCESS;
    }

    /**
     * The IdP could not end every session it knows about. Still a Success at the top level.
     */
    public function partial(): bool
    {
        return $this->secondaryStatusCode === SamlLogoutResponse::STATUS_PARTIAL_LOGOUT;
    }
}
