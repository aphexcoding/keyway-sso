<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

/**
 * The validated subset of an OpenID Provider discovery document.
 *
 * Only the fields this plugin acts on, already checked by OidcDiscovery: every endpoint is an
 * absolute https URL and the issuer is byte-identical to the configured one. Anything the reader
 * later reads from here has therefore passed A6/C4 - which is the point of having a value object
 * instead of passing the raw array around, where "did anyone check this?" becomes unanswerable.
 */
final class OidcProviderMetadata
{
    public readonly string $issuer;
    public readonly string $authorizationEndpoint;
    public readonly string $tokenEndpoint;
    public readonly string $jwksUri;
    public readonly ?string $userinfoEndpoint;
    public readonly ?string $endSessionEndpoint;

    public function __construct(
        string $issuer,
        string $authorizationEndpoint,
        string $tokenEndpoint,
        string $jwksUri,
        ?string $userinfoEndpoint = null,
        ?string $endSessionEndpoint = null
    ) {
        $this->issuer = $issuer;
        $this->authorizationEndpoint = $authorizationEndpoint;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->jwksUri = $jwksUri;
        $this->userinfoEndpoint = $userinfoEndpoint;
        $this->endSessionEndpoint = $endSessionEndpoint;
    }
}
