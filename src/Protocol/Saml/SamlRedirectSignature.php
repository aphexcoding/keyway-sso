<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use OneLogin\Saml2\Utils;
use RuntimeException;

/**
 * Builds a signed HTTP-Redirect URL for an outgoing logout message.
 *
 * The mirror image of SamlLogoutMessageReader::verifyRedirectSignature(), and the reason both
 * live close together: on this binding the signature covers the QUERY STRING, not the XML, so
 * the only way to be correct is to sign exactly the octets that are then sent. That is why this
 * class takes values that are ALREADY percent-encoded and concatenates them itself rather than
 * calling http_build_query() - handing the encoding to a second piece of code is handing it the
 * chance to encode differently than we signed, and the resulting logout fails at the IdP with a
 * signature error nobody can reproduce.
 *
 * It is also why an inbound RelayState is echoed back exactly as it arrived: re-encoding a value
 * somebody else encoded is a guess.
 *
 * SHA-256 and nothing weaker. There is no parameter for the algorithm on purpose: an outgoing
 * algorithm switch is how an integration ends up signing with SHA-1 "temporarily".
 */
final class SamlRedirectSignature
{
    public const SIG_ALG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    private function __construct()
    {
    }

    /**
     * @param string                $endpoint  Absolute URL of the IdP's SLO endpoint.
     * @param array<string, string> $encoded   Ordered, ALREADY percent-encoded parameters:
     *                                         `SAMLRequest` or `SAMLResponse` first, then
     *                                         `RelayState` if there is one. `SigAlg` and
     *                                         `Signature` are added here.
     * @param string                $privateKeyPem SP private key.
     */
    public static function url(string $endpoint, array $encoded, string $privateKeyPem): string
    {
        $query = '';
        foreach ($encoded as $name => $value) {
            $query .= ($query === '' ? '' : '&') . $name . '=' . $value;
        }

        // Bindings 3.4.4.1: SigAlg is the last member of the signed string, and the signature
        // parameter itself is never part of it.
        $query .= '&SigAlg=' . rawurlencode(self::SIG_ALG_RSA_SHA256);

        $key = openssl_pkey_get_private(Utils::formatPrivateKey($privateKeyPem, true));

        if ($key === false) {
            throw new RuntimeException('SP private key could not be loaded for logout signing.');
        }

        $signature = '';
        if (openssl_sign($query, $signature, $key, OPENSSL_ALGO_SHA256) !== true) {
            throw new RuntimeException('Logout message could not be signed.');
        }

        $separator = str_contains($endpoint, '?') ? '&' : '?';

        return $endpoint . $separator . $query . '&Signature=' . rawurlencode(base64_encode($signature));
    }
}
