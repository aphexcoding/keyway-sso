<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use InvalidArgumentException;

/**
 * Everything the OIDC reader is allowed to trust, fixed at construction time.
 *
 * The sibling of SamlConnectionConfig and built on the same rule: no permissive defaults, and
 * nothing that weakens a check is reachable from settings. Three things are deliberately NOT
 * constructor arguments, because a deployment that can widen them has no contract left:
 *
 *  - ALLOWED_ALGORITHMS (C1/C3). The allow list is fixed in code. Keycloak's own discovery
 *    document on the test realm advertises `HS256`, `HS384`, `HS512` and `EdDSA` among the id
 *    token signing algorithms; Entra ID advertises `RS256` only today and may advertise more
 *    tomorrow. What the IdP offers is not what we accept. An `HS*` id token on a connection
 *    whose key material is public is an authentication bypass, not a compatibility option.
 *  - CODE_CHALLENGE_METHOD (C8). `S256` always. The same Keycloak document advertises `plain`
 *    as a supported code challenge method, and league/oauth2-client 2.9.0 implements it
 *    (AbstractProvider::PKCE_METHOD_PLAIN, src/Provider/AbstractProvider.php:74). Neither fact
 *    makes it acceptable: `plain` puts the verifier in the URL the attacker already stole.
 *  - Whether the time checks run at all (A4). Only their tolerance is configurable, and only up
 *    to MAX_CLOCK_SKEW.
 *
 * Scheme policy: the issuer and the redirect URI must both be `https`. The issuer is the root of
 * trust (the discovery document names the JWKS that verifies every id token) and the redirect URI
 * is where the authorization code lands in the user's browser. There is no loopback exception and
 * no setting to relax it - a development IdP on plain HTTP is a reason to put a certificate on
 * the development IdP.
 */
final class OidcConnectionConfig
{
    /** Contract A4: the ceiling is part of the contract, not a preference. */
    public const MAX_CLOCK_SKEW = 120;

    /**
     * Contract C1/C3. Asymmetric only, and only the two the whole market actually uses. Adding
     * `PS256` or `EdDSA` here later is a decision with a review, not a configuration change.
     *
     * @var list<string>
     */
    public const ALLOWED_ALGORITHMS = ['RS256', 'ES256'];

    /** Contract C8. */
    public const CODE_CHALLENGE_METHOD = 'S256';

    public readonly string $issuer;
    public readonly string $clientId;
    public readonly ?string $clientSecret;
    public readonly string $redirectUri;
    public readonly int $clockSkew;
    public readonly bool $fetchUserinfo;

    /** @var list<string> */
    private array $scopes;

    /**
     * @param list<string> $scopes `openid` is mandatory and is added when missing.
     */
    public function __construct(
        string $issuer,
        string $clientId,
        ?string $clientSecret,
        string $redirectUri,
        array $scopes = ['openid', 'profile', 'email'],
        int $clockSkew = 60,
        bool $fetchUserinfo = false
    ) {
        $issuer = trim($issuer);
        $clientId = trim($clientId);
        $redirectUri = trim($redirectUri);

        if (!self::isHttpsUrl($issuer)) {
            throw new InvalidArgumentException(
                'Issuer must be an absolute https URL, without a query string or fragment. '
                . 'It is compared byte for byte against the `iss` claim, so it is stored exactly '
                . 'as entered - including or excluding a trailing slash.'
            );
        }

        if ($clientId === '') {
            throw new InvalidArgumentException('Client id must not be empty.');
        }

        if ($clientSecret !== null && trim($clientSecret) === '') {
            throw new InvalidArgumentException(
                'Client secret must be a secret or null, never an empty string. Null means a '
                . 'public client, which is only safe because PKCE is mandatory (C8).'
            );
        }

        if (!self::isHttpsUrl($redirectUri, true)) {
            throw new InvalidArgumentException(
                'Redirect URI must be an absolute https URL without a fragment. The '
                . 'authorization code travels to it through the user agent.'
            );
        }

        if ($clockSkew < 0 || $clockSkew > self::MAX_CLOCK_SKEW) {
            throw new InvalidArgumentException(sprintf(
                'Clock skew must be between 0 and %d seconds.',
                self::MAX_CLOCK_SKEW
            ));
        }

        $this->issuer = $issuer;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret === null ? null : trim($clientSecret);
        $this->redirectUri = $redirectUri;
        $this->clockSkew = $clockSkew;
        $this->fetchUserinfo = $fetchUserinfo;
        $this->scopes = self::normaliseScopes($scopes);
    }

    /**
     * @return list<string>
     */
    public function scopes(): array
    {
        return $this->scopes;
    }

    public function scopeParameter(): string
    {
        return implode(' ', $this->scopes);
    }

    /**
     * Confidential client (a secret to present at the token endpoint) or public client (PKCE
     * only). Both are supported; neither is allowed to skip PKCE.
     */
    public function isConfidential(): bool
    {
        return $this->clientSecret !== null;
    }

    /**
     * OpenID Connect Discovery 1.0, section 4: the issuer with the well-known path appended.
     * Built from the CONFIGURED issuer, never from anything the IdP or the browser sent.
     */
    public function discoveryUrl(): string
    {
        return rtrim($this->issuer, '/') . '/.well-known/openid-configuration';
    }

    /**
     * @param list<string> $scopes
     * @return list<string>
     */
    private static function normaliseScopes(array $scopes): array
    {
        $out = [];

        foreach ($scopes as $scope) {
            $scope = trim((string)$scope);

            // A space would silently split one scope into two in the query string.
            if ($scope === '' || preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope) !== 1) {
                continue;
            }

            if (!in_array($scope, $out, true)) {
                $out[] = $scope;
            }
        }

        if (!in_array('openid', $out, true)) {
            // Without it the IdP runs a plain OAuth 2.0 flow and returns no id token at all,
            // which would leave userinfo as the only source of identity - exactly what C10
            // forbids.
            array_unshift($out, 'openid');
        }

        return $out;
    }

    private static function isHttpsUrl(string $url, bool $allowQuery = false): bool
    {
        if ($url === '') {
            return false;
        }

        $parts = parse_url($url);
        if ($parts === false || !is_array($parts)) {
            return false;
        }

        if (strtolower((string)($parts['scheme'] ?? '')) !== 'https') {
            return false;
        }

        if (($parts['host'] ?? '') === '') {
            return false;
        }

        if (isset($parts['fragment'])) {
            return false;
        }

        if (!$allowQuery && isset($parts['query'])) {
            return false;
        }

        return true;
    }
}
