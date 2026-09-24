<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\HttpClientInterface;
use Keyway\Sso\Core\Port\KeyValueCacheInterface;

/**
 * Contract C4: where the trust in an id token actually comes from.
 *
 * The document is fetched from the CONFIGURED issuer (config->discoveryUrl(), built from the
 * setting, never from anything in the request or in the token), over https with certificate
 * verification on, and then checked before a single field of it is used:
 *
 *  - `issuer` in the document must equal the configured issuer byte for byte (A6/C6). This is
 *    the one check that makes the rest of discovery safe: without it, a site pointed at
 *    `https://idp.example/tenant-a` would happily take endpoints and a JWKS advertised for
 *    tenant B, and every later "the issuer matches" check would compare the token against a
 *    value the attacker chose.
 *  - every endpoint we use must be an absolute https URL. An `http` token endpoint leaks the
 *    client secret and the authorization code; an `http` JWKS is the root of trust served in
 *    clear text.
 *  - when the IdP advertises its id token signing algorithms, at least one of them must be on
 *    OUR allow list - otherwise the connection cannot ever work and it is better to say so
 *    during "test connection" than during someone's login.
 *  - when the IdP advertises its code challenge methods, `S256` must be among them. If it only
 *    offers `plain`, the connection is refused rather than downgraded (C8).
 *
 * The document is cached (it changes about as often as the IdP is reinstalled) and the cache is
 * a port, so the Craft adapter can hand over the site cache. The cached copy is the already
 * validated one, so a poisoned cache entry still cannot introduce a non-https endpoint - but
 * everything in it was checked when it was written, which is why it is keyed by the discovery
 * URL and never by anything user-supplied.
 */
final class OidcDiscovery
{
    use RejectsWithDetail;

    public const DEFAULT_TTL = 3600;

    private OidcConnectionConfig $config;
    private HttpClientInterface $http;
    private KeyValueCacheInterface $cache;
    private ClockInterface $clock;
    private int $ttl;

    private ?OidcProviderMetadata $metadata = null;

    public function __construct(
        OidcConnectionConfig $config,
        HttpClientInterface $http,
        KeyValueCacheInterface $cache,
        ClockInterface $clock,
        RejectionDetail $rejectionDetail,
        int $ttl = self::DEFAULT_TTL
    ) {
        $this->config = $config;
        $this->http = $http;
        $this->cache = $cache;
        $this->clock = $clock;
        $this->rejectionDetail = $rejectionDetail;
        $this->ttl = max(60, $ttl);
    }

    /**
     * @throws IdentityReaderException When the document cannot be fetched or does not check out.
     */
    public function metadata(): OidcProviderMetadata
    {
        if ($this->metadata !== null) {
            return $this->metadata;
        }

        $cacheKey = $this->cacheKey();
        $cached = $this->cache->get($cacheKey);

        if ($cached !== null) {
            // Re-validated on the way out as well: a cache is shared mutable state, and an
            // entry written by an older build of this plugin has not necessarily been through
            // the checks this build makes.
            $this->metadata = $this->validate($cached);

            return $this->metadata;
        }

        $document = $this->fetch();
        $this->metadata = $this->validate($document);
        $this->cache->set($cacheKey, $document, $this->ttl);

        return $this->metadata;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(): array
    {
        $url = $this->config->discoveryUrl();

        try {
            $response = $this->http->get($url);
        } catch (HttpTransportException $error) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                'Discovery document could not be fetched: ' . $error->getMessage()
            );
        }

        if (!$response->isSuccessful()) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                sprintf('Discovery endpoint answered with HTTP %d.', $response->statusCode)
            );
        }

        return $this->decodeJsonObject($response->body, 'Discovery document');
    }

    /**
     * @param array<string, mixed> $document
     */
    private function validate(array $document): OidcProviderMetadata
    {
        $issuer = $document['issuer'] ?? null;

        if (!is_string($issuer) || !hash_equals($this->config->issuer, $issuer)) {
            // Exact comparison, per A6. No trailing-slash forgiveness: a mismatch means the
            // document does not describe the provider this site was configured to trust.
            $this->reject(
                IdentityReaderException::ISSUER_MISMATCH,
                sprintf(
                    'Discovery document is issued by "%s", not by the configured issuer.',
                    is_string($issuer) ? $issuer : '(absent)'
                )
            );
        }

        $authorization = $this->requireHttpsEndpoint($document, 'authorization_endpoint');
        $token = $this->requireHttpsEndpoint($document, 'token_endpoint');
        $jwks = $this->requireHttpsEndpoint($document, 'jwks_uri');
        $userinfo = $this->optionalHttpsEndpoint($document, 'userinfo_endpoint');
        $endSession = $this->optionalHttpsEndpoint($document, 'end_session_endpoint');

        $this->requireOverlappingAlgorithms($document);
        $this->requireS256($document);

        return new OidcProviderMetadata(
            $issuer,
            $authorization,
            $token,
            $jwks,
            $userinfo,
            $endSession
        );
    }

    /**
     * @param array<string, mixed> $document
     */
    private function requireHttpsEndpoint(array $document, string $field): string
    {
        $value = $document[$field] ?? null;

        if (!is_string($value) || !self::isHttpsUrl($value)) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                sprintf('Discovery document has no absolute https "%s".', $field)
            );
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $document
     */
    private function optionalHttpsEndpoint(array $document, string $field): ?string
    {
        $value = $document[$field] ?? null;

        if ($value === null) {
            return null;
        }

        // Present but not https is a rejection rather than a silent "treat as absent": the
        // difference between "the IdP has no userinfo endpoint" and "the IdP advertises an
        // http one" matters, and quietly ignoring the second hides a misconfiguration.
        if (!is_string($value) || !self::isHttpsUrl($value)) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                sprintf('Discovery document advertises a non-https "%s".', $field)
            );
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $document
     */
    private function requireOverlappingAlgorithms(array $document): void
    {
        $advertised = $document['id_token_signing_alg_values_supported'] ?? null;

        if (!is_array($advertised) || $advertised === []) {
            return; // The field is optional in practice; our allow list decides anyway.
        }

        foreach ($advertised as $algorithm) {
            if (is_string($algorithm)
                && in_array($algorithm, OidcConnectionConfig::ALLOWED_ALGORITHMS, true)
            ) {
                return;
            }
        }

        // Note what this check is NOT: it never widens the allow list. The IdP's list can only
        // make us refuse earlier, never accept more.
        $this->reject(
            IdentityReaderException::ALGORITHM_NOT_ALLOWED,
            'Identity provider signs id tokens only with algorithms this plugin refuses ('
            . implode(', ', array_map('strval', $advertised)) . ').'
        );
    }

    /**
     * @param array<string, mixed> $document
     */
    private function requireS256(array $document): void
    {
        $advertised = $document['code_challenge_methods_supported'] ?? null;

        if (!is_array($advertised) || $advertised === []) {
            return;
        }

        if (in_array(OidcConnectionConfig::CODE_CHALLENGE_METHOD, $advertised, true)) {
            return;
        }

        $this->reject(
            IdentityReaderException::DISCOVERY_FAILED,
            'Identity provider does not support the S256 code challenge method; PKCE is '
            . 'mandatory and "plain" is not an acceptable substitute.'
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonObject(string $body, string $label): array
    {
        $decoded = json_decode($body, true, 32, JSON_BIGINT_AS_STRING);

        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded) || array_is_list($decoded)) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                $label . ' is not a JSON object.'
            );
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private function cacheKey(): string
    {
        return 'keyway.oidc.discovery.' . hash('sha256', $this->config->discoveryUrl());
    }

    private static function isHttpsUrl(string $url): bool
    {
        $parts = parse_url($url);

        return is_array($parts)
            && strtolower((string)($parts['scheme'] ?? '')) === 'https'
            && ($parts['host'] ?? '') !== '';
    }
}
