<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\HttpClientInterface;
use Keyway\Sso\Core\Port\KeyValueCacheInterface;
use Throwable;

/**
 * Contract C4/C5: the verifying keys, and which one may verify a given token.
 *
 * Division of labour with firebase/php-jwt 7.1.0, stated explicitly because "the library does
 * it" is not an answer the contract accepts:
 *
 *  DELEGATED to the library (A2 - no hand-rolled key parsing):
 *    - turning a JWK into usable key material: JWK::parseKeySet(), which does the modulus and
 *      exponent to PEM work for RSA and the curve point work for EC.
 *
 *  BUILT HERE, because parseKeySet() alone does not give what C4/C5 ask for:
 *    - SYMMETRIC KEYS ARE FILTERED OUT BEFORE PARSING. JWK::parseKey() accepts `kty: oct` and
 *      returns a Key holding the raw secret (vendor/firebase/php-jwt/src/JWK.php:187-192). A
 *      JWKS is a PUBLIC document: an `oct` entry publishes the HMAC secret to the world, and a
 *      verifier that keeps it will verify `HS256` tokens anyone can forge. This is C3's failure
 *      mode arriving through the key set instead of through the `alg` header, so the allow list
 *      is applied to the KEYS as well as to the header.
 *    - ENCRYPTION KEYS ARE FILTERED OUT. The test realm's Keycloak publishes two keys: one
 *      `use: sig, alg: RS256` and one `use: enc, alg: RSA-OAEP`. parseKeySet() returns both, and
 *      only `use` tells them apart.
 *    - ONE BAD KEY DOES NOT KILL THE SET. parseKeySet() throws on the first entry it cannot
 *      parse (JWK.php:76-81 calls parseKey, which throws), so a single unusable key in an
 *      otherwise healthy JWKS would take the whole connection down. Each key is parsed on its
 *      own and failures are skipped.
 *    - `alg` IS OPTIONAL IN A JWK AND MANDATORY IN THIS LIBRARY. JWK::parseKey() throws
 *      'JWK must contain an "alg" parameter' unless a default is supplied (JWK.php:115-124), and
 *      Microsoft Entra ID publishes its signing keys without `alg`. The default is derived per
 *      key from `kty`/`crv` (RSA -> RS256, P-256 -> ES256) rather than passed once for the whole
 *      set, because a single default would mislabel an EC key in a mixed set and mislabelling is
 *      how a key ends up verifying an algorithm it was not meant for.
 *    - `kid` SELECTION AND THE REFRESH RULE (C5). The library's own cached key set refreshes on
 *      every unknown `kid` and is rate-limited only when the integrator opts in - the
 *      constructor default is `$rateLimit = false`
 *      (vendor/firebase/php-jwt/src/CachedKeySet.php:84) and JWT::getKey() deliberately skips the
 *      "is it there?" check for that class so the lookup triggers a fetch (JWT.php:491-493).
 *      Left like that, a stream of tokens with random `kid`s turns this site into a load
 *      generator against the IdP. Here: at most one refresh per rejected `kid`, and never more
 *      often than MIN_REFRESH_INTERVAL.
 */
final class JwksKeyStore
{
    use RejectsWithDetail;

    public const DEFAULT_TTL = 3600;

    /** C5: "rate-limited". Two rotations inside a minute are not a thing; DoS attempts are. */
    public const MIN_REFRESH_INTERVAL = 60;

    private OidcConnectionConfig $config;
    private OidcDiscovery $discovery;
    private HttpClientInterface $http;
    private KeyValueCacheInterface $cache;
    private ClockInterface $clock;
    private int $ttl;

    /** @var array<string, Key>|null kid => key, parsed from the current document. */
    private ?array $keysByKid = null;

    /** @var list<Key> Keys published without a `kid`. */
    private array $keysWithoutKid = [];

    public function __construct(
        OidcConnectionConfig $config,
        OidcDiscovery $discovery,
        HttpClientInterface $http,
        KeyValueCacheInterface $cache,
        ClockInterface $clock,
        RejectionDetail $rejectionDetail,
        int $ttl = self::DEFAULT_TTL
    ) {
        $this->config = $config;
        $this->discovery = $discovery;
        $this->http = $http;
        $this->cache = $cache;
        $this->clock = $clock;
        $this->rejectionDetail = $rejectionDetail;
        $this->ttl = max(60, $ttl);
    }

    /**
     * The key that, and only that, may verify this token.
     *
     * @param string|null $kid The `kid` header of the token, or null when it carries none.
     * @throws IdentityReaderException KEY_NOT_FOUND when no single key can be identified.
     */
    public function keyFor(?string $kid): Key
    {
        $this->load(false);

        if ($kid === null || $kid === '') {
            return $this->onlyKey();
        }

        $key = $this->keysByKid[$kid] ?? null;
        if ($key instanceof Key) {
            return $key;
        }

        // C5: exactly one refresh chance per unknown kid, so that a key rotation is survivable
        // without turning an attacker-chosen header into an unbounded fetch loop.
        if ($this->mayRefreshFor($kid)) {
            $this->load(true);

            $key = $this->keysByKid[$kid] ?? null;
            if ($key instanceof Key) {
                return $key;
            }
        }

        $this->reject(
            IdentityReaderException::KEY_NOT_FOUND,
            sprintf('No usable signing key with kid "%s" in the provider JWKS.', $kid)
        );
    }

    /**
     * Diagnostics only: which kids we currently hold.
     *
     * @return list<string>
     */
    public function kids(): array
    {
        $this->load(false);

        return array_keys($this->keysByKid ?? []);
    }

    /**
     * C5: a token with no `kid` is only acceptable when there is exactly one key to mean.
     * Trying every key in turn is how a rotated-out key, or a key an attacker steered us to,
     * ends up verifying a token.
     */
    private function onlyKey(): Key
    {
        $total = count($this->keysByKid ?? []) + count($this->keysWithoutKid);

        if ($total !== 1) {
            $this->reject(
                IdentityReaderException::KEY_NOT_FOUND,
                sprintf(
                    'Token carries no kid and the provider publishes %d usable signing keys; '
                    . 'refusing to guess.',
                    $total
                )
            );
        }

        $key = $this->keysWithoutKid[0] ?? null;
        if ($key instanceof Key) {
            return $key;
        }

        /** @var array<string, Key> $byKid */
        $byKid = $this->keysByKid ?? [];

        return (array_values($byKid))[0];
    }

    private function load(bool $force): void
    {
        if ($this->keysByKid !== null && !$force) {
            return;
        }

        $cacheKey = $this->cacheKey();
        $document = $force ? null : $this->cache->get($cacheKey);

        if ($document === null) {
            $document = $this->fetch();
            $this->cache->set($cacheKey, $document, $this->ttl);
        }

        $this->parse($document);
    }

    /**
     * @return array<string, mixed>
     */
    private function fetch(): array
    {
        $url = $this->discovery->metadata()->jwksUri;

        try {
            $response = $this->http->get($url);
        } catch (HttpTransportException $error) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                'JWKS could not be fetched: ' . $error->getMessage()
            );
        }

        if (!$response->isSuccessful()) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                sprintf('JWKS endpoint answered with HTTP %d.', $response->statusCode)
            );
        }

        $decoded = json_decode($response->body, true, 32, JSON_BIGINT_AS_STRING);

        if (json_last_error() !== JSON_ERROR_NONE
            || !is_array($decoded)
            || !isset($decoded['keys'])
            || !is_array($decoded['keys'])
        ) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                'JWKS is not a JSON object with a "keys" member.'
            );
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string, mixed> $document
     */
    private function parse(array $document): void
    {
        $byKid = [];
        $withoutKid = [];

        $keys = $document['keys'] ?? [];
        if (!is_array($keys)) {
            $keys = [];
        }

        foreach ($keys as $jwk) {
            if (!is_array($jwk)) {
                continue;
            }

            $algorithm = self::usableAlgorithm($jwk);
            if ($algorithm === null) {
                continue;
            }

            try {
                // parseKeySet rather than parseKey so the library's own set-level handling stays
                // on the path; one entry at a time so a broken key cannot take the set with it.
                $parsed = JWK::parseKeySet(['keys' => [$jwk]], $algorithm);
            } catch (Throwable) {
                continue;
            }

            $key = array_values($parsed)[0] ?? null;
            if (!$key instanceof Key) {
                continue;
            }

            // The library keys its result by the array index when a JWK has no `kid`, which
            // would invent the kid "0". We key by the kid the provider actually published.
            $kid = $jwk['kid'] ?? null;

            if (is_string($kid) && $kid !== '') {
                $byKid[$kid] = $key;
            } else {
                $withoutKid[] = $key;
            }
        }

        $this->keysByKid = $byKid;
        $this->keysWithoutKid = $withoutKid;

        if ($byKid === [] && $withoutKid === []) {
            $this->reject(
                IdentityReaderException::KEY_NOT_FOUND,
                'Provider JWKS contains no key this plugin can verify with: it needs an RSA or '
                . 'P-256 EC signing key usable for RS256 or ES256.'
            );
        }
    }

    /**
     * The algorithm this key may be used for, or null when the key must not be used at all.
     *
     * This is where C1/C3 is applied to the key material rather than to the token header, and it
     * is not redundant with the header check: the two block different attacks. The header check
     * stops a token that asks for `HS256`; this stops a key set that would make `HS256` possible
     * in the first place.
     *
     * @param array<mixed> $jwk
     */
    private static function usableAlgorithm(array $jwk): ?string
    {
        $use = $jwk['use'] ?? null;
        if ($use !== null && $use !== 'sig') {
            return null;
        }

        $keyOps = $jwk['key_ops'] ?? null;
        if (is_array($keyOps) && !in_array('verify', $keyOps, true)) {
            return null;
        }

        $kty = $jwk['kty'] ?? null;

        $default = match (true) {
            $kty === 'RSA' => 'RS256',
            $kty === 'EC' && ($jwk['crv'] ?? null) === 'P-256' => 'ES256',
            // `oct` (symmetric), `OKP` (EdDSA) and every other curve fall through to null: not
            // "unsupported for now" but "must never verify an id token on this connection".
            default => null,
        };

        if ($default === null) {
            return null;
        }

        $algorithm = $jwk['alg'] ?? null;

        if ($algorithm === null) {
            return $default;
        }

        if (!is_string($algorithm)
            || !in_array($algorithm, OidcConnectionConfig::ALLOWED_ALGORITHMS, true)
        ) {
            return null;
        }

        // A key that claims an algorithm its type cannot produce (an RSA key labelled ES256) is
        // dropped rather than silently re-labelled.
        return $algorithm === $default ? $algorithm : null;
    }

    private function mayRefreshFor(string $kid): bool
    {
        $key = $this->refreshCacheKey();
        $record = $this->cache->get($key) ?? ['at' => 0, 'kids' => []];

        $at = is_int($record['at'] ?? null) ? $record['at'] : 0;
        $kids = is_array($record['kids'] ?? null) ? $record['kids'] : [];

        if (in_array($kid, $kids, true)) {
            return false; // Already spent this kid's one refresh.
        }

        $now = $this->clock->now();
        if ($now - $at < self::MIN_REFRESH_INTERVAL) {
            return false;
        }

        $kids[] = $kid;
        if (count($kids) > 32) {
            $kids = array_slice($kids, -32);
        }

        $this->cache->set($key, ['at' => $now, 'kids' => array_values($kids)], $this->ttl);

        return true;
    }

    private function cacheKey(): string
    {
        return 'keyway.oidc.jwks.' . hash('sha256', $this->config->issuer);
    }

    private function refreshCacheKey(): string
    {
        return 'keyway.oidc.jwks.refresh.' . hash('sha256', $this->config->issuer);
    }
}
