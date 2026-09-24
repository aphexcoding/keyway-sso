<?php

declare(strict_types=1);

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Keyway\Sso\Core\Http\HttpResponse;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Support\InMemoryKeyValueCache;
use Keyway\Sso\Protocol\Oidc\JwksKeyStore;
use Keyway\Sso\Protocol\Oidc\OidcConnectionConfig;
use Keyway\Sso\Protocol\Oidc\OidcDiscovery;
use Keyway\Sso\Protocol\Oidc\RejectionDetail;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FakeHttpClient;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\OidcFixtures;

/**
 * Contract C4 and C5: where the verifying key comes from, and which one may be used.
 *
 * These are the checks that decide whose signature counts, so the fixtures are the hostile
 * versions of a discovery document and a JWKS - the wrong issuer, an http endpoint, a key set
 * that publishes an HMAC secret, a rotated key, an attacker-chosen `kid`.
 */
if (!class_exists(JWK::class)) {
    fwrite(STDOUT, "oidc_discovery             skipped: vendor absent (run composer install)\n");

    return [];
}

$now = time();

/**
 * @param array<string, mixed> $options
 * @return array{0: OidcDiscovery, 1: JwksKeyStore, 2: FakeHttpClient, 3: RejectionDetail, 4: FixedClock}
 */
$make = static function (array $options = []) use ($now): array {
    $clock = new FixedClock((int)($options['now'] ?? $now));
    $cache = new InMemoryKeyValueCache($clock);
    $http = new FakeHttpClient();

    $http->onJson(
        OidcFixtures::discoveryUrl(),
        $options['discovery'] ?? OidcFixtures::discovery()
    );

    if (array_key_exists('discoveryResponse', $options)) {
        $http->on(OidcFixtures::discoveryUrl(), $options['discoveryResponse']);
    }

    $http->onJson(OidcFixtures::jwksUri(), $options['jwks'] ?? OidcFixtures::jwks(['rsa']));

    foreach ($options['jwksQueue'] ?? [] as $document) {
        $http->queueJson(OidcFixtures::jwksUri(), $document);
    }

    $config = new OidcConnectionConfig(
        (string)($options['issuer'] ?? OidcFixtures::ISSUER),
        OidcFixtures::CLIENT_ID,
        OidcFixtures::CLIENT_SECRET,
        OidcFixtures::REDIRECT_URI
    );

    $detail = new RejectionDetail();
    $discovery = new OidcDiscovery($config, $http, $cache, $clock, $detail);
    $keys = new JwksKeyStore($config, $discovery, $http, $cache, $clock, $detail);

    return [$discovery, $keys, $http, $detail, $clock];
};

/**
 * @param array<string, mixed> $options
 */
$rejectsDiscovery = static function (string $expectedReason, array $options) use ($make): void {
    [$discovery] = $make($options);

    $error = Assert::throws(
        IdentityReaderException::class,
        static fn () => $discovery->metadata()
    );

    Assert::same(
        $expectedReason,
        $error instanceof IdentityReaderException ? $error->reasonCode() : '',
        'discovery rejection reason'
    );
};

return [
    // ---------------------------------------------------------------- C4: the document itself

    'a discovery document from the configured issuer yields its endpoints' =>
        static function () use ($make): void {
            [$discovery, , $http] = $make();

            $metadata = $discovery->metadata();

            Assert::same(OidcFixtures::ISSUER, $metadata->issuer);
            Assert::same(OidcFixtures::authorizationEndpoint(), $metadata->authorizationEndpoint);
            Assert::same(OidcFixtures::tokenEndpoint(), $metadata->tokenEndpoint);
            Assert::same(OidcFixtures::jwksUri(), $metadata->jwksUri);
            Assert::same(OidcFixtures::userinfoEndpoint(), $metadata->userinfoEndpoint);

            // Fetched from the configured issuer's well-known path, not from anywhere else.
            Assert::same(1, $http->callCount(OidcFixtures::discoveryUrl()));

            $discovery->metadata();
            Assert::same(1, $http->callCount(OidcFixtures::discoveryUrl()), 'cached, not refetched');
        },

    'a document issued by somebody else is refused even when it is well formed' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::ISSUER_MISMATCH, [
                'discovery' => OidcFixtures::discovery([
                    'issuer' => 'https://idp.example.test/realms/other-tenant',
                ]),
            ]);
        },

    'issuer comparison is exact, so a trailing slash is a mismatch' =>
        static function () use ($rejectsDiscovery): void {
            // Not pedantry: prefix-tolerant issuer comparison is how a multi-tenant IdP lets
            // tenant A's document answer for tenant B.
            $rejectsDiscovery(IdentityReaderException::ISSUER_MISMATCH, [
                'discovery' => OidcFixtures::discovery(['issuer' => OidcFixtures::ISSUER . '/']),
            ]);
        },

    'a JWKS served over plain http is refused' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discovery' => OidcFixtures::discovery([
                    'jwks_uri' => 'http://idp.example.test/realms/keyway/certs',
                ]),
            ]);
        },

    'a missing token endpoint is refused rather than defaulted' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discovery' => OidcFixtures::discovery(['token_endpoint' => null]),
            ]);
        },

    'an http userinfo endpoint is refused instead of quietly ignored' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discovery' => OidcFixtures::discovery([
                    'userinfo_endpoint' => 'http://idp.example.test/realms/keyway/userinfo',
                ]),
            ]);
        },

    'a provider that only offers plain PKCE is refused, not downgraded to' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discovery' => OidcFixtures::discovery([
                    'code_challenge_methods_supported' => ['plain'],
                ]),
            ]);
        },

    'a provider that signs only with algorithms we refuse fails at configuration time' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::ALGORITHM_NOT_ALLOWED, [
                'discovery' => OidcFixtures::discovery([
                    'id_token_signing_alg_values_supported' => ['HS256', 'EdDSA'],
                ]),
            ]);
        },

    'the advertised algorithm list can never widen our own' =>
        static function () use ($make): void {
            // The Keycloak test realm advertises HS256/HS384/HS512 among its id token signing
            // algorithms. Reading the document must not add a single one of them.
            [$discovery] = $make();
            $discovery->metadata();

            Assert::sameList(['RS256', 'ES256'], OidcConnectionConfig::ALLOWED_ALGORITHMS);
        },

    'an unreachable provider is a rejection with a reason, not a stray transport error' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discoveryResponse' => new HttpTransportException('TLS handshake failed'),
            ]);
        },

    'an HTTP error and a non-JSON body are both discovery failures' =>
        static function () use ($rejectsDiscovery): void {
            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discoveryResponse' => FakeHttpClient::json(['error' => 'nope'], 500),
            ]);

            $rejectsDiscovery(IdentityReaderException::DISCOVERY_FAILED, [
                'discoveryResponse' => new HttpResponse(200, '<html>not json</html>'),
            ]);
        },

    'the rejection detail names the problem for the administrator, the message does not' =>
        static function () use ($make): void {
            [$discovery, , , $detail] = $make([
                'discovery' => OidcFixtures::discovery(['issuer' => 'https://elsewhere.test']),
            ]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $discovery->metadata()
            );

            Assert::contains('elsewhere.test', $detail->last(), 'detail carries the diagnosis');
            Assert::notContains('elsewhere.test', $error->getMessage(), 'user message stays neutral');
            Assert::same($detail->last(), $discovery->detail());
        },

    'a poisoned cache entry is re-validated on the way out, not trusted' =>
        static function (): void {
            // The cache is shared mutable state: an entry written by an older, looser build of
            // this plugin - or by anything else with access to the site cache - must not be able
            // to introduce an http JWKS or a foreign issuer. Revalidation on read is what the
            // docblock promises, so it gets a guard (review finding M46).
            $clock = new FixedClock();
            $cache = new InMemoryKeyValueCache($clock);
            $http = new FakeHttpClient();
            $http->onJson(OidcFixtures::discoveryUrl(), OidcFixtures::discovery());

            $config = new OidcConnectionConfig(
                OidcFixtures::ISSUER,
                OidcFixtures::CLIENT_ID,
                OidcFixtures::CLIENT_SECRET,
                OidcFixtures::REDIRECT_URI
            );

            $cacheKey = 'keyway.oidc.discovery.' . hash('sha256', $config->discoveryUrl());

            $poisoned = [
                [OidcFixtures::discovery(['jwks_uri' => 'http://idp.example.test/certs']), IdentityReaderException::DISCOVERY_FAILED],
                [OidcFixtures::discovery(['issuer' => 'https://attacker.test/realm']), IdentityReaderException::ISSUER_MISMATCH],
            ];

            foreach ($poisoned as [$document, $expected]) {
                $cache->set($cacheKey, $document, 3600);

                $discovery = new OidcDiscovery($config, $http, $cache, $clock, new RejectionDetail());
                $error = Assert::throws(
                    IdentityReaderException::class,
                    static fn () => $discovery->metadata()
                );
                Assert::same($expected, $error->reasonCode());
            }

            Assert::same(0, $http->callCount(OidcFixtures::discoveryUrl()), 'the cache was really used');
        },

    // ------------------------------------------------------------------- C5: choosing the key

    'the kid in the header selects the key' =>
        static function () use ($make): void {
            [, $keys] = $make(['jwks' => OidcFixtures::jwks(['rsa', 'ec'])]);

            Assert::same('RS256', $keys->keyFor(OidcFixtures::KID_RSA)->getAlgorithm());
            Assert::same('ES256', $keys->keyFor(OidcFixtures::KID_EC)->getAlgorithm());
        },

    'a symmetric key published in the JWKS is never usable for verification' =>
        static function () use ($make): void {
            // This is the one that would end the plugin. firebase/php-jwt parses `kty: oct`
            // happily (JWK.php:187-192) and hands back a Key holding the secret - and a JWKS is
            // a public document, so that secret is public too. Anyone could then sign their own
            // HS256 id token. Proven twice: the library WOULD hand it over, and the key store
            // refuses to.
            $document = OidcFixtures::jwks(['rsa', 'oct']);

            $libraryKeys = JWK::parseKeySet($document);
            Assert::true(
                ($libraryKeys[OidcFixtures::KID_OCT] ?? null) instanceof Key,
                'the library does return the symmetric key'
            );
            Assert::same('HS256', $libraryKeys[OidcFixtures::KID_OCT]->getAlgorithm());

            [, $keys] = $make(['jwks' => $document]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor(OidcFixtures::KID_OCT)
            );
            Assert::same(IdentityReaderException::KEY_NOT_FOUND, $error->reasonCode());

            // The healthy key in the same set still works: the filter drops one entry, not all.
            Assert::same('RS256', $keys->keyFor(OidcFixtures::KID_RSA)->getAlgorithm());
        },

    'an encryption key from the same JWKS cannot verify a signature' =>
        static function () use ($make): void {
            // Keycloak publishes exactly this: one `use: sig` key and one `use: enc` RSA-OAEP
            // key, in one document.
            $document = OidcFixtures::jwks(['rsa', 'enc']);

            $libraryKeys = JWK::parseKeySet($document);
            Assert::true(
                ($libraryKeys[OidcFixtures::KID_ENC] ?? null) instanceof Key,
                'the library does return the encryption key'
            );

            [, $keys] = $make(['jwks' => $document]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor(OidcFixtures::KID_ENC)
            );
            Assert::same(IdentityReaderException::KEY_NOT_FOUND, $error->reasonCode());
        },

    'a key published without alg is still usable, because Entra ID publishes them that way' =>
        static function () use ($make): void {
            $document = OidcFixtures::jwks(['rsa']);
            unset($document['keys'][0]['alg']);

            // Without a per-key default, the library refuses the whole set.
            Assert::throws(
                UnexpectedValueException::class,
                static fn () => JWK::parseKeySet($document)
            );

            [, $keys] = $make(['jwks' => $document]);

            Assert::same('RS256', $keys->keyFor(OidcFixtures::KID_RSA)->getAlgorithm());
        },

    'a key labelled with an algorithm its type cannot produce is dropped' =>
        static function () use ($make): void {
            $document = OidcFixtures::jwks(['rsa']);
            $document['keys'][0]['alg'] = 'ES256';

            [, $keys] = $make(['jwks' => $document]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor(OidcFixtures::KID_RSA)
            );
            Assert::same(IdentityReaderException::KEY_NOT_FOUND, $error->reasonCode());
        },

    'one unparsable entry does not take the whole key set down' =>
        static function () use ($make): void {
            $document = OidcFixtures::jwks(['rsa']);
            array_unshift($document['keys'], ['kty' => 'RSA', 'kid' => 'broken', 'alg' => 'RS256']);

            Assert::throws(
                UnexpectedValueException::class,
                static fn () => JWK::parseKeySet($document),
                'the library gives up on the first bad key'
            );

            [, $keys] = $make(['jwks' => $document]);

            Assert::same('RS256', $keys->keyFor(OidcFixtures::KID_RSA)->getAlgorithm());
        },

    'a token with no kid is accepted only when there is exactly one key to mean' =>
        static function () use ($make): void {
            [, $single] = $make(['jwks' => OidcFixtures::jwks(['rsa'])]);
            Assert::same('RS256', $single->keyFor(null)->getAlgorithm());

            [, $several] = $make(['jwks' => OidcFixtures::jwks(['rsa', 'ec'])]);
            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $several->keyFor(null),
                'trying every key in turn is exactly what C5 forbids'
            );
            Assert::same(IdentityReaderException::KEY_NOT_FOUND, $error->reasonCode());
        },

    'an unknown kid buys exactly one refresh, and a rotated key is then found' =>
        static function () use ($make): void {
            [, $keys, $http] = $make([
                'jwks' => OidcFixtures::jwks(['rsa']),
                'jwksQueue' => [OidcFixtures::jwks(['rsa', 'rotated'])],
            ]);

            Assert::same('RS256', $keys->keyFor(OidcFixtures::KID_RSA)->getAlgorithm());
            Assert::same(1, $http->callCount(OidcFixtures::jwksUri()));

            // The rotated key was not in the first document; the refresh finds it.
            Assert::same('RS256', $keys->keyFor(OidcFixtures::KID_RSA_ROTATED)->getAlgorithm());
            Assert::same(2, $http->callCount(OidcFixtures::jwksUri()));
        },

    'a stream of invented kids cannot turn this site into a load generator' =>
        static function () use ($make): void {
            [, $keys, $http] = $make();

            foreach (['made-up-1', 'made-up-2', 'made-up-3'] as $kid) {
                $error = Assert::throws(
                    IdentityReaderException::class,
                    static fn () => $keys->keyFor($kid)
                );
                Assert::same(IdentityReaderException::KEY_NOT_FOUND, $error->reasonCode());
            }

            // One initial fetch plus one refresh for the first unknown kid. The second and third
            // are inside MIN_REFRESH_INTERVAL and fetch nothing.
            Assert::same(2, $http->callCount(OidcFixtures::jwksUri()), 'rate limited per C5');
        },

    'the same kid never buys a second refresh, even after the rate window' =>
        static function () use ($make, $now): void {
            [, $keys, $http, , $clock] = $make(['now' => $now]);

            Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor('made-up-1')
            );
            Assert::same(2, $http->callCount(OidcFixtures::jwksUri()));

            // The clock MUST move past MIN_REFRESH_INTERVAL here. Without it the second attempt
            // is blocked by the time window and the per-kid rule is never exercised - that was
            // the defect the turn 4 review measured (mutation M38 survived).
            $clock->advance(120);

            Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor('made-up-1')
            );
            Assert::same(2, $http->callCount(OidcFixtures::jwksUri()), 'one refresh per kid');

            // A different kid, now outside the window, still gets its own single chance: the
            // per-kid rule is a ledger, not a global freeze.
            Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor('made-up-9')
            );
            Assert::same(3, $http->callCount(OidcFixtures::jwksUri()));
        },

    'a key set with nothing usable in it is a rejection, not an empty accept' =>
        static function () use ($make): void {
            [, $keys] = $make(['jwks' => OidcFixtures::jwks(['oct'])]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $keys->keyFor(OidcFixtures::KID_OCT)
            );
            Assert::same(IdentityReaderException::KEY_NOT_FOUND, $error->reasonCode());
        },
];
