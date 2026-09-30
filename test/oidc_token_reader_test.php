<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Keyway\Sso\Core\Http\HttpResponse;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\RejectionDetailInterface;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Core\Support\InMemoryKeyValueCache;
use Keyway\Sso\Protocol\Oidc\JwksKeyStore;
use Keyway\Sso\Protocol\Oidc\OidcAuthorizationRequest;
use Keyway\Sso\Protocol\Oidc\OidcConnectionConfig;
use Keyway\Sso\Protocol\Oidc\OidcDiscovery;
use Keyway\Sso\Protocol\Oidc\OidcTokenReader;
use Keyway\Sso\Protocol\Oidc\RejectionDetail;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FakeHttpClient;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\InMemoryReplayGuard;
use Keyway\Sso\Test\Support\InMemoryStateStorage;
use Keyway\Sso\Test\Support\OidcFixtures;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * The malicious half of the OIDC contract (IdentityReaderInterface, sections A and C).
 *
 * Every case runs a whole login: OidcAuthorizationRequest issues the state, the nonce and the
 * PKCE verifier, the fake provider mints an id token against the nonce it was given - checking
 * the verifier the way a real token endpoint does - and OidcTokenReader reads the callback. The
 * tokens are really signed with keys generated in-process, so a fixture that is "not actually
 * signed" cannot pass for a working signature check.
 *
 * One defect per fixture, and every rejection is asserted on its reason code rather than on the
 * bare fact that something was thrown: "it threw" is satisfied by a reader that rejects
 * everything, the happy path included.
 */
if (!class_exists(JWT::class)) {
    fwrite(STDOUT, "oidc_token_reader          skipped: vendor absent (run composer install)\n");

    return [];
}

$now = time();

/**
 * Builds one login, end to end, and hands back everything a case might want to assert on.
 *
 * @param array<string, mixed> $o
 * @return array<string, mixed>
 */
$flow = static function (array $o = []) use ($now): array {
    $clockNow = (int)($o['now'] ?? $now);
    $clock = new FixedClock($clockNow);
    $cache = new InMemoryKeyValueCache($clock);
    $http = new FakeHttpClient();

    $http->onJson(OidcFixtures::discoveryUrl(), $o['discovery'] ?? OidcFixtures::discovery());
    $http->onJson(OidcFixtures::jwksUri(), $o['jwks'] ?? OidcFixtures::jwks(['rsa']));

    $config = new OidcConnectionConfig(
        OidcFixtures::ISSUER,
        OidcFixtures::CLIENT_ID,
        array_key_exists('secret', $o) ? $o['secret'] : OidcFixtures::CLIENT_SECRET,
        OidcFixtures::REDIRECT_URI,
        ['openid', 'profile', 'email'],
        (int)($o['skew'] ?? 60),
        (bool)($o['fetchUserinfo'] ?? false)
    );

    $detail = new RejectionDetail();
    $discovery = new OidcDiscovery($config, $http, $cache, $clock, $detail);
    $keys = new JwksKeyStore($config, $discovery, $http, $cache, $clock, $detail);

    // One random source for both the state store and the authorization request: two independent
    // deterministic sources would hand out the same bytes twice and quietly make the nonce equal
    // the state id.
    $random = new SequenceRandomSource();
    $stateStore = new StateStore(
        $o['storage'] ?? new InMemoryStateStorage(),
        $clock,
        $random,
        new RedirectGuard(),
        300
    );
    $guard = $o['guard'] ?? new InMemoryReplayGuard($clock);

    $reader = new OidcTokenReader(
        $config,
        $discovery,
        $keys,
        $clock,
        $stateStore,
        $guard,
        $http,
        $detail
    );

    $authorization = new OidcAuthorizationRequest($config, $discovery, $stateStore, $random);
    $redirect = $authorization->start($o['returnUrl'] ?? '/admin');

    parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $query);
    $nonce = (string)($query['nonce'] ?? '');
    $challenge = (string)($query['code_challenge'] ?? '');

    $code = (string)($o['code'] ?? 'authorization-code-4f2a9c');
    $accessToken = array_key_exists('accessToken', $o) ? $o['accessToken'] : 'access-token-8b71e0';

    $claims = [
        '__now' => $clockNow,
        'nonce' => $nonce,
        'exp' => $clockNow + 300,
        'iat' => $clockNow,
        'c_hash' => OidcFixtures::tokenHash($code),
    ];

    if (is_string($accessToken)) {
        $claims['at_hash'] = OidcFixtures::tokenHash($accessToken);
    }

    foreach ($o['claims'] ?? [] as $name => $value) {
        $claims[$name] = $value;
    }

    $idToken = $o['idToken'] ?? OidcFixtures::idToken($claims, $o['tokenOptions'] ?? []);
    if (is_callable($idToken)) {
        $idToken = $idToken($claims, $code, $accessToken);
    }

    $body = $o['tokenResponse'] ?? array_filter([
        'access_token' => $accessToken,
        'token_type' => 'Bearer',
        'expires_in' => 300,
        'id_token' => $idToken,
    ], static fn ($value): bool => $value !== null);

    // Bends one field of an otherwise complete token response (null removes the field) without
    // the case having to rebuild the id token, which only exists inside this closure.
    if (is_array($body)) {
        foreach ($o['tokenBody'] ?? [] as $name => $value) {
            if ($value === null) {
                unset($body[$name]);
                continue;
            }

            $body[$name] = $value;
        }
    }

    if (is_array($body)) {
        $response = static function (array $form) use ($body, $challenge): HttpResponse {
            // The fake provider enforces PKCE exactly as a real one does: no verifier, or a
            // verifier that does not hash to the challenge we sent, and there is no token.
            $verifier = $form['code_verifier'] ?? '';
            if ($verifier === '' || OidcAuthorizationRequest::challenge($verifier) !== $challenge) {
                return FakeHttpClient::json(['error' => 'invalid_grant'], 400);
            }

            return FakeHttpClient::json($body);
        };
        $http->on(OidcFixtures::tokenEndpoint(), $response);
    } else {
        $http->on(OidcFixtures::tokenEndpoint(), $body);
    }

    if (array_key_exists('userinfo', $o)) {
        $http->on(
            OidcFixtures::userinfoEndpoint(),
            is_array($o['userinfo']) ? FakeHttpClient::json($o['userinfo']) : $o['userinfo']
        );
    }

    $request = array_merge(
        ['code' => $code, 'state' => (string)($query['state'] ?? '')],
        $o['request'] ?? []
    );

    foreach ($request as $name => $value) {
        if ($value === null) {
            unset($request[$name]);
        }
    }

    return [
        'reader' => $reader,
        'authorization' => $authorization,
        'read' => static fn (): IdentityPayload => $reader->read($request),
        'request' => $request,
        'query' => $query,
        'url' => $redirect->url,
        'state' => $redirect->state,
        'stateStore' => $stateStore,
        'http' => $http,
        'detail' => $detail,
        'guard' => $guard,
        'nonce' => $nonce,
        'code' => $code,
        'accessToken' => $accessToken,
        'clock' => $clock,
    ];
};

/**
 * @param array<string, mixed> $o
 */
$rejects = static function (string $expectedReason, array $o) use ($flow): IdentityReaderException {
    $context = $flow($o);

    $error = Assert::throws(IdentityReaderException::class, $context['read']);

    Assert::same(
        $expectedReason,
        $error instanceof IdentityReaderException ? $error->reasonCode() : '',
        'rejection reason'
    );

    /** @var IdentityReaderException $error */
    return $error;
};

return [
    // ------------------------------------------------------- C7/C8/C11: the start of the login

    'the authorization url carries state, a fresh nonce and an S256 challenge' =>
        static function () use ($flow): void {
            $context = $flow();
            $query = $context['query'];

            Assert::same('code', $query['response_type']);
            Assert::same(OidcFixtures::CLIENT_ID, $query['client_id']);
            Assert::same(OidcFixtures::REDIRECT_URI, $query['redirect_uri']);
            Assert::contains('openid', (string)$query['scope']);
            Assert::same('S256', $query['code_challenge_method']);
            Assert::notSame('', $query['nonce']);
            Assert::notSame('', $query['state']);

            // The verifier is server-side (C8) and the challenge in the URL is its SHA-256.
            $validation = $context['stateStore']->consume((string)$query['state']);
            Assert::true($validation->valid);

            $verifier = $validation->context()['code_verifier'] ?? '';
            Assert::notSame('', $verifier);
            Assert::same(
                OidcAuthorizationRequest::challenge($verifier),
                $query['code_challenge'],
                'the URL carries the hash, never the verifier'
            );
            Assert::same($validation->context()['nonce'] ?? '', $query['nonce']);

            // Neither secret may be recoverable from anything the browser holds.
            Assert::notContains($verifier, $context['url']);
            Assert::notContains($verifier, (string)$query['state']);
            Assert::notContains((string)$query['nonce'], (string)$query['state']);
        },

    'two logins from the same connection never share a nonce or a verifier' =>
        static function () use ($flow): void {
            // Both logins are started from one OidcAuthorizationRequest, on one random source:
            // the property under test is that nothing is cached or reused between calls, and two
            // separately built test doubles would have been fed the same deterministic bytes and
            // proven nothing at all.
            $context = $flow();
            $second = $context['authorization']->start('/admin');

            parse_str((string)parse_url($second->url, PHP_URL_QUERY), $query);

            Assert::notSame($context['query']['nonce'], $query['nonce']);
            Assert::notSame($context['query']['code_challenge'], $query['code_challenge']);
            Assert::notSame($context['query']['state'], $query['state']);
        },

    'nothing a caller passes in the state context can replace the nonce or the verifier' =>
        static function () use ($flow): void {
            // C7 and C8 rest entirely on these two values being the ones we generated. If glue
            // code - or a later refactor that pipes request data into $context - could set them,
            // both checks would verify the attacker's own value against itself.
            $context = $flow();
            $redirect = $context['authorization']->start('/admin', [
                'nonce' => 'attacker-chosen-nonce',
                'code_verifier' => 'attacker-chosen-verifier',
                'connection' => 'default',
            ]);

            parse_str((string)parse_url($redirect->url, PHP_URL_QUERY), $query);
            Assert::notSame('attacker-chosen-nonce', $query['nonce']);

            $validation = $context['stateStore']->consume((string)$redirect->state);
            Assert::true($validation->valid);
            Assert::same($query['nonce'], $validation->context()['nonce'] ?? '');
            Assert::notSame('attacker-chosen-verifier', $validation->context()['code_verifier'] ?? '');
            Assert::same('default', $validation->context()['connection'] ?? '', 'other context survives');
        },

    'a login state without a nonce and a verifier is refused, never run with the checks off' =>
        static function () use ($flow): void {
            // A state record not written by OidcAuthorizationRequest - an older build, a hand
            // rolled controller - would otherwise carry the flow forward with C7 and C8 silently
            // disabled. Fail closed is the only safe reading.
            // The storage is SHARED with the reader's own state store, otherwise the token would
            // simply be unknown to it and the case would pass without ever reaching the check.
            $storage = new InMemoryStateStorage();
            $context = $flow(['storage' => $storage]);
            $store = new StateStore(
                $storage,
                $context['clock'],
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );
            $token = $store->issue('/admin', ['protocol' => 'oidc']);

            $request = $context['request'];
            $request['state'] = $token->value;

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $context['reader']->read($request)
            );
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    // ------------------------------------------------------------------------- the happy path

    'a correctly signed id token is accepted and its claims come back untouched' =>
        static function () use ($flow): void {
            $payload = $flow()['read']();

            Assert::same('f:9d4e:test.user', $payload->nameId());
            Assert::same(OidcFixtures::ISSUER, $payload->issuer());
            Assert::same('session-index-1', $payload->sessionIndex());

            // A7: the name arrives spelled exactly as the provider sent it, capital G and all.
            Assert::true(in_array('Groups', $payload->names(), true), 'claim name kept verbatim');
            Assert::sameList(['craft-admins', 'craft-editors'], $payload->values('Groups'));
            Assert::sameList(['test.user@example.test'], $payload->values('email'));
        },

    'an ES256 token signed with the provider EC key is accepted' =>
        static function () use ($flow): void {
            $payload = $flow([
                'jwks' => OidcFixtures::jwks(['ec']),
                'tokenOptions' => ['alg' => 'ES256'],
            ])['read']();

            Assert::same('f:9d4e:test.user', $payload->nameId());
        },

    'the code exchange happens on the back channel, with the verifier and the credentials' =>
        static function () use ($flow): void {
            $context = $flow();
            $context['read']();

            $request = $context['http']->lastRequest(OidcFixtures::tokenEndpoint());
            Assert::notNull($request);

            $form = $request['form'];
            Assert::same('POST', $request['method']);
            Assert::same('authorization_code', $form['grant_type']);
            Assert::same($context['code'], $form['code']);
            Assert::same(OidcFixtures::REDIRECT_URI, $form['redirect_uri']);
            Assert::same(OidcFixtures::CLIENT_ID, $form['client_id']);
            Assert::same(OidcFixtures::CLIENT_SECRET, $form['client_secret']);
            Assert::same(
                (string)$context['query']['code_challenge'],
                OidcAuthorizationRequest::challenge($form['code_verifier']),
                'the verifier sent is the one the challenge was made from'
            );
        },

    'a public client with no secret completes the flow on PKCE alone' =>
        static function () use ($flow): void {
            $context = $flow(['secret' => null]);
            $payload = $context['read']();

            Assert::same('f:9d4e:test.user', $payload->nameId());

            $form = ($context['http']->lastRequest(OidcFixtures::tokenEndpoint()))['form'];
            Assert::false(array_key_exists('client_secret', $form), 'no empty secret is sent');
        },

    // -------------------------------------------------------------- C1/C2/C3: the allow list

    'alg none is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ALGORITHM_NOT_ALLOWED, [
                'idToken' => static fn (array $claims): string => OidcFixtures::rawToken(
                    ['alg' => 'none', 'typ' => 'JWT', 'kid' => OidcFixtures::KID_RSA],
                    $claims
                ),
            ]);
        },

    'a token with an allowed alg but no signature at all is refused' =>
        static function () use ($rejects): void {
            // Honest note about what this fixture does and does not prove: the reader's own
            // empty-signature check (C2) is defence in depth, and removing it does not make this
            // token pass - openssl simply fails to verify an empty signature one step later, with
            // the same reason code. The case is here because C2 must stay covered by SOMETHING,
            // not because it isolates our check.
            $rejects(IdentityReaderException::SIGNATURE_INVALID, [
                'idToken' => static fn (array $claims): string => OidcFixtures::rawToken(
                    ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => OidcFixtures::KID_RSA],
                    $claims
                ),
            ]);
        },

    'an id token segment outside the base64url alphabet is refused before any decoding' =>
        static function () use ($flow): void {
            $context = $flow([
                'idToken' => static function (array $claims): string {
                    // `+` is standard base64 but not base64url. It matters because
                    // JWT::urlsafeB64Decode() calls base64_decode() in non-strict mode
                    // (JWT.php:432-435), which silently drops what it does not recognise
                    // instead of reporting it.
                    [$header, $payload, $signature] = explode('.', OidcFixtures::idToken($claims));

                    return $header . '.' . substr($payload, 0, -1) . '+.' . $signature;
                },
            ]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            Assert::contains('base64url', $context['detail']->last());
        },

    'a five-segment JWE is refused rather than read as a JWS' =>
        static function () use ($flow): void {
            $context = $flow([
                'idToken' => static fn (array $claims): string =>
                    OidcFixtures::idToken($claims) . '.encrypted-key.initialisation-vector',
            ]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            Assert::contains('three-segment', $context['detail']->last());
        },

    'HS256 signed with the provider public key is refused' =>
        static function () use ($rejects): void {
            // The single most important case in this module. The IdP's public key is public by
            // definition, so an HMAC algorithm turns "anyone who can read the JWKS" into "anyone
            // who can mint an identity". The reason code matters here: ALGORITHM_NOT_ALLOWED
            // means our allow list rejected it before a key was even looked up. (With the allow
            // list removed the token is still refused one step later, by the key/algorithm
            // binding - the two gates overlap on purpose, and the code says which one fired.)
            $rejects(IdentityReaderException::ALGORITHM_NOT_ALLOWED, [
                'idToken' => static fn (array $claims): string => OidcFixtures::idToken(
                    $claims,
                    ['alg' => 'HS256', 'hmacKey' => OidcFixtures::publicKey('rsa')]
                ),
            ]);
        },

    'an HS256 token pointing at a symmetric key the provider published is refused' =>
        static function () use ($rejects): void {
            // The variant that would actually verify if either gate were missing: the JWKS
            // itself carries the HMAC secret (`kty: oct`), so the attacker does not need to
            // guess anything. Refused by the header allow list, and refused again by the key
            // filter that never lets an `oct` entry become a verification key.
            $rejects(IdentityReaderException::ALGORITHM_NOT_ALLOWED, [
                'jwks' => OidcFixtures::jwks(['rsa', 'oct']),
                'idToken' => static fn (array $claims): string => OidcFixtures::idToken(
                    $claims,
                    [
                        'alg' => 'HS256',
                        'kid' => OidcFixtures::KID_OCT,
                        'hmacKey' => OidcFixtures::OCT_SECRET,
                    ]
                ),
            ]);
        },

    'a genuinely valid signature with an off-list algorithm is still refused' =>
        static function () use ($rejects): void {
            // RS512 is real, safe cryptography and firebase/php-jwt supports it. It is refused
            // anyway, because the allow list is policy, not capability.
            $rejects(IdentityReaderException::ALGORITHM_NOT_ALLOWED, [
                'tokenOptions' => ['alg' => 'RS512'],
            ]);
        },

    'a header demanding critical extensions is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ALGORITHM_NOT_ALLOWED, [
                'idToken' => static fn (array $claims): string => OidcFixtures::rawToken(
                    [
                        'alg' => 'RS256',
                        'kid' => OidcFixtures::KID_RSA,
                        'crit' => ['http://example.test/exp'],
                    ],
                    $claims,
                    'not-a-real-signature'
                ),
            ]);
        },

    // ----------------------------------------------------------------- C5: kid and signatures

    'a token whose kid is unknown to the provider JWKS is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::KEY_NOT_FOUND, [
                'tokenOptions' => ['kid' => 'some-other-key'],
            ]);
        },

    'a token with no kid is refused when the provider publishes several keys' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::KEY_NOT_FOUND, [
                'jwks' => OidcFixtures::jwks(['rsa', 'ec']),
                'tokenOptions' => ['kid' => null],
            ]);
        },

    'a token signed by an unrelated key that claims the right kid is refused' =>
        static function () use ($rejects): void {
            // Proves the signature is genuinely verified rather than assumed from the kid.
            $rejects(IdentityReaderException::SIGNATURE_INVALID, [
                'tokenOptions' => ['signingKey' => 'foreign', 'kid' => OidcFixtures::KID_RSA],
            ]);
        },

    // ------------------------------------------------------------------------- C6: the claims

    'an id token from another issuer is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ISSUER_MISMATCH, [
                'claims' => ['iss' => 'https://idp.example.test/realms/other'],
            ]);
        },

    'an issuer that merely starts with ours is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ISSUER_MISMATCH, [
                'claims' => ['iss' => OidcFixtures::ISSUER . '.evil.test'],
            ]);
        },

    'an id token minted for another client is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::AUDIENCE_MISMATCH, [
                'claims' => ['aud' => 'some-other-client'],
            ]);
        },

    'several audiences without azp are refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::AUDIENCE_MISMATCH, [
                'claims' => ['aud' => [OidcFixtures::CLIENT_ID, 'reporting-api']],
            ]);
        },

    'several audiences with azp naming somebody else are refused' =>
        static function () use ($rejects): void {
            // The dangerous shape: a token issued in another client's login that happens to list
            // us as an extra audience. azp is the only claim that says who logged in where.
            $rejects(IdentityReaderException::AUDIENCE_MISMATCH, [
                'claims' => [
                    'aud' => [OidcFixtures::CLIENT_ID, 'reporting-api'],
                    'azp' => 'reporting-api',
                ],
            ]);
        },

    'an audience list carrying a non-string value cannot smuggle past the azp rule' =>
        static function () use ($rejects): void {
            // Measured hole from the turn 4 review: filtering non-strings out of `aud` made
            // `[us, 12345]` look single-valued, so azp - the only claim saying which client the
            // user actually logged in to - was never required.
            foreach ([12345, null, ['nested'], true] as $smuggled) {
                $rejects(IdentityReaderException::MALFORMED_RESPONSE, [
                    'claims' => ['aud' => [OidcFixtures::CLIENT_ID, $smuggled]],
                ]);
            }

            // Even with a correct azp: an audience we cannot read is not an audience we accept.
            $rejects(IdentityReaderException::MALFORMED_RESPONSE, [
                'claims' => [
                    'aud' => [OidcFixtures::CLIENT_ID, 12345],
                    'azp' => OidcFixtures::CLIENT_ID,
                ],
            ]);
        },

    'several audiences with azp naming us are accepted' =>
        static function () use ($flow): void {
            $payload = $flow([
                'claims' => [
                    'aud' => [OidcFixtures::CLIENT_ID, 'reporting-api'],
                    'azp' => OidcFixtures::CLIENT_ID,
                ],
            ])['read']();

            Assert::same('f:9d4e:test.user', $payload->nameId());
        },

    'an expired id token is refused' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'claims' => ['exp' => $now - 3600, 'iat' => $now - 3900],
            ]);
        },

    'an id token that expired within the configured skew is still accepted' =>
        static function () use ($flow, $now): void {
            // The skew is a tolerance, not a hole: 30 seconds inside a 60 second allowance.
            $payload = $flow(['claims' => ['exp' => $now - 30], 'skew' => 60])['read']();

            Assert::same('f:9d4e:test.user', $payload->nameId());
        },

    'an id token minted an hour ago is refused even though it has not expired' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'claims' => ['iat' => $now - 3600, 'exp' => $now + 3600],
            ]);
        },

    'an id token issued in the future is refused' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'claims' => ['iat' => $now + 600, 'exp' => $now + 900],
            ]);
        },

    'a future iat is caught by us even when nbf makes the library skip its own iat check' =>
        static function () use ($flow, $now): void {
            // firebase/php-jwt only checks `iat` when `nbf` is absent - JWT.php:179 reads
            // `!isset($payload->nbf) && isset($payload->iat) && ...`. With `nbf` present and
            // already in the past the library waves the token straight through, so the reader's
            // own `iat` check is the only thing between a pre-minted token and a session.
            $context = $flow([
                'claims' => ['nbf' => $now - 10, 'iat' => $now + 600, 'exp' => $now + 900],
            ]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::ASSERTION_EXPIRED, $error->reasonCode());
            Assert::contains(
                'issued in the future',
                $context['detail']->last(),
                'our iat check has to be the one that rejects, not the library'
            );
        },

    'an id token whose nbf has not arrived yet is refused' =>
        static function () use ($flow, $now): void {
            // Behaviour coverage, and honest about who does the work: the rejection here comes
            // from the library, not from checkTimes(). decode() pins JWT::$timestamp to our
            // clock and JWT::$leeway to our skew, which makes the library's nbf condition
            // (JWT.php:168, `nbf > timestamp + leeway`) character-for-character the same test as
            // ours (`nbf - skew > now`). Our nbf re-check is therefore defence in depth that
            // cannot fire while those two stay pinned together, and deleting it does NOT turn
            // this case red - measured, not assumed. Asserting the library's wording is what
            // keeps that fact visible: if the reason ever becomes 'Id token is not valid yet.',
            // the layering changed and somebody should know.
            $context = $flow([
                'claims' => ['nbf' => $now + 600, 'iat' => $now, 'exp' => $now + 900],
            ]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::ASSERTION_EXPIRED, $error->reasonCode());
            Assert::contains('outside its validity window', $context['detail']->last());
            Assert::contains('nbf', $context['detail']->last());
        },

    'an id token with no exp at all is refused' =>
        static function () use ($flow): void {
            // JWT.php:188 guards its expiry check on isset(), so a token that simply omits `exp`
            // never meets a library check at all: it is our check or nothing.
            $context = $flow(['claims' => ['exp' => null]]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::ASSERTION_EXPIRED, $error->reasonCode());
            Assert::contains(
                'no usable exp',
                $context['detail']->last(),
                'a missing exp is its own rejection, not an expiry comparison against null'
            );
        },

    'an id token with no iat at all is refused' =>
        static function () use ($flow): void {
            $context = $flow(['claims' => ['iat' => null]]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            Assert::contains(
                'no usable iat',
                $context['detail']->last(),
                'a missing iat is its own rejection, not an age comparison against null'
            );
        },

    'a token with no sub is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SUBJECT_MISSING, ['claims' => ['sub' => null]]);
        },

    'a whitespace-only sub is refused rather than mapped to an empty user' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SUBJECT_MISSING, ['claims' => ['sub' => "  \t "]]);
        },

    // ------------------------------------------------------------------------- C7: the nonce

    'an id token with no nonce is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::NONCE_MISMATCH, ['claims' => ['nonce' => null]]);
        },

    'an id token carrying another session nonce is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::NONCE_MISMATCH, [
                'claims' => ['nonce' => 'nonce-from-a-different-login'],
            ]);
        },

    // -------------------------------------------------------------------- C9: at_hash, c_hash

    'a wrong at_hash is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::TOKEN_HASH_MISMATCH, [
                'claims' => ['at_hash' => OidcFixtures::tokenHash('somebody-elses-access-token')],
            ]);
        },

    'a wrong c_hash is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::TOKEN_HASH_MISMATCH, [
                'claims' => ['c_hash' => OidcFixtures::tokenHash('another-authorization-code')],
            ]);
        },

    'an at_hash we cannot check is a rejection, never a pass' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::TOKEN_HASH_MISMATCH, [
                'accessToken' => null,
                'claims' => ['at_hash' => OidcFixtures::tokenHash('access-token-8b71e0')],
            ]);
        },

    // ------------------------------------------------------------------------ C10: userinfo

    'userinfo claims are merged only when the subject agrees, and never win' =>
        static function () use ($flow): void {
            $payload = $flow([
                'fetchUserinfo' => true,
                'userinfo' => [
                    'sub' => 'f:9d4e:test.user',
                    'email' => 'rewritten@evil.test',
                    'department' => 'Engineering',
                ],
            ])['read']();

            Assert::sameList(['Engineering'], $payload->values('department'), 'extra claim added');
            Assert::sameList(
                ['test.user@example.test'],
                $payload->values('email'),
                'the signed id token wins over the unsigned userinfo document'
            );
        },

    'a userinfo document about a different subject is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SUBJECT_MISMATCH, [
                'fetchUserinfo' => true,
                'userinfo' => ['sub' => 'f:9d4e:someone.else', 'email' => 'someone@example.test'],
            ]);
        },

    'a signed userinfo response is refused rather than parsed unverified' =>
        static function () use ($flow): void {
            $context = $flow([
                'fetchUserinfo' => true,
                'userinfo' => new HttpResponse(
                    200,
                    'eyJhbGciOiJSUzI1NiJ9.e30.signature',
                    ['Content-Type' => 'application/jwt']
                ),
            ]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            // Without the media type gate the same body would merely fail to parse as JSON. The
            // point is that we refuse the path on sight, not that this fixture is unparsable.
            Assert::contains('application/jwt', $context['detail']->last());
        },

    'userinfo is never called before the id token verified' =>
        static function () use ($flow): void {
            $context = $flow([
                'fetchUserinfo' => true,
                'userinfo' => ['sub' => 'f:9d4e:test.user'],
                'tokenOptions' => ['signingKey' => 'foreign', 'kid' => OidcFixtures::KID_RSA],
            ]);

            Assert::throws(IdentityReaderException::class, $context['read']);
            Assert::same(
                0,
                $context['http']->callCount(OidcFixtures::userinfoEndpoint()),
                'a rejected token must not trigger a userinfo call'
            );
        },

    // ------------------------------------------------------------------------ C11: the state

    'a callback with no state is refused before anything is exchanged' =>
        static function () use ($flow): void {
            $context = $flow(['request' => ['state' => null]]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
            Assert::same(
                0,
                $context['http']->callCount(OidcFixtures::tokenEndpoint()),
                'no state, no code exchange'
            );
        },

    'a forged state value is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::UNSOLICITED_RESPONSE, [
                'request' => ['state' => 'AAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBB'],
            ]);
        },

    'the same callback cannot be replayed' =>
        static function () use ($flow): void {
            $context = $flow();

            Assert::same('f:9d4e:test.user', $context['read']()->nameId());

            $error = Assert::throws(IdentityReaderException::class, $context['read']);
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    'a callback with no code is refused' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::MALFORMED_RESPONSE, [
                'request' => ['code' => null],
            ]);
        },

    // ------------------------------------------------------------------------- A5: single use

    'an id token jti is accepted once and never again' =>
        static function () use ($flow, $now): void {
            // The same clock the flow pins its reader to. The guard honours $expiresAt, so a
            // wall-clock guard would sweep against a different clock than the one that set the
            // horizon - green today only because the horizon is 360 s wide.
            $guard = new InMemoryReplayGuard(new FixedClock($now));

            Assert::same(
                'f:9d4e:test.user',
                $flow(['guard' => $guard, 'claims' => ['jti' => 'one-time-only']])['read']()->nameId()
            );

            // A second, otherwise perfect login carrying the same jti: fresh state, fresh nonce,
            // valid signature, and still refused.
            $error = Assert::throws(
                IdentityReaderException::class,
                $flow(['guard' => $guard, 'claims' => ['jti' => 'one-time-only']])['read']
            );
            Assert::same(IdentityReaderException::REPLAYED_ASSERTION, $error->reasonCode());
        },

    // ------------------------------------------------------------- the provider misbehaving

    'a login the provider refused is not an identity' =>
        static function () use ($flow): void {
            $context = $flow(['request' => ['error' => 'access_denied']]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);
            Assert::same(IdentityReaderException::STATUS_NOT_SUCCESS, $error->reasonCode());
            Assert::same(0, $context['http']->callCount(OidcFixtures::tokenEndpoint()));
        },

    'a token endpoint error is refused even when the body carries a usable id token' =>
        static function () use ($rejects, $now): void {
            // The status check has to be isolated: an HTTP 400 with no id_token is caught one
            // step later by the parser, with the same reason code, and proves nothing about
            // whether the status was ever looked at (review finding M22/P2).
            $rejects(IdentityReaderException::MALFORMED_RESPONSE, [
                'tokenResponse' => FakeHttpClient::json([
                    'access_token' => 'access-token-8b71e0',
                    'token_type' => 'Bearer',
                    'id_token' => OidcFixtures::idToken(
                        ['__now' => $now, 'nonce' => 'irrelevant-here']
                    ),
                ], 400),
            ]);
        },

    'a token response with no id token is refused' =>
        static function () use ($rejects): void {
            // An access token on its own says nothing verifiable about who is logging in.
            $rejects(IdentityReaderException::MALFORMED_RESPONSE, [
                'tokenResponse' => FakeHttpClient::json([
                    'access_token' => 'access-token-8b71e0',
                    'token_type' => 'Bearer',
                ]),
            ]);
        },

    'a token response carrying only a parsable access token is still refused for the id token' =>
        static function () use ($flow, $now): void {
            // Keycloak issues JWT access tokens by default, so "no id_token" does not imply
            // "nothing in this response parses". If the reader ever fell back to access_token,
            // this one would travel all the way to the audience check before being refused -
            // a rejection about the wrong thing, one step too late.
            $context = $flow([
                'tokenBody' => [
                    'id_token' => null,
                    'access_token' => OidcFixtures::idToken(['__now' => $now, 'aud' => 'account']),
                ],
            ]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            Assert::contains(
                'no id_token',
                $context['detail']->last(),
                'the rejection has to name the missing id token, not the access token it is not'
            );
        },

    'a token response with a token type other than bearer is refused' =>
        static function () use ($flow): void {
            $context = $flow(['tokenBody' => ['token_type' => 'mac']]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            Assert::contains('unsupported token type', $context['detail']->last());
        },

    'an unreachable token endpoint is a transport failure, not a malformed token' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::DISCOVERY_FAILED, [
                'tokenResponse' => new HttpTransportException('connection timed out'),
            ]);
        },

    // ------------------------------------------------------------------ A8: failure discipline

    // The detail is what LoginFlow puts in the diagnostics row, and it only gets there through
    // RejectionDetailInterface: a reader that stops implementing it goes quiet with every
    // LoginFlow test still green, because those run on a stand-in.
    'a wrong client secret is named in the detail the diagnostics row is built from' =>
        static function () use ($flow): void {
            $context = $flow(['tokenResponse' => FakeHttpClient::json(['error' => 'invalid_client'], 401)]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
            Assert::true($context['reader'] instanceof RejectionDetailInterface, 'LoginFlow can ask for the detail');
            Assert::same('Token endpoint answered HTTP 401: invalid_client.', $context['reader']->detail());
        },

    // Since 1.0.2 the detail is shown in the administrator's panel. The callback's `error` is
    // typed by whoever holds a state, and anyone can hold one by starting a login.
    'only something shaped like an OAuth error code is quoted from the callback' =>
        static function () use ($flow): void {
            $context = $flow(['request' => ['error' => 'Your licence expired - renew at https://evil.example/pay']]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::STATUS_NOT_SUCCESS, $error->reasonCode());
            Assert::same('Identity provider returned the error "(unreadable)".', $context['reader']->detail());

            $plain = $flow(['request' => ['error' => 'access_denied']]);
            Assert::throws(IdentityReaderException::class, $plain['read']);
            Assert::contains('"access_denied"', $plain['reader']->detail(), 'a real code is still quoted');

            // `$` alone matches before a trailing newline; the pattern must not.
            $trailing = $flow(['request' => ['error' => "access_denied\n"]]);
            Assert::throws(IdentityReaderException::class, $trailing['read']);
            Assert::contains('(unreadable)', $trailing['reader']->detail());
        },

    'only something shaped like an OAuth error code is quoted from the token endpoint' =>
        static function () use ($flow): void {
            $context = $flow(['tokenResponse' => FakeHttpClient::json(['error' => str_repeat('x', 65)], 400)]);

            Assert::throws(IdentityReaderException::class, $context['read']);
            Assert::same('Token endpoint answered HTTP 400: (unreadable).', $context['reader']->detail());

            $missing = $flow(['tokenResponse' => FakeHttpClient::json(['message' => 'nope'], 400)]);
            Assert::throws(IdentityReaderException::class, $missing['read']);
            Assert::same('Token endpoint answered HTTP 400: no error code.', $missing['reader']->detail());
        },

    'the login screen never learns why, and the diagnostics record always does' =>
        static function () use ($flow): void {
            $context = $flow(['claims' => ['nonce' => 'nonce-from-a-different-login']]);

            $error = Assert::throws(IdentityReaderException::class, $context['read']);

            Assert::same(IdentityReaderException::NONCE_MISMATCH, $error->reasonCode());
            Assert::notContains('nonce-from-a-different-login', $error->getMessage());
            Assert::notContains('eyJ', $error->getMessage(), 'no raw token in the user message');
            Assert::contains('nonce', $context['detail']->last(), 'the administrator gets the why');
            Assert::same($context['detail']->last(), $context['reader']->detail());
        },

    'a hostile JWT::$leeway set elsewhere in the process cannot extend a token lifetime' =>
        static function () use ($flow, $now): void {
            // JWT::$leeway and JWT::$timestamp are public static properties of the library
            // (vendor/firebase/php-jwt/src/JWT.php:43 and :52), so ANY code in the same PHP
            // process - another Craft plugin, a stray test helper - can widen every time check
            // the library makes. The reader pins both to its own clock for the duration of the
            // call, re-checks every bound itself afterwards, and restores what it found.
            $previousLeeway = JWT::$leeway;
            $previousTimestamp = JWT::$timestamp;

            JWT::$leeway = 86400;
            JWT::$timestamp = $now - 86400;

            try {
                $error = Assert::throws(
                    IdentityReaderException::class,
                    $flow(['claims' => ['exp' => $now - 3600, 'iat' => $now - 3900]])['read']
                );
                Assert::same(IdentityReaderException::ASSERTION_EXPIRED, $error->reasonCode());

                // A valid login still works, and the globals are left exactly as they were.
                Assert::same('f:9d4e:test.user', $flow()['read']()->nameId());
                Assert::same(86400, JWT::$leeway, 'the reader restores what it borrowed');
                Assert::same($now - 86400, JWT::$timestamp);
            } finally {
                JWT::$leeway = $previousLeeway;
                JWT::$timestamp = $previousTimestamp;
            }
        },

    'the reader announces its protocol for the diagnostics panel' =>
        static function () use ($flow): void {
            Assert::same('oidc', $flow()['reader']->protocol());
        },
];
