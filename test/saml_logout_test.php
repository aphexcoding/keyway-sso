<?php

declare(strict_types=1);

use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Protocol\Saml\InboundLogoutRequest;
use Keyway\Sso\Protocol\Saml\SamlConnectionConfig;
use Keyway\Sso\Protocol\Saml\SamlLogoutRequest;
use Keyway\Sso\Protocol\Saml\SamlLogoutRequestReader;
use Keyway\Sso\Protocol\Saml\SamlLogoutResponse;
use Keyway\Sso\Protocol\Saml\SamlLogoutResponseReader;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\InMemoryReplayGuard;
use Keyway\Sso\Test\Support\InMemoryStateStorage;
use Keyway\Sso\Test\Support\SamlFixtures;
use Keyway\Sso\Test\Support\SamlLogoutFixtures;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * SAML Single Logout, all four protocol paths.
 *
 * Two of them read a document written by somebody else - an IdP-initiated LogoutRequest and the
 * IdP's answer to ours - and a LogoutRequest is the one SAML message whose whole purpose is to
 * END a session. So the fixtures here are really signed with a real RSA key and every rejection
 * is asserted on its reason code, never on the bare fact that something was thrown: "it threw"
 * is satisfied by a reader that refuses everything, including the happy path, and a logout that
 * always fails looks exactly like a logout that always succeeds to anybody not reading the logs.
 *
 * The two outgoing paths are pinned to FixedClock and SequenceRandomSource, and their signature
 * is verified here with OpenSSL against the SP certificate - asserting that a `Signature=`
 * parameter is present would be satisfied by a class that signs the wrong string.
 */
if (!class_exists(\OneLogin\Saml2\Utils::class) || !function_exists('gzdeflate')) {
    fwrite(STDOUT, "saml_logout                skipped: vendor or ext-zlib absent\n");

    return [];
}

$now = 1_700_000_000;

/** Our own key pair. Unrelated to the IdP's, which is the point: we sign, they verify. */
$spKey = static fn (): string => SamlFixtures::foreignKey();
$spCert = static fn (): string => SamlFixtures::foreignCert();

/**
 * @param array<string, mixed> $options
 */
$makeConfig = static function (array $options = []) use ($spKey): SamlConnectionConfig {
    return new SamlConnectionConfig(
        (string)($options['idpEntityId'] ?? SamlFixtures::IDP_ENTITY_ID),
        SamlFixtures::cert(),
        SamlFixtures::SP_ENTITY_ID,
        SamlFixtures::ACS_URL,
        SamlFixtures::IDP_SSO_URL,
        array_key_exists('spPrivateKey', $options) ? $options['spPrivateKey'] : $spKey(),
        (int)($options['skew'] ?? 60),
        array_key_exists('idpSloUrl', $options) ? $options['idpSloUrl'] : SamlLogoutFixtures::IDP_SLO_URL,
        array_key_exists('spSloUrl', $options) ? $options['spSloUrl'] : SamlLogoutFixtures::SP_SLO_URL
    );
};

/**
 * @param array<string, mixed> $options
 * @return array{0: SamlLogoutRequestReader, 1: InMemoryReplayGuard}
 */
$makeRequestReader = static function (array $options = []) use ($makeConfig, $now): array {
    $clock = new FixedClock((int)($options['now'] ?? $now));

    // The guard gets the SAME clock as the reader. It honours $expiresAt, so wiring it to the
    // wall clock would let every entry expire instantly against a fixture dated 2023 - and a
    // registry that forgets at once is a registry that never refuses anything.
    $guard = $options['guard'] ?? new InMemoryReplayGuard($clock);

    return [new SamlLogoutRequestReader($makeConfig($options), $clock, $guard), $guard];
};

/**
 * A response reader plus a state token already carrying a logout request id.
 *
 * @param array<string, mixed> $options
 * @return array{0: SamlLogoutResponseReader, 1: string}
 */
$makeResponseReader = static function (array $options = []) use ($makeConfig, $now): array {
    $clock = new FixedClock((int)($options['now'] ?? $now));
    $store = new StateStore(
        new InMemoryStateStorage(),
        $clock,
        new SequenceRandomSource(),
        new RedirectGuard(),
        300
    );

    $context = array_key_exists('context', $options)
        ? $options['context']
        : ['logout_request_id' => (string)($options['requestId'] ?? '_our_request_id')];

    $state = $store->issue('/admin', $context);

    return [new SamlLogoutResponseReader($makeConfig($options), $clock, $store), $state->value];
};

/** The query string of a URL we produced, as the IdP would receive it. */
$rawQuery = static fn (string $url): string => (string)parse_url($url, PHP_URL_QUERY);

/**
 * @return array<string, string> Raw, still-encoded parameters.
 */
$rawParams = static function (string $query): array {
    $out = [];
    foreach (explode('&', $query) as $pair) {
        [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
        $out[rawurldecode($name)] = $value;
    }

    return $out;
};

/** The XML inside a SAMLRequest/SAMLResponse parameter. */
$message = static function (string $query, string $param) use ($rawParams): string {
    $raw = $rawParams($query);

    return (string)gzinflate((string)base64_decode(rawurldecode($raw[$param] ?? ''), true));
};

/** Does the Signature parameter really cover the octets that were emitted? */
$signatureVerifies = static function (string $query, string $param) use ($rawParams, $spCert): bool {
    $raw = $rawParams($query);

    $signed = $param . '=' . ($raw[$param] ?? '');
    if (array_key_exists('RelayState', $raw)) {
        $signed .= '&RelayState=' . $raw['RelayState'];
    }
    $signed .= '&SigAlg=' . ($raw['SigAlg'] ?? '');

    $key = openssl_pkey_get_public(\OneLogin\Saml2\Utils::formatCert($spCert()));

    return $key !== false && openssl_verify(
        $signed,
        (string)base64_decode(rawurldecode($raw['Signature'] ?? ''), true),
        $key,
        OPENSSL_ALGO_SHA256
    ) === 1;
};

/**
 * @param array<string, mixed> $fixture
 */
$refusesRequest = static function (
    array $fixture,
    string $expectedReason,
    array $readerOptions = []
) use ($makeRequestReader): IdentityReaderException {
    [$reader] = $makeRequestReader($readerOptions);

    $error = Assert::throws(
        IdentityReaderException::class,
        static fn () => $reader->read(SamlLogoutFixtures::requestQuery($fixture)),
        $expectedReason
    );

    /** @var IdentityReaderException $error */
    Assert::same($expectedReason, $error->reasonCode(), 'reason code');

    return $error;
};

return [

    // -------------------------------------------------------------------------------
    // Path 3: an IdP-initiated LogoutRequest, the hostile one
    // -------------------------------------------------------------------------------

    'a signed IdP logout request is read into a subject to match, not an order to obey' =>
        static function () use ($makeRequestReader, $now): void {
            [$reader] = $makeRequestReader();

            $request = $reader->read(SamlLogoutFixtures::requestQuery([
                'now' => $now,
                'id' => '_logout_abc',
                'nameId' => 'alice@example.test',
                'sessionIndex' => '_session_7',
            ]));

            Assert::same('_logout_abc', $request->id, 'the id we must answer');
            Assert::same('alice@example.test', $request->subjectForResponse());
            Assert::same(1, $request->namedSessionCount());
            Assert::true($request->matches('alice@example.test', '_session_7'));
            Assert::same(
                'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
                $request->nameIdFormat
            );
            Assert::same('back-to-the-cp', rawurldecode((string)$request->rawRelayState));
        },

    'an unsigned logout request is refused, because it would be a session kill by GET' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'unsigned' => true],
                IdentityReaderException::SIGNATURE_MISSING
            );
        },

    'a logout request signed with somebody else certificate is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'signWith' => 'foreign'],
                IdentityReaderException::SIGNATURE_INVALID
            );
        },

    'a tampered signature is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'tamperSignature' => true],
                IdentityReaderException::SIGNATURE_INVALID
            );
        },

    'SHA-1 is not accepted as a signature algorithm, however correctly it was used' =>
        static function () use ($refusesRequest, $now): void {
            // The fixture really signs with SHA-1, so this case fails on the ALLOWLIST and not
            // on arithmetic: a reader that looked the algorithm up instead of allowing it would
            // verify this message successfully.
            $refusesRequest(
                ['now' => $now, 'sigAlg' => SamlLogoutFixtures::SIG_ALG_SHA1],
                IdentityReaderException::ALGORITHM_NOT_ALLOWED
            );
        },

    'an unknown signature algorithm is refused rather than guessed' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'sigAlg' => 'http://example.test/whatever'],
                IdentityReaderException::ALGORITHM_NOT_ALLOWED
            );
        },

    'the signature is checked over the octets as they arrived, not over a re-encoded copy' =>
        static function () use ($refusesRequest, $now): void {
            // Identical after decoding, different on the wire. A verifier that rebuilt the
            // signed string from parse_str() output would accept this.
            $refusesRequest(
                ['now' => $now, 'reEncoded' => true],
                IdentityReaderException::SIGNATURE_INVALID
            );
        },

    'a repeated SAMLRequest parameter is refused rather than resolved' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'duplicateMessage' => true],
                IdentityReaderException::MALFORMED_RESPONSE
            );
        },

    'a logout request from an issuer we do not trust is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'issuer' => 'https://evil.example.test/metadata'],
                IdentityReaderException::ISSUER_MISMATCH
            );
        },

    'a logout request addressed to a different endpoint is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'destination' => 'https://craft.example.test/sso/acs'],
                IdentityReaderException::DESTINATION_MISMATCH
            );
        },

    'a logout request with no Destination at all is refused, not waved through' =>
        static function () use ($refusesRequest, $now): void {
            // The federation replay: an administrator of another SP at the same IdP takes a
            // LogoutRequest issued for THEIR endpoint - one without a Destination - and sends the
            // identical, correctly signed URL here. Issuer matches, signature matches, the replay
            // guard sees a first use. Destination is the only field that says who it was for, and
            // Bindings 3.4.5.1 makes it mandatory on a signed message, which this always is.
            $refusesRequest(
                ['now' => $now, 'destination' => false],
                IdentityReaderException::DESTINATION_MISMATCH
            );
        },

    'a logout answer with no Destination at all is refused too' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'relayState' => $state,
                    'destination' => false,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::DESTINATION_MISMATCH, $error->reasonCode());
        },

    'the replay entry outlives the message, so a logout URL cannot be reused once it expires' =>
        static function () use ($makeConfig, $now): void {
            // Both clocks move together, like a real deployment where time passes between the
            // two requests; the guard honours the horizon the reader gave it.
            $clockNow = $now;
            $clock = new class ($clockNow) implements \Keyway\Sso\Core\Port\ClockInterface {
                public function __construct(private int &$now)
                {
                }

                public function now(): int
                {
                    return $this->now;
                }
            };

            $guard = new InMemoryReplayGuard($clock);
            $reader = new SamlLogoutRequestReader($makeConfig(), $clock, $guard);

            // The IdP's clock runs one skew ahead of ours - legal, that is what clockSkew is for.
            $query = SamlLogoutFixtures::requestQuery([
                'now' => $now,
                'id' => '_late_replay',
                'issueInstant' => $now + 60,
            ]);

            Assert::doesNotThrow(static fn () => $reader->read($query), 'first use');

            // Six minutes later the message is STILL inside the acceptance window, because that
            // window is measured from its IssueInstant. A registry entry timed from our own
            // now() would already be gone - and the same URL, lifted from browser history or a
            // proxy log, would end the session a second time.
            $clockNow = $now + 361;

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read($query)
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::REPLAYED_ASSERTION, $error->reasonCode());

            // The exact instant the margin exists for. With the IdP one skew ahead of us at the
            // first request and one skew behind at the second, the message stays acceptable
            // until IssueInstant + MAX_MESSAGE_AGE + 2 * skew. A horizon built with a single
            // skew expires HERE, while the message is still good - so the margin is two skews,
            // not one, and this is the case that tells the difference.
            $clockNow = $now + 420;

            $late = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read($query),
                'the last instant the message is still acceptable'
            );

            /** @var IdentityReaderException $late */
            Assert::same(IdentityReaderException::REPLAYED_ASSERTION, $late->reasonCode());
        },

    'every SessionIndex the IdP names travels up, not just the first' =>
        static function () use ($makeRequestReader, $now): void {
            [$reader] = $makeRequestReader();

            $request = $reader->read(SamlLogoutFixtures::requestQuery([
                'now' => $now,
                'sessionIndex' => '_session_a',
                'extraSessionIndex' => '_session_b',
            ]));

            // Ending one of two and answering Success reports a logout that did not happen.
            Assert::same(2, $request->namedSessionCount());
            Assert::true($request->matches('alice@example.test', '_session_a'));
            Assert::true($request->matches('alice@example.test', '_session_b'));
        },

    'a logout request older than the accepted window is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'issueInstant' => $now - 3600],
                IdentityReaderException::ASSERTION_EXPIRED
            );
        },

    'a logout request dated in the future is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'issueInstant' => $now + 3600],
                IdentityReaderException::ASSERTION_EXPIRED
            );
        },

    'a logout request whose own NotOnOrAfter has passed is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'issueInstant' => $now - 120, 'notOnOrAfter' => $now - 90],
                IdentityReaderException::ASSERTION_EXPIRED
            );
        },

    'a compression bomb is refused at the inflate ceiling, signed or not' =>
        static function () use ($makeRequestReader, $now): void {
            // A well-formed LogoutRequest that would be ACCEPTED if it fitted: same issuer, same
            // destination, same instant, correctly signed. The only thing wrong with it is that
            // it inflates to ~2 MB from a couple of kilobytes on the wire. Without the ceiling
            // this is a memory amplifier on an endpoint that needs no session to reach.
            $padding = str_repeat('A', 2_000_000);

            $bomb = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
                . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
                . ' ID="_bomb" Version="2.0"'
                . ' IssueInstant="' . gmdate('Y-m-d\TH:i:s\Z', $now) . '"'
                . ' Destination="' . SamlLogoutFixtures::SP_SLO_URL . '">'
                . '<saml:Issuer>' . SamlFixtures::IDP_ENTITY_ID . '</saml:Issuer>'
                . '<saml:NameID>' . $padding . '</saml:NameID>'
                . '</samlp:LogoutRequest>';

            [$reader] = $makeRequestReader();

            $query = SamlLogoutFixtures::requestQuery(['now' => $now, 'xmlOverride' => $bomb]);

            // Cheap on the wire is the definition of the attack: assert it, so a future fixture
            // that stops compressing cannot turn this case into a test of nothing.
            Assert::true(strlen($query) < 20_000, 'the bomb is small on the wire');

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read($query),
                'the inflate ceiling'
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
        },

    'a DOCTYPE in a logout request is refused before anything reads it' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'doctype' => true],
                IdentityReaderException::DOCTYPE_REJECTED
            );
        },

    'the same logout request cannot be replayed, even though its signature stays valid' =>
        static function () use ($makeRequestReader, $now): void {
            [$reader, $guard] = $makeRequestReader();
            $query = SamlLogoutFixtures::requestQuery(['now' => $now, 'id' => '_replayed']);

            Assert::doesNotThrow(static fn () => $reader->read($query), 'first use');

            [$second] = $makeRequestReader(['guard' => $guard]);
            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $second->read($query)
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::REPLAYED_ASSERTION, $error->reasonCode());
        },

    'two NameIDs mean two candidate victims, so the request is refused' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'secondNameId' => true],
                IdentityReaderException::SUBJECT_MISSING
            );
        },

    'an empty NameID is refused rather than treated as a wildcard' =>
        static function () use ($refusesRequest, $now): void {
            $refusesRequest(
                ['now' => $now, 'nameId' => '   '],
                IdentityReaderException::SUBJECT_MISSING
            );
        },

    'a comment inside the NameID does not truncate the subject we match on' =>
        static function () use ($makeRequestReader, $now): void {
            [$reader] = $makeRequestReader();

            $request = $reader->read(SamlLogoutFixtures::requestQuery([
                'now' => $now,
                'commentInNameId' => true,
            ]));

            // Truncated, this would read "alice@exa" - a different person on a site where that
            // local part exists (the SAML half of CVE-2017-11428).
            Assert::same('alice@example.test', $request->subjectForResponse());
        },

    'a LogoutResponse arriving where a LogoutRequest is expected is refused' =>
        static function () use ($makeRequestReader, $now): void {
            [$reader] = $makeRequestReader();
            $query = SamlLogoutFixtures::responseQuery(['now' => $now, 'relayState' => 'x']);

            // The signature is perfectly valid; only the element name is wrong. Accepting it
            // would mean the endpoint acts on whatever samlp document it can parse.
            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(str_replace('SAMLResponse=', 'SAMLRequest=', $query))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::SIGNATURE_INVALID, $error->reasonCode());
        },

    'single logout is refused outright on a connection that has none configured' =>
        static function () use ($makeRequestReader, $now): void {
            [$reader] = $makeRequestReader(['idpSloUrl' => null]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::requestQuery(['now' => $now]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
        },

    'a rejection never repeats the document, the certificate or the signature' =>
        static function () use ($refusesRequest, $now): void {
            $error = $refusesRequest(
                ['now' => $now, 'signWith' => 'foreign'],
                IdentityReaderException::SIGNATURE_INVALID
            );

            $message = $error->getMessage();
            Assert::notContains('alice@example.test', $message, 'no subject in the user message');
            Assert::notContains('BEGIN CERTIFICATE', $message);
            Assert::notContains('SAMLRequest', $message);
        },

    // -------------------------------------------------------------------------------
    // Path 2: the IdP's answer to a logout we started
    // -------------------------------------------------------------------------------

    'the answer to our logout is accepted only when it correlates with the request we sent' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader(['requestId' => '_ours_1']);

            $response = $reader->read(SamlLogoutFixtures::responseQuery([
                'now' => $now,
                'inResponseTo' => '_ours_1',
                'relayState' => $state,
            ]));

            Assert::same('_ours_1', $response->inResponseTo);
            Assert::true($response->succeeded(), 'top-level Success');
            Assert::false($response->partial(), 'nothing partial about it');
        },

    'a logout answer to somebody else request is refused as unsolicited' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader(['requestId' => '_ours_1']);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'inResponseTo' => '_someone_elses',
                    'relayState' => $state,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    'a logout answer with no InResponseTo at all is refused' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'inResponseTo' => false,
                    'relayState' => $state,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    'a logout answer carrying no RelayState is refused' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader] = $makeResponseReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'relayState' => false,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    'a login state cannot authorise a logout answer' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader(['context' => ['request_id' => '_a_login']]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'inResponseTo' => '_a_login',
                    'relayState' => $state,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    'the state token behind a logout answer is single use' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader(['requestId' => '_ours_1']);
            $query = SamlLogoutFixtures::responseQuery([
                'now' => $now,
                'inResponseTo' => '_ours_1',
                'relayState' => $state,
            ]);

            Assert::doesNotThrow(static fn () => $reader->read($query), 'first use');

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read($query)
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    'an unsigned logout answer is refused' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'relayState' => $state,
                    'unsigned' => true,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::SIGNATURE_MISSING, $error->reasonCode());
        },

    'a partial logout is reported as partial, not swallowed into success' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader(['requestId' => '_ours_1']);

            $response = $reader->read(SamlLogoutFixtures::responseQuery([
                'now' => $now,
                'inResponseTo' => '_ours_1',
                'relayState' => $state,
                'secondaryStatus' => SamlLogoutResponse::STATUS_PARTIAL_LOGOUT,
            ]));

            Assert::true($response->succeeded(), 'PartialLogout is a second-level code');
            Assert::true($response->partial(), 'and it must be visible as such');
        },

    'an IdP saying it could not log us out is reported, not turned into an error page' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader(['requestId' => '_ours_1']);

            $response = $reader->read(SamlLogoutFixtures::responseQuery([
                'now' => $now,
                'inResponseTo' => '_ours_1',
                'relayState' => $state,
                'status' => SamlLogoutResponse::STATUS_RESPONDER,
            ]));

            Assert::false($response->succeeded());
            Assert::same(SamlLogoutResponse::STATUS_RESPONDER, $response->statusCode);
        },

    'a logout answer from an issuer we do not trust is refused' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'relayState' => $state,
                    'issuer' => 'https://evil.example.test/metadata',
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::ISSUER_MISMATCH, $error->reasonCode());
        },

    'a DOCTYPE in a logout answer is refused' =>
        static function () use ($makeResponseReader, $now): void {
            [$reader, $state] = $makeResponseReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read(SamlLogoutFixtures::responseQuery([
                    'now' => $now,
                    'relayState' => $state,
                    'doctype' => true,
                ]))
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::DOCTYPE_REJECTED, $error->reasonCode());
        },

    // -------------------------------------------------------------------------------
    // Path 1: the LogoutRequest we send
    // -------------------------------------------------------------------------------

    'our logout request names the subject, the session and the IdP endpoint' =>
        static function () use ($makeConfig, $now, $rawQuery, $message): void {
            $store = new StateStore(
                new InMemoryStateStorage(),
                new FixedClock($now),
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );

            $starter = new SamlLogoutRequest(
                $makeConfig(),
                $store,
                new FixedClock($now),
                new SequenceRandomSource()
            );

            $redirect = $starter->start('alice@example.test', '_session_7', null, '/admin');
            $xml = $message($rawQuery($redirect->url()), 'SAMLRequest');

            Assert::same(0, strpos($redirect->url(), SamlLogoutFixtures::IDP_SLO_URL), 'IdP endpoint');
            Assert::contains('<samlp:LogoutRequest', $xml);
            Assert::contains('IssueInstant="2023-11-14T22:13:20Z"', $xml, 'the injected clock');
            Assert::contains('Destination="' . SamlLogoutFixtures::IDP_SLO_URL . '"', $xml);
            Assert::contains('>' . SamlFixtures::SP_ENTITY_ID . '<', $xml, 'our own Issuer');
            Assert::contains('>alice@example.test<', $xml);
            Assert::contains('<samlp:SessionIndex>_session_7</samlp:SessionIndex>', $xml);
        },

    'our logout request is really signed over the query string we emit' =>
        static function () use ($makeConfig, $now, $rawQuery, $signatureVerifies, $rawParams): void {
            $store = new StateStore(
                new InMemoryStateStorage(),
                new FixedClock($now),
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );

            $redirect = (new SamlLogoutRequest(
                $makeConfig(),
                $store,
                new FixedClock($now),
                new SequenceRandomSource()
            ))->start('alice@example.test');

            $query = $rawQuery($redirect->url());
            $parameters = $rawParams($query);

            Assert::same(
                'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                rawurldecode($parameters['SigAlg'] ?? ''),
                'SHA-256, never weaker'
            );
            Assert::true($signatureVerifies($query, 'SAMLRequest'), 'signature covers what we send');
        },

    'the id of our logout request travels in the state, never in the URL' =>
        static function () use ($makeConfig, $now, $rawQuery, $message): void {
            $store = new StateStore(
                new InMemoryStateStorage(),
                new FixedClock($now),
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );

            $redirect = (new SamlLogoutRequest(
                $makeConfig(),
                $store,
                new FixedClock($now),
                new SequenceRandomSource()
            ))->start('alice@example.test');

            $xml = $message($rawQuery($redirect->url()), 'SAMLRequest');
            preg_match('/ ID="([^"]+)"/', $xml, $matches);
            $id = $matches[1] ?? '';

            Assert::notSame('', $id, 'the request has an id');

            $state = $redirect->state();
            Assert::notNull($state, 'an SP-initiated logout issues state');
            Assert::same(
                $id,
                $store->consume((string)$state?->value)->context()['logout_request_id'] ?? '',
                'the id is correlatable server-side'
            );
            Assert::notContains($id, (string)$state?->value, 'and not derivable from the token');
        },

    'a logout request without a subject is refused before it reaches the IdP' =>
        static function () use ($makeConfig, $now): void {
            $store = new StateStore(
                new InMemoryStateStorage(),
                new FixedClock($now),
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );

            $starter = new SamlLogoutRequest(
                $makeConfig(),
                $store,
                new FixedClock($now),
                new SequenceRandomSource()
            );

            // Some IdPs answer "log out somebody" by ending every session they hold.
            Assert::throws(RuntimeException::class, static fn () => $starter->start('  '));
        },

    'a connection without single logout cannot produce a logout request at all' =>
        static function () use ($makeConfig, $now): void {
            $store = new StateStore(
                new InMemoryStateStorage(),
                new FixedClock($now),
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );

            $starter = new SamlLogoutRequest(
                $makeConfig(['spPrivateKey' => null]),
                $store,
                new FixedClock($now),
                new SequenceRandomSource()
            );

            Assert::throws(
                RuntimeException::class,
                static fn () => $starter->start('alice@example.test')
            );
        },

    // -------------------------------------------------------------------------------
    // Path 4: the LogoutResponse we send back
    // -------------------------------------------------------------------------------

    'our logout answer states the outcome honestly and quotes the request it answers' =>
        static function () use ($makeConfig, $now, $rawQuery, $message): void {
            $responder = new SamlLogoutResponse(
                $makeConfig(),
                new FixedClock($now),
                new SequenceRandomSource()
            );

            $request = new InboundLogoutRequest('_their_id', 'alice@example.test', null, [], null);

            $cases = [
                'success' => [SamlLogoutResponse::STATUS_SUCCESS, null],
                'partialLogout' => [
                    SamlLogoutResponse::STATUS_SUCCESS,
                    SamlLogoutResponse::STATUS_PARTIAL_LOGOUT,
                ],
                'unknownPrincipal' => [
                    SamlLogoutResponse::STATUS_REQUESTER,
                    SamlLogoutResponse::STATUS_UNKNOWN_PRINCIPAL,
                ],
                'requesterError' => [SamlLogoutResponse::STATUS_REQUESTER, null],
                'responderError' => [SamlLogoutResponse::STATUS_RESPONDER, null],
            ];

            foreach ($cases as $method => [$top, $secondary]) {
                $xml = $message($rawQuery($responder->$method($request)->url()), 'SAMLResponse');

                Assert::contains('InResponseTo="_their_id"', $xml, $method . ': correlation');
                Assert::contains('Value="' . $top . '"', $xml, $method . ': top-level status');

                if ($secondary === null) {
                    Assert::same(
                        1,
                        substr_count($xml, '<samlp:StatusCode'),
                        $method . ': no invented second level'
                    );
                } else {
                    Assert::contains('Value="' . $secondary . '"', $xml, $method . ': second level');
                }
            }
        },

    'our logout answer is signed and echoes the RelayState byte for byte' =>
        static function () use ($makeConfig, $now, $rawQuery, $rawParams, $signatureVerifies): void {
            $responder = new SamlLogoutResponse(
                $makeConfig(),
                new FixedClock($now),
                new SequenceRandomSource()
            );

            // As it would arrive: already encoded, and encoded in a way we would not have chosen.
            $raw = 'back%2Dto%2Dthe%2Dcp';
            $request = new InboundLogoutRequest('_their_id', 'alice@example.test', null, [], $raw);

            $query = $rawQuery($responder->success($request)->url());
            $parameters = $rawParams($query);

            Assert::same($raw, $parameters['RelayState'] ?? '', 'echoed, not re-encoded');
            Assert::true($signatureVerifies($query, 'SAMLResponse'), 'and signed as emitted');
        },

    // -------------------------------------------------------------------------------
    // The round trip, because the two halves are only useful together
    // -------------------------------------------------------------------------------

    'a logout we start is the logout the IdP answer is matched against' =>
        static function () use ($makeConfig, $now, $rawQuery, $message): void {
            $clock = new FixedClock($now);
            $store = new StateStore(
                new InMemoryStateStorage(),
                $clock,
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );

            $redirect = (new SamlLogoutRequest($makeConfig(), $store, $clock, new SequenceRandomSource()))
                ->start('alice@example.test', '_session_7');

            $xml = $message($rawQuery($redirect->url()), 'SAMLRequest');
            preg_match('/ ID="([^"]+)"/', $xml, $matches);

            $reader = new SamlLogoutResponseReader($makeConfig(), $clock, $store);

            $response = $reader->read(SamlLogoutFixtures::responseQuery([
                'now' => $now,
                'inResponseTo' => $matches[1] ?? '',
                'relayState' => $redirect->state()?->value,
            ]));

            Assert::true($response->succeeded());
            Assert::same($matches[1] ?? '', $response->inResponseTo);
        },
];
