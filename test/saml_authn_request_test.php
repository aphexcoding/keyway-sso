<?php

declare(strict_types=1);

use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Core\Login\LoginConnection;
use Keyway\Sso\Core\Port\AuthenticationStartInterface;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Protocol\Saml\SamlAuthnRequest;
use Keyway\Sso\Protocol\Saml\SamlConnectionConfig;
use Keyway\Sso\Protocol\Saml\SamlRedirect;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\InMemoryStateStorage;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * The request half of the SAML round trip (SamlAuthnRequest + SamlRedirect).
 *
 * The reader suite next door asserts what we refuse to believe from the identity provider; this
 * one asserts what we actually put on the wire, by inflating the query parameter and reading the
 * document back. Asserting that "SAMLRequest is present" would be satisfied by a starter that
 * deflates an empty string, and an identity provider is the last place you want to discover that.
 *
 * Everything is pinned to FixedClock and SequenceRandomSource: a request whose id and timestamp
 * cannot be predicted in a test is a request whose id nobody can assert travels into the state.
 */
if (!extension_loaded('dom') || !function_exists('gzdeflate')) {
    // zlib is as load-bearing here as dom: the HTTP-Redirect binding IS deflate. A suite that
    // skipped only on a missing dom would fail with a fatal instead of saying what is absent.
    // The other file that reaches gzdeflate() is test/craft_login_runtime_test.php; it guards
    // one case rather than the file, because the rest of it is about wiring, not zlib.
    fwrite(STDOUT, "saml_authn_request         skipped: ext-dom or ext-zlib absent\n");

    return [];
}

/** A base64 blob long enough to pass the "certificate, not fingerprint" shape check. */
$cert = str_repeat('MIIC', 80);

$ssoUrl = 'https://idp.example.test/realms/keyway/protocol/saml';
$acsUrl = 'https://site.example.test/actions/keyway-sso/sso/acs';
$spEntityId = 'https://site.example.test';

/** 1_700_000_000 is 2023-11-14T22:13:20Z; the literal is asserted below rather than recomputed. */
$fixedNow = 1_700_000_000;

$config = static function (string $ssoUrl) use ($cert, $acsUrl, $spEntityId): SamlConnectionConfig {
    return new SamlConnectionConfig(
        'https://idp.example.test/metadata',
        $cert,
        $spEntityId,
        $acsUrl,
        $ssoUrl
    );
};

/**
 * @return array{0: SamlAuthnRequest, 1: StateStore}
 */
$makeStarter = static function (string $ssoUrl) use ($config, $fixedNow): array {
    $store = new StateStore(
        new InMemoryStateStorage(),
        new FixedClock($fixedNow),
        new SequenceRandomSource(),
        new RedirectGuard(),
        300
    );

    return [
        new SamlAuthnRequest($config($ssoUrl), $store, new FixedClock($fixedNow), new SequenceRandomSource()),
        $store,
    ];
};

/**
 * The query parameters as the identity provider would see them.
 *
 * @return array<string, string>
 */
$query = static function (string $url): array {
    parse_str((string)parse_url($url, PHP_URL_QUERY), $parsed);

    /** @var array<string, string> $parsed */
    return $parsed;
};

/** The AuthnRequest as XML: base64 out, raw DEFLATE out, document in. */
$inflate = static function (string $samlRequest): DOMDocument {
    $raw = base64_decode($samlRequest, true);
    Assert::true(is_string($raw) && $raw !== '', 'SAMLRequest is valid base64');

    $xml = gzinflate((string)$raw);
    Assert::true(is_string($xml) && $xml !== '', 'SAMLRequest is raw DEFLATE, per Bindings 3.4.4.1');

    $document = new DOMDocument();
    Assert::true($document->loadXML((string)$xml), 'the inflated payload is well-formed XML');

    return $document;
};

$cases = [
    'the handle matches the reader, so the callback can find its way back'
        => static function () use ($makeStarter, $ssoUrl): void {
            [$starter] = $makeStarter($ssoUrl);

            Assert::same('saml2', $starter->connection());
        },

    'the redirect carries the SSO endpoint, the request and the relay state'
        => static function () use ($makeStarter, $query, $ssoUrl): void {
            [$starter] = $makeStarter($ssoUrl);
            $start = $starter->start('/admin', []);

            Assert::true(
                str_starts_with($start->url(), $ssoUrl . '?'),
                'the browser goes to the configured endpoint: ' . $start->url()
            );

            $parameters = $query($start->url());
            Assert::true(($parameters['SAMLRequest'] ?? '') !== '', 'SAMLRequest is present');
            Assert::same($start->state()->value, $parameters['RelayState'] ?? '');
        },

    // The case that makes the rest meaningful: the bytes really are a SAML request, and every
    // value in it is the configured one rather than something derived from the environment.
    'the inflated request says who we are, where it goes and where the answer belongs'
        => static function () use ($makeStarter, $query, $inflate, $ssoUrl, $acsUrl, $spEntityId): void {
            [$starter, $store] = $makeStarter($ssoUrl);
            $start = $starter->start('/admin', []);

            $document = $inflate($query($start->url())['SAMLRequest']);
            $root = $document->documentElement;

            Assert::notNull($root);
            Assert::same('AuthnRequest', $root?->localName);
            Assert::same('urn:oasis:names:tc:SAML:2.0:protocol', $root?->namespaceURI);
            Assert::same('2.0', $root?->getAttribute('Version'));
            Assert::same($ssoUrl, $root?->getAttribute('Destination'));
            Assert::same($acsUrl, $root?->getAttribute('AssertionConsumerServiceURL'));
            Assert::same(
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                $root?->getAttribute('ProtocolBinding'),
                'the only binding this plugin can receive on'
            );

            $issuer = $document->getElementsByTagNameNS(
                'urn:oasis:names:tc:SAML:2.0:assertion',
                'Issuer'
            )->item(0);
            Assert::notNull($issuer);
            Assert::same($spEntityId, $issuer?->textContent);

            // The clock, not time(): a starter that reaches for the wall clock passes every
            // other assertion in this file and fails this one.
            Assert::same('2023-11-14T22:13:20Z', $root?->getAttribute('IssueInstant'));

            // The id in the document and the id in the state are the same string, which is the
            // whole reason the state carries it.
            $context = $store->inspect($start->state()->value)->context();
            Assert::same($context['request_id'] ?? '', $root?->getAttribute('ID'));
            // Asserted on SHAPE, not on "the first character happens not to be a digit": the
            // latter only catches a missing prefix when the fixture's random bytes happen to
            // start with one, which makes the test's strength a property of SequenceRandomSource.
            Assert::true(
                preg_match('/^_[0-9a-f]{32}$/', (string)($context['request_id'] ?? '')) === 1,
                'xsd:ID must be the underscore prefix plus 128 bits of hex, got: '
                    . (string)($context['request_id'] ?? '')
            );
        },

    'RelayState stays inside the 80-byte limit the binding imposes'
        => static function () use ($makeStarter, $query): void {
            // SAML 2.0 Bindings section 3.4.3 caps RelayState at 80 bytes and identity providers
            // do enforce it. Today's token is 66 characters, so the headroom is 14 - and it is
            // spent by anyone who raises StateStore::ID_BYTES or SECRET_BYTES without knowing
            // this ceiling exists. Nothing else in the suite connects those constants to it, so
            // without this assertion the regression ships green.
            [$starter] = $makeStarter('https://idp.example.test/saml');
            $start = $starter->start('/admin', []);

            $relayState = $query($start->url())['RelayState'] ?? '';
            Assert::true($relayState !== '', 'RelayState must carry the state token');
            Assert::true(
                strlen($relayState) <= 80,
                'RelayState is ' . strlen($relayState) . ' bytes; the binding allows 80'
            );
        },

    'an SSO endpoint that already has a query string gets an ampersand, not a second question mark'
        => static function () use ($makeStarter, $query): void {
            $ssoUrl = 'https://idp.example.test/saml?tenant=acme';
            [$starter] = $makeStarter($ssoUrl);
            $start = $starter->start('/admin', []);

            Assert::true(str_starts_with($start->url(), $ssoUrl . '&SAMLRequest='), $start->url());
            Assert::same(1, substr_count($start->url(), '?'), 'exactly one query separator');

            $parameters = $query($start->url());
            Assert::same('acme', $parameters['tenant'] ?? '');
            Assert::true(($parameters['SAMLRequest'] ?? '') !== '');
        },

    // LoginFlow::begin() reads the state back before the browser leaves and refuses the login
    // when the context did not survive. This is that check, run against the real store.
    'the caller\'s context survives into the state, and cannot displace ours'
        => static function () use ($makeStarter, $query, $inflate, $ssoUrl): void {
            [$starter, $store] = $makeStarter($ssoUrl);

            // What LoginFlow::begin() actually passes, plus a hostile attempt to pick the id.
            $start = $starter->start('/admin', [
                'connection' => 'saml2',
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_BOUND,
                'request_id' => 'attacker-chosen',
            ]);

            $context = $store->inspect($start->state()->value)->context();

            Assert::same('saml2', $context['connection'] ?? '');
            Assert::same(BrowserBinding::MODE_BOUND, $context[BrowserBinding::CONTEXT_MODE] ?? '');
            Assert::same('saml2', $context['protocol'] ?? '');
            Assert::notSame(
                'attacker-chosen',
                $context['request_id'] ?? '',
                'our keys are merged last, so no caller can choose the request id'
            );

            // Not merely "different from what the caller asked for": still the id that was
            // actually issued, which is what a later InResponseTo check would compare against.
            $document = $inflate($query($start->url())['SAMLRequest']);
            Assert::same($document->documentElement?->getAttribute('ID'), $context['request_id'] ?? '');
        },

    'the return URL reaches the state token'
        => static function () use ($makeStarter, $ssoUrl): void {
            [$starter] = $makeStarter($ssoUrl);

            // One case only: what RedirectGuard does with hostile values is its own suite.
            Assert::same('/admin/entries', $starter->start('/admin/entries', [])->state()->returnUrl);
        },

    'the redirect object offers nothing but the URL and the state'
        => static function () use ($makeStarter, $ssoUrl): void {
            [$starter] = $makeStarter($ssoUrl);
            $start = $starter->start('/admin', []);

            Assert::true($start instanceof SamlRedirect);
            Assert::true($start instanceof AuthenticationStartInterface);

            $methods = get_class_methods(SamlRedirect::class);
            sort($methods);
            Assert::sameList(['__construct', 'state', 'url'], $methods);

            $properties = array_map(
                static fn (ReflectionProperty $property): string => $property->getName(),
                (new ReflectionClass(SamlRedirect::class))->getProperties(ReflectionProperty::IS_PUBLIC)
            );
            sort($properties);
            Assert::sameList(['state', 'url'], $properties, 'the request id stays in the state record');
        },

    'an SSO endpoint that is empty or not http(s) is refused when the connection is built'
        => static function () use ($config): void {
            Assert::throws(InvalidArgumentException::class, static fn () => $config(''));
            Assert::throws(InvalidArgumentException::class, static fn () => $config('   '));
            Assert::throws(InvalidArgumentException::class, static fn () => $config('/sso'));
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => $config('javascript:alert(1)'),
                'a non-http scheme is not somewhere a browser may be sent'
            );
            Assert::doesNotThrow(static fn () => $config('http://idp.example.test/saml'));
        },
];

// Pairing the starter with the real reader needs the SAML library; the assertion is about the
// two halves agreeing, and a fake reader would assert nothing about the real one.
if (class_exists(\OneLogin\Saml2\Utils::class)) {
    $cases['the starter and the real response reader form a connection Craft can build']
        = static function () use ($makeStarter, $config, $ssoUrl, $acsUrl, $fixedNow): void {
            [$starter, $store] = $makeStarter($ssoUrl);

            $clock = new FixedClock($fixedNow);
            $reader = new \Keyway\Sso\Protocol\Saml\SamlResponseReader(
                $config($ssoUrl),
                $clock,
                $store,
                new \Keyway\Sso\Test\Support\InMemoryReplayGuard($clock)
            );

            Assert::same($reader->protocol(), $starter->connection(), 'the pair agrees on the handle');

            $connection = null;
            Assert::doesNotThrow(static function () use (&$connection, $reader, $starter, $acsUrl): void {
                $connection = new LoginConnection(
                    $reader,
                    $starter,
                    CallbackStyle::CrossSitePost,
                    $acsUrl,
                    'RelayState'
                );
            });

            Assert::true($connection?->canStart() ?? false, 'a SAML login can now be started');
        };
}

return $cases;
