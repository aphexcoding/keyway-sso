<?php

declare(strict_types=1);

use Keyway\Sso\Protocol\Saml\SpMetadata;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CertificateFixtures;

/**
 * The SP metadata document (SpMetadata).
 *
 * Everything here reads the generated document back through DOM instead of grepping the string.
 * A `str_contains($xml, 'WantAssertionsSigned="true"')` is worth exactly as much as the
 * uniqueness of that substring: it passes on a document where the attribute sits on the wrong
 * element, in the wrong namespace, or after a stray `<` broke the markup and the rest of the
 * file became text. Those are the three failures an identity provider actually rejects us for,
 * so every assertion below names a node.
 *
 * The other half of the suite is about promises: the flags in this document tell an IdP how to
 * configure itself, and a flag that does not match the code (AuthnRequestsSigned, the POST-only
 * ACS, the absent SingleLogoutService) produces a login that fails on somebody else's server.
 */
if (!extension_loaded('dom')) {
    fwrite(STDOUT, "saml_metadata              skipped: ext-dom absent\n");

    return [];
}

const MD_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

$entityId = 'https://site.example.test/sso';
$acsUrl = 'https://site.example.test/actions/keyway-sso/sso/acs';
$sloUrl = 'https://site.example.test/actions/keyway-sso/sso/slo';

/** 1_700_000_000 is 2023-11-14T22:13:20Z; the literal is asserted rather than recomputed. */
$fixedTime = 1_700_000_000;

// A REAL self-signed X.509 certificate (RSA 2048, CN=keyway-sso-test), and it has to be real:
// the constructor parses the decoded bytes with openssl_x509_read(), because shape alone cannot
// tell a de-armoured certificate from a de-armoured private key. The bytes live in
// CertificateFixtures because settings_translator_test needs exactly the same thing - one real
// certificate, parsed and never signed with - and two pinned copies of it would drift apart.
$certBody = CertificateFixtures::body();

/** The matching private key's base64 body. Never a certificate - and it must never be accepted. */
$keyBody = CertificateFixtures::privateKeyBody();

$pem = CertificateFixtures::pem();

/** The document, parsed - and the parse itself is the first assertion. */
$parse = static function (string $xml): DOMDocument {
    $document = new DOMDocument();
    Assert::true($document->loadXML($xml), 'the metadata is well-formed XML');

    return $document;
};

/** @return list<DOMElement> */
$elements = static function (DOMDocument $document, string $namespace, string $name): array {
    $found = [];

    foreach ($document->getElementsByTagNameNS($namespace, $name) as $node) {
        $found[] = $node;
    }

    return $found;
};

/** The single element with this name, or a failure that says how many there really were. */
$only = static function (DOMDocument $document, string $namespace, string $name) use ($elements): DOMElement {
    $found = $elements($document, $namespace, $name);
    Assert::same(1, count($found), 'exactly one ' . $name);

    return $found[0];
};

$cases = [
    'the minimal document is an EntityDescriptor carrying the entity id and nothing invented'
        => static function () use ($parse, $only, $elements, $entityId, $acsUrl): void {
            $document = $parse((new SpMetadata($entityId, $acsUrl))->toXml());
            $root = $document->documentElement;

            Assert::notNull($root);
            Assert::same('EntityDescriptor', $root?->localName);
            Assert::same(MD_NS, $root?->namespaceURI, 'the metadata namespace, not the protocol one');
            Assert::same($entityId, $root?->getAttribute('entityID'));

            // Absent, not empty: an IdP reads `validUntil=""` as a malformed date, not as "no
            // expiry", and the whole point of the null argument is to omit the attribute.
            Assert::false($root?->hasAttribute('validUntil') ?? true, 'no validUntil when none was given');

            Assert::same(0, count($elements($document, MD_NS, 'KeyDescriptor')), 'no key was supplied');
            Assert::same(
                0,
                count($elements($document, MD_NS, 'SingleLogoutService')),
                'this plugin has no SLO; advertising one points the IdP at a 404'
            );

            $acs = $only($document, MD_NS, 'AssertionConsumerService');
            Assert::same($acsUrl, $acs->getAttribute('Location'));
        },

    'the declaration is written, so the file is a document and not a fragment'
        => static function () use ($entityId, $acsUrl): void {
            $xml = (new SpMetadata($entityId, $acsUrl))->toXml();

            Assert::true(str_starts_with($xml, '<?xml version="1.0" encoding="UTF-8"?>'), $xml);
        },

    'the SPSSODescriptor promises exactly what the code does, and nothing more'
        => static function () use ($parse, $only, $entityId, $acsUrl): void {
            $document = $parse((new SpMetadata($entityId, $acsUrl))->toXml());
            $descriptor = $only($document, MD_NS, 'SPSSODescriptor');

            Assert::same(
                'urn:oasis:names:tc:SAML:2.0:protocol',
                $descriptor->getAttribute('protocolSupportEnumeration')
            );
            // SamlAuthnRequest does not sign. Declaring true here makes a metadata-driven IdP
            // require a signature we never send, and every login dies at the IdP.
            Assert::same(
                'false',
                $descriptor->getAttribute('AuthnRequestsSigned'),
                'we do not sign AuthnRequests, so we must not claim to'
            );
            // SamlResponseReader requires a signature unconditionally, so this one is true.
            Assert::same('true', $descriptor->getAttribute('WantAssertionsSigned'));
        },

    'the assertion consumer service is the POST endpoint, is default, and is the only one'
        => static function () use ($parse, $only, $acsUrl, $entityId): void {
            $document = $parse((new SpMetadata($entityId, $acsUrl))->toXml());
            $acs = $only($document, MD_NS, 'AssertionConsumerService');

            Assert::same(
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                $acs->getAttribute('Binding'),
                'CallbackStyle::CrossSitePost is the only thing this SP can receive on'
            );
            Assert::same($acsUrl, $acs->getAttribute('Location'));
            Assert::same('0', $acs->getAttribute('index'));
            Assert::same('true', $acs->getAttribute('isDefault'));
        },

    'the default NameID format is unspecified alone, because the reader checks no format'
        => static function () use ($parse, $elements, $entityId, $acsUrl): void {
            $document = $parse((new SpMetadata($entityId, $acsUrl))->toXml());
            $formats = $elements($document, MD_NS, 'NameIDFormat');

            Assert::same(1, count($formats));
            Assert::same(
                'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified',
                $formats[0]->textContent,
                'SamlResponseReader::readNameId() ignores Format; emailAddress would be a lie'
            );
        },

    'a supplied format list replaces the default, one element per entry, in order'
        => static function () use ($parse, $elements, $entityId, $acsUrl): void {
            $wanted = [
                'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            ];

            $document = $parse((new SpMetadata($entityId, $acsUrl, null, null, null, $wanted))->toXml());
            $formats = $elements($document, MD_NS, 'NameIDFormat');

            Assert::sameList(
                $wanted,
                array_map(static fn (DOMElement $node): string => $node->textContent, $formats)
            );
        },

    'the full document carries the key, the logout endpoint and the expiry'
        => static function () use ($parse, $only, $entityId, $acsUrl, $sloUrl, $pem, $certBody, $fixedTime): void {
            $document = $parse(
                (new SpMetadata($entityId, $acsUrl, $pem, $sloUrl, $fixedTime))->toXml()
            );

            Assert::same('2023-11-14T22:13:20Z', $document->documentElement?->getAttribute('validUntil'));

            $key = $only($document, MD_NS, 'KeyDescriptor');
            Assert::same(
                'encryption',
                $key->getAttribute('use'),
                'we do not sign, so the only key an IdP can use against us is an encryption key'
            );

            $certificate = $only($document, DS_NS, 'X509Certificate');
            Assert::same($certBody, $certificate->textContent);
            Assert::same(DS_NS, $certificate->namespaceURI, 'the certificate lives in the xmldsig namespace');

            // The certificate must hang off KeyInfo/X509Data, not off KeyDescriptor directly.
            Assert::same('X509Data', $certificate->parentNode?->localName);
            Assert::same('KeyInfo', $certificate->parentNode?->parentNode?->localName);

            $logout = $only($document, MD_NS, 'SingleLogoutService');
            Assert::same('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', $logout->getAttribute('Binding'));
            Assert::same($sloUrl, $logout->getAttribute('Location'));
        },

    // The failure this guards against is invisible to a substring test: every value correct,
    // every element present, and a validating IdP parser rejects the document anyway.
    'the children of SPSSODescriptor follow the order md:SSODescriptorType requires'
        => static function () use ($parse, $only, $entityId, $acsUrl, $sloUrl, $pem, $fixedTime): void {
            $document = $parse(
                (new SpMetadata($entityId, $acsUrl, $pem, $sloUrl, $fixedTime, [
                    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                ]))->toXml()
            );

            $names = [];
            foreach ($only($document, MD_NS, 'SPSSODescriptor')->childNodes as $child) {
                if ($child instanceof DOMElement) {
                    $names[] = $child->localName;
                }
            }

            Assert::sameList(
                [
                    'KeyDescriptor',
                    'SingleLogoutService',
                    'NameIDFormat',
                    'NameIDFormat',
                    'AssertionConsumerService',
                ],
                $names,
                'XSD sequences are ordered; a shuffled document is rejected despite being correct'
            );
        },

    'the minimal document keeps the same order once the optional elements are gone'
        => static function () use ($parse, $only, $entityId, $acsUrl): void {
            $document = $parse((new SpMetadata($entityId, $acsUrl))->toXml());

            $names = [];
            foreach ($only($document, MD_NS, 'SPSSODescriptor')->childNodes as $child) {
                if ($child instanceof DOMElement) {
                    $names[] = $child->localName;
                }
            }

            Assert::sameList(['NameIDFormat', 'AssertionConsumerService'], $names);
        },

    'validUntil is xsd:dateTime in UTC, derived from the argument and never from the wall clock'
        => static function () use ($parse, $entityId, $acsUrl): void {
            // Two different timestamps, because a class that ignored the argument and called
            // time() would still satisfy a single "looks like a date" assertion.
            $first = $parse((new SpMetadata($entityId, $acsUrl, null, null, 0))->toXml());
            Assert::same('1970-01-01T00:00:00Z', $first->documentElement?->getAttribute('validUntil'));

            $second = $parse((new SpMetadata($entityId, $acsUrl, null, null, 2_000_000_000))->toXml());
            Assert::same('2033-05-18T03:33:20Z', $second->documentElement?->getAttribute('validUntil'));
        },

    'the PEM armour and its line breaks are stripped, because X509Certificate is base64 content'
        => static function () use ($parse, $only, $entityId, $acsUrl, $pem, $certBody): void {
            $document = $parse((new SpMetadata($entityId, $acsUrl, $pem))->toXml());
            $certificate = $only($document, DS_NS, 'X509Certificate');

            Assert::same($certBody, $certificate->textContent);
            Assert::notContains('BEGIN CERTIFICATE', $certificate->textContent);
            Assert::notContains('-', $certificate->textContent, 'no armour fragment survives');
            Assert::notContains("\n", $certificate->textContent, 'no wrapped lines survive');
        },

    'a bare base64 certificate is taken as it is, whitespace and all removed'
        => static function () use ($parse, $only, $entityId, $acsUrl, $certBody): void {
            $spaced = " " . chunk_split($certBody, 16, " \r\n") . " ";

            $document = $parse((new SpMetadata($entityId, $acsUrl, $spaced))->toXml());

            Assert::same($certBody, $only($document, DS_NS, 'X509Certificate')->textContent);
        },

    // The reason the document is built through DOM instead of sprintf: a `"` inside an
    // attribute value is a markup break, and a markup break is a document an IdP cannot read.
    'entity ids and URLs full of XML metacharacters survive the round trip untouched'
        => static function () use ($parse, $only): void {
            $entityId = 'https://site.example.test/sso?a=1&b="x"&c=<y>';
            $acsUrl = 'https://site.example.test/acs?q="&<z>';

            $document = $parse((new SpMetadata($entityId, $acsUrl))->toXml());

            Assert::same($entityId, $document->documentElement?->getAttribute('entityID'));
            Assert::same($acsUrl, $only($document, MD_NS, 'AssertionConsumerService')->getAttribute('Location'));
        },

    'a NameID format containing markup is escaped as text, not smuggled in as an element'
        => static function () use ($parse, $elements, $entityId, $acsUrl): void {
            $format = 'urn:example:<script>&"';

            $document = $parse((new SpMetadata($entityId, $acsUrl, null, null, null, [$format]))->toXml());
            $formats = $elements($document, MD_NS, 'NameIDFormat');

            Assert::same(1, count($formats));
            Assert::same($format, $formats[0]->textContent);
            Assert::same(0, $formats[0]->getElementsByTagName('script')->length, 'text stayed text');
        },

    'an empty entity id is refused'
        => static function () use ($acsUrl): void {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata('', $acsUrl)
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata("  \n\t ", $acsUrl),
                'whitespace is not an entity id'
            );
        },

    'the ACS URL must be an absolute http(s) URL with a host'
        => static function () use ($entityId, $acsUrl): void {
            // `https://` and `http:` land on the HOST branch specifically: parse_url() returns a
            // scheme for both and no host. Without them the branch is untested - `https:///acs`
            // fails parse_url() outright and never reaches it, which is why it is not enough on
            // its own.
            $bads = [
                '',
                '/actions/keyway-sso/sso/acs',
                'javascript:alert(1)',
                'https:///acs',
                'site.example.test/acs',
                'https://',
                'http:',
                'https:/acs',
            ];

            foreach ($bads as $bad) {
                Assert::throws(
                    InvalidArgumentException::class,
                    static fn () => new SpMetadata($entityId, $bad),
                    'accepted a bad ACS URL: ' . $bad
                );
            }

            Assert::doesNotThrow(static fn () => new SpMetadata($entityId, $acsUrl));
            Assert::doesNotThrow(
                static fn () => new SpMetadata($entityId, 'http://site.example.test/acs'),
                'plain http is allowed - a developer install is not a security hole in metadata'
            );
        },

    'a supplied logout URL obeys the same rule; null stays legal'
        => static function () use ($entityId, $acsUrl): void {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, null, 'not-a-url')
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, null, ''),
                'an empty string is a mistake, not "no logout endpoint"'
            );
            Assert::doesNotThrow(static fn () => new SpMetadata($entityId, $acsUrl, null, null));
        },

    'a certificate is either key material or null - never an empty or malformed string'
        => static function () use ($entityId, $acsUrl, $certBody): void {
            // The SamlConnectionConfig::spPrivateKey rule: treating '' as absent publishes
            // metadata with no key to an administrator who believes they configured one.
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, ''),
                'an empty certificate is an error, not an absent certificate'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, "   \n  "),
                'whitespace only'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
                'armour with nothing inside it'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, 'not base64! <>'),
                'characters that cannot appear in base64'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, 'AA=='),
                'four characters of base64 are not a certificate'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, str_repeat('ab', 32)),
                'a SHA-256 fingerprint is base64-shaped and is still not a certificate'
            );
            Assert::doesNotThrow(static fn () => new SpMetadata($entityId, $acsUrl, $certBody));
        },

    // The one mistake in this class that could not be taken back: this document is served from
    // an anonymous endpoint, the plugin stores an SP PRIVATE key one settings field away from
    // the certificate, and stripping PEM armour before looking at its label accepts that key in
    // full - its body is base64 too. So the label is checked first, and these cases pin it.
    // A list of malformed pastes, every one of which got past an earlier version of
    // the gate, and case A is not exotic: pasting `fullchain + key` into one field is the single
    // most common way an administrator fills a box like this. The old check asked a question
    // ABOUT PART of the value ("does it contain this label?"); these cases pin the rule that
    // replaced it, which matches the WHOLE value and then parses the bytes.
    'a certificate bundled with a private key is refused, in either order'
        => static function () use ($entityId, $acsUrl, $certBody, $keyBody): void {
            $block = static fn (string $label, string $body): string => sprintf(
                "-----BEGIN %s-----\n%s-----END %s-----\n",
                $label,
                chunk_split($body, 64, "\n"),
                $label
            );

            $cert = $block('CERTIFICATE', $certBody);

            $bundles = [
                'certificate then key' => $cert . $block('PRIVATE KEY', $keyBody),
                'key then certificate' => $block('PRIVATE KEY', $keyBody) . $cert,
                'certificate then RSA key' => $cert . $block('RSA PRIVATE KEY', $keyBody),
                'two certificates (a chain)' => $cert . $cert,
                'certificate with trailing armour' => $cert . '-----BEGIN PRIVATE KEY-----',
            ];

            foreach ($bundles as $label => $value) {
                Assert::throws(
                    InvalidArgumentException::class,
                    static fn () => new SpMetadata($entityId, $acsUrl, $value),
                    $label . ' must not reach a document served anonymously'
                );
            }

            // And the same key with its armour taken off by hand - the case no shape check can
            // catch, because a de-armoured key and a de-armoured certificate are both base64.
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, $keyBody),
                'a bare base64 private key is still a private key'
            );

            // The positives, so the gate is not simply "refuse everything": a real certificate
            // goes in, armoured or bare, and only its own body comes out.
            foreach (['armoured' => $cert, 'bare' => $certBody] as $label => $value) {
                $xml = new DOMDocument();
                $xml->loadXML((new SpMetadata($entityId, $acsUrl, $value))->toXml());

                $written = trim(
                    (string)$xml->getElementsByTagNameNS(
                        'http://www.w3.org/2000/09/xmldsig#',
                        'X509Certificate'
                    )->item(0)?->textContent
                );

                Assert::same($certBody, $written, $label . ' certificate goes in whole');
                Assert::notContains($keyBody, $written, 'and nothing else comes with it');
            }
        },

    // The third shape of the same leak, and the one no pattern can catch: the two DER structures
    // are concatenated BEFORE base64, so the value is one clean block with one clean alphabet,
    // and openssl_x509_read() parses the first structure without complaining about the rest.
    // What closes it is publishing what openssl RECOGNISED instead of what the caller passed.
    'a certificate with a private key concatenated at the DER level is stripped, not published'
        => static function () use ($entityId, $acsUrl, $certBody, $keyBody): void {
            $poisoned = base64_encode(base64_decode($certBody, true) . base64_decode($keyBody, true));

            Assert::notSame($certBody, $poisoned, 'the fixture really is longer than the certificate');

            $read = static function (string $value) use ($entityId, $acsUrl): string {
                $xml = new DOMDocument();
                $xml->loadXML((new SpMetadata($entityId, $acsUrl, $value))->toXml());

                return trim(
                    (string)$xml->getElementsByTagNameNS(
                        'http://www.w3.org/2000/09/xmldsig#',
                        'X509Certificate'
                    )->item(0)?->textContent
                );
            };

            // Bare and armoured, because the anchored pattern accepts both and neither can see
            // inside the base64.
            $armoured = "-----BEGIN CERTIFICATE-----\n" . chunk_split($poisoned, 64, "\n") . "-----END CERTIFICATE-----\n";

            foreach (['bare' => $poisoned, 'armoured' => $armoured] as $label => $value) {
                $written = $read($value);

                Assert::same($certBody, $written, $label . ': only the certificate survives');
                Assert::notContains(
                    substr($keyBody, 0, 60),
                    $written,
                    $label . ': not one byte of the private key is published'
                );
            }

            // And the clean value is unchanged by the same re-export - a gate that mangled valid
            // input would be its own kind of bug.
            Assert::same($certBody, $read($certBody), 'a clean certificate survives byte for byte');
        },

    'a PEM block that is not a certificate is refused, whatever is inside it'
        => static function () use ($entityId, $acsUrl, $certBody): void {
            $pem = static fn (string $label, string $body): string => sprintf(
                "-----BEGIN %s-----\n%s-----END %s-----\n",
                $label,
                chunk_split($body, 64, "\n"),
                $label
            );

            foreach (['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'PUBLIC KEY'] as $label) {
                Assert::throws(
                    InvalidArgumentException::class,
                    static fn () => new SpMetadata($entityId, $acsUrl, $pem($label, $certBody)),
                    $label . ' must never reach a published document'
                );
            }

            $document = new SpMetadata($entityId, $acsUrl, $pem('CERTIFICATE', $certBody));
            Assert::contains($certBody, $document->toXml(), 'a real certificate still goes in');
        },

    // The strongest assertion available to this file, and it costs nothing: the official OASIS
    // schema ships inside onelogin/php-saml, which this project already depends on. A hand-written
    // list of expected child names says what WE think the schema requires; this says what it does.
    // Skipped, visibly, when vendor/ is absent - the suite must still run with no Composer.
    'every shape of the document validates against the OASIS metadata schema'
        => static function () use ($entityId, $acsUrl, $certBody): void {
            $xsd = __DIR__ . '/../vendor/onelogin/php-saml/src/Saml2/schemas/saml-schema-metadata-2.0.xsd';

            if (!is_file($xsd)) {
                Assert::true(true, 'skipped: vendor absent, no schema to validate against');

                return;
            }

            $shapes = [
                'minimal' => new SpMetadata($entityId, $acsUrl),
                'certificate only' => new SpMetadata($entityId, $acsUrl, $certBody),
                'logout only' => new SpMetadata($entityId, $acsUrl, null, 'https://site.example.test/slo'),
                'expiry only' => new SpMetadata($entityId, $acsUrl, null, null, 1_700_000_000),
                'everything' => new SpMetadata(
                    $entityId,
                    $acsUrl,
                    $certBody,
                    'https://site.example.test/slo',
                    1_700_000_000,
                    ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', SpMetadata::NAMEID_UNSPECIFIED]
                ),
            ];

            $previous = libxml_use_internal_errors(true);

            foreach ($shapes as $label => $document) {
                $xml = new DOMDocument();
                $xml->loadXML($document->toXml());
                libxml_clear_errors();

                Assert::true($xml->schemaValidate($xsd), $label . ' is schema-valid');
            }

            libxml_use_internal_errors($previous);
        },

    'the entity id the document names is the one a caller can read back off it'
        => static function () use ($acsUrl): void {
            $entityId = 'https://site.example.test/sso';

            // Not decoration: the file name in Content-Disposition is derived from this, and an
            // accessor quietly returning '' would name every download on every install alike -
            // exactly the confusion it exists to prevent.
            Assert::same($entityId, (new SpMetadata($entityId, $acsUrl))->entityId());
            Assert::same(
                $entityId,
                (new SpMetadata('  ' . $entityId . '  ', $acsUrl))->entityId(),
                'and it is the trimmed value that went into the document, not the raw argument'
            );

            $xml = new DOMDocument();
            $xml->loadXML((new SpMetadata('  ' . $entityId . '  ', $acsUrl))->toXml());
            Assert::same($entityId, $xml->documentElement?->getAttribute('entityID'));
        },

    'bytes that would produce a document no parser can read are refused'
        => static function () use ($entityId, $acsUrl): void {
            // HTTP 200 with an unparseable body is the worst answer an endpoint can give: the
            // IdP reports a parse error and nothing points back at the settings field.
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata("https://site.example.test/\xB1\xC5", $acsUrl),
                'invalid UTF-8 in the entity id'
            );

            // A NUL truncates rather than breaks, which is worse: the document would name an
            // entity id different from the one the response reader compares the Audience with.
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata("https://site.example.test\0.evil", $acsUrl),
                'a NUL byte in the entity id'
            );
            // Embedded, not trailing: `trim()` already strips a NUL at either end, so a trailing
            // one never reaches the document in the first place.
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, "https://site.example.test/acs\0.evil"),
                'and in the ACS URL'
            );

            Assert::doesNotThrow(
                static fn () => new SpMetadata('https://sité.example.test/ssö', $acsUrl),
                'valid UTF-8 above ASCII is fine - an entity id is not required to be ASCII'
            );
        },

    'a format list must be non-empty and free of empty entries'
        => static function () use ($entityId, $acsUrl): void {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, null, null, null, []),
                'an empty list is not the same as null'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, null, null, null, ['urn:one', '']),
                'an empty entry would emit an empty NameIDFormat element'
            );
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SpMetadata($entityId, $acsUrl, null, null, null, ['   ']),
                'whitespace is not a format'
            );
        },

    'fileName derives a readable name from the entity id'
        => static function (): void {
            Assert::same(
                'https-site.example.test-sso-metadata.xml',
                SpMetadata::fileName('https://site.example.test/sso')
            );
            Assert::same(
                SpMetadata::fileName('https://site.example.test/sso'),
                SpMetadata::fileName('https://site.example.test/sso'),
                'deterministic: the name shows up in support tickets'
            );
        },

    // The value reaches a Content-Disposition header. A quote or a bare CR/LF there is header
    // splitting, not a cosmetic problem.
    'fileName strips everything a response header could be broken with'
        => static function (): void {
            $name = SpMetadata::fileName("https://site.test/\"sso\"; filename=\"evil.sh\"\r\nX-Evil: 1");

            foreach (['"', ';', "\r", "\n", ' ', '/', '\\', '='] as $forbidden) {
                Assert::notContains($forbidden, $name, 'dangerous character survived: ' . $name);
            }

            Assert::true(
                preg_match('/^[A-Za-z0-9._-]+\.xml$/', $name) === 1,
                'the name is restricted to a safe alphabet, got: ' . $name
            );
            Assert::true(str_ends_with($name, '-metadata.xml'), $name);
        },

    'fileName collapses runs of separators and stays short enough for a header and a filesystem'
        => static function (): void {
            Assert::same('a-b-metadata.xml', SpMetadata::fileName('a:///b'), 'runs collapse to one hyphen');

            // The case above is collapsed by the `+` quantifier of the first substitution, not by
            // the run-collapsing one - so on its own it leaves that line free to delete with the
            // suite still green. Hyphens ALREADY in the entity id are what actually exercises it.
            Assert::same('a-b-metadata.xml', SpMetadata::fileName('a--b'), 'literal runs too');
            // Only runs of hyphens are collapsed; an underscore is a legal file-name character
            // and is left alone. Asserted so the behaviour is a decision and not a surprise.
            Assert::same('a-_-b-metadata.xml', SpMetadata::fileName('a-_-b'));

            $long = SpMetadata::fileName('https://' . str_repeat('very-long-host.', 20) . 'example.test/sso');
            Assert::true(strlen($long) <= 60 + strlen('-metadata.xml'), 'got ' . strlen($long) . ' characters');
            Assert::true(str_ends_with($long, '-metadata.xml'), $long);
            Assert::false(str_contains($long, '--'), $long);
        },

    'fileName falls back to a fixed name when the entity id reduces to nothing'
        => static function (): void {
            Assert::same('keyway-sso-metadata.xml', SpMetadata::fileName(''));
            Assert::same('keyway-sso-metadata.xml', SpMetadata::fileName('///'));
            Assert::same('keyway-sso-metadata.xml', SpMetadata::fileName('...'), 'no leading-dot file names');
        },
];

return $cases;
