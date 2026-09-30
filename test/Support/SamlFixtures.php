<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use OneLogin\Saml2\Utils;

/**
 * Builds real, really-signed SAML responses for the reader tests.
 *
 * The key pair is generated in-process on first use, so nothing secret is committed and nothing
 * expires. It is a TEST key: it signs fixtures inside this test run and nothing else. Never
 * reuse it anywhere, and do not copy it into a settings file.
 *
 * String assembly is acceptable here and only here - the fixtures are the attacker's document,
 * and an attacker is not bound by "no string surgery on XML". Production code (SamlResponseReader)
 * parses with DOM only, per contract A2.
 */
final class SamlFixtures
{
    public const IDP_ENTITY_ID = 'https://idp.example.test/metadata';
    public const IDP_SSO_URL = 'https://idp.example.test/sso';
    public const SP_ENTITY_ID = 'https://craft.example.test/sso/metadata';
    public const ACS_URL = 'https://craft.example.test/sso/acs';

    private static ?string $cert = null;
    private static ?string $key = null;

    /** A second, unrelated key pair: the "attacker signed it with their own certificate" case. */
    private static ?string $otherCert = null;
    private static ?string $otherKey = null;

    public static function cert(): string
    {
        self::ensureKeys();

        return (string)self::$cert;
    }

    public static function privateKey(): string
    {
        self::ensureKeys();

        return (string)self::$key;
    }

    public static function foreignCert(): string
    {
        self::ensureOtherKeys();

        return (string)self::$otherCert;
    }

    public static function foreignKey(): string
    {
        self::ensureOtherKeys();

        return (string)self::$otherKey;
    }

    private static function ensureKeys(): void
    {
        if (self::$cert !== null) {
            return;
        }

        [self::$cert, self::$key] = self::generate('idp.example.test');
    }

    private static function ensureOtherKeys(): void
    {
        if (self::$otherCert !== null) {
            return;
        }

        [self::$otherCert, self::$otherKey] = self::generate('evil.example.test');
    }

    /**
     * @return array{0: string, 1: string} [certificate PEM, private key PEM]
     */
    private static function generate(string $commonName): array
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $pkey = openssl_pkey_new($config);
        if ($pkey === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }

        $csr = openssl_csr_new(['commonName' => $commonName], $pkey, $config);
        if ($csr === false) {
            throw new \RuntimeException('openssl_csr_new failed: ' . openssl_error_string());
        }

        $x509 = openssl_csr_sign($csr, null, $pkey, 3650, $config);
        if ($x509 === false) {
            throw new \RuntimeException('openssl_csr_sign failed: ' . openssl_error_string());
        }

        openssl_x509_export($x509, $cert);
        openssl_pkey_export($pkey, $key, null, $config);

        return [(string)$cert, (string)$key];
    }

    /**
     * `now` IS REQUIRED and there is deliberately no fallback to time(). A fixture that reads the
     * wall clock on its own is a second, unsynchronised clock in a suite whose readers all run on
     * a FixedClock, and the two can straddle a second boundary. Every caller already knows the
     * timestamp it pinned its reader to; making it say so removes the class of bug rather than
     * one instance of it.
     *
     * @param array<string, mixed> $o Overrides; see the defaults below. Must carry `now`.
     */
    public static function response(array $o): string
    {
        if (!isset($o['now'])) {
            throw new \RuntimeException(
                'SamlFixtures::response() needs an explicit now: pass the timestamp the reader '
                . 'under test is pinned to, never the wall clock.'
            );
        }

        $now = (int)$o['now'];

        $defaults = [
            // Carried in $c so assertionXml() reads THIS timestamp instead of taking its own.
            'now' => $now,
            'issuer' => self::IDP_ENTITY_ID,
            'responseIssuer' => self::IDP_ENTITY_ID,
            'audience' => self::SP_ENTITY_ID,
            'destination' => self::ACS_URL,
            'recipient' => self::ACS_URL,
            'inResponseTo' => 'KW_request_id',
            'scdInResponseTo' => null,        // null -> copy inResponseTo
            'status' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'assertionId' => '_assertion_' . bin2hex(random_bytes(8)),
            'responseId' => '_response_' . bin2hex(random_bytes(8)),
            'nameId' => 'alice@example.test',
            'notBefore' => $now - 60,
            'notOnOrAfter' => $now + 300,
            'scdNotOnOrAfter' => $now + 300,  // false -> omit the attribute entirely
            'method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
            'attributes' => ['  Email  ' => ['Alice@Example.TEST'], 'Groups' => ['Staff', 'Admins']],
            'sessionIndex' => '_session_1',
            'signAssertion' => true,
            'signWith' => null,               // null -> the trusted IdP key
            'signEnvelope' => false,
            'breakReference' => false,        // rename the Assertion ID after signing
            'secondAssertion' => false,      // real wrapping: forged copy of the SIGNED assertion
            'wrappingInExtensions' => false,  // original signed assertion hidden in Extensions
            'commentInNameId' => false,
            'duplicateId' => false,
            'stripEnvelopedTransform' => false,
            'nestSignature' => false,
            'doctype' => false,
            'withConditions' => true,
        ];

        $c = array_merge($defaults, $o);

        $assertion = self::assertionXml($c);

        if ($c['signAssertion'] === true) {
            $key = $c['signWith'] === 'foreign' ? self::foreignKey() : self::privateKey();
            $cert = $c['signWith'] === 'foreign' ? self::foreignCert() : self::cert();
            $assertion = Utils::addSign($assertion, $key, $cert);
            $assertion = self::stripDeclaration($assertion);
        }

        if ($c['breakReference'] === true) {
            // The signature still verifies against its own Reference, but that Reference no
            // longer names the assertion anyone reads: textbook wrapping shape.
            // xmlseclibs overwrites the ID while signing, so the real one is read back here.
            $signedId = self::assertionId($assertion);
            $assertion = str_replace(
                'ID="' . $signedId . '"',
                'ID="' . $signedId . '_moved"',
                $assertion
            );
        }

        $body = $assertion;
        $extensions = '';

        if ($c['nestSignature'] === true) {
            // Isolates the nesting rule (ds:Signature must be a DIRECT child of the assertion)
            // from the URI pin, which would otherwise mask it.
            //
            // MEASURED, do not assume more than this: the signature does NOT still verify here.
            // The enveloped transform only strips the ds:Signature node itself, so wrapping it in
            // <saml:Advice> leaves an empty <saml:Advice/> inside the digested content and the
            // digest no longer matches. With the nesting rule ON the reader answers
            // SIGNATURE_COVERAGE; with it OFF the document still dies on crypto
            // (SIGNATURE_INVALID). The test therefore asserts the REASON CODE, not merely that
            // something was thrown - that is what makes it detect removal of the rule.
            // A true "valid signature, wrong node" fixture is not buildable with Utils::addSign().
            // The trailing space matters: <ds:SignatureValue> and <ds:SignatureMethod> would
            // match a looser needle and shred the document.
            $body = str_replace('<ds:Signature ', '<saml:Advice><ds:Signature ', $body);
            $body = str_replace('</ds:Signature>', '</ds:Signature></saml:Advice>', $body);
        }

        if ($c['stripEnvelopedTransform'] === true) {
            // Removes the guarantee that the signature was stripped before hashing.
            //
            // MEASURED, do not assume more than this: rewriting the transform URI does NOT leave
            // a valid signature. Transforms live in SignedInfo, SignedInfo is itself covered by
            // SignatureValue, and the transform list also decides how the digest is computed -
            // so both break. With the transform rule ON the reader answers SIGNATURE_COVERAGE;
            // with it OFF the document dies on crypto (SIGNATURE_INVALID). As with nestSignature
            // above, the test's value comes from asserting the REASON CODE.
            $body = str_replace(
                'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                'http://example.test/not-a-transform',
                $body
            );
        }

        if ($c['commentInNameId'] === true) {
            // XML comment truncation (the SAML half of CVE-2017-11428 / GitLab, Duo, OneLogin,
            // 2018). Comments are excluded from canonicalisation for a `#id` reference
            // (xmlseclibs processRefNode(), $includeCommentNodes = false), so the document below
            // is STILL CORRECTLY SIGNED. Only the reader's choice of textContent over
            // firstChild->nodeValue decides whether the subject stays whole.
            $plain = self::esc((string)$c['nameId']);
            $cut = (int)floor(strlen($plain) / 2);
            $body = str_replace(
                '>' . $plain . '<',
                '>' . substr($plain, 0, $cut) . '<!---->' . substr($plain, $cut) . '<',
                $body
            );
        }

        if ($c['duplicateId'] === true) {
            // A decoy carrying the same ID as the assertion: a Reference resolver that takes
            // the first match in document order would digest this instead.
            $extensions .= '<samlp:Extensions><samlp:Decoy ID="'
                . self::esc(self::assertionId($assertion)) . '"/></samlp:Extensions>';
        }

        if ($c['secondAssertion'] === true || $c['wrappingInExtensions'] === true) {
            // XML Signature Wrapping in its real shape (CVE-2017-11427): the forged assertion is
            // a COPY of the genuinely signed one with the subject swapped, so an implementation
            // that verifies "a signature, somewhere" and then reads "an assertion, somewhere"
            // hands out an administrator session. An unsigned hand-built assertion would not
            // test this - it would only test that something is unsigned.
            $forged = $body;
            if (preg_match('#<saml:Assertion .*?</saml:Assertion>#s', $body, $matches) === 1) {
                $forged = $matches[0];
            }
            $forged = str_replace(
                self::esc((string)$c['nameId']),
                'admin@example.test',
                $forged
            );

            if ($c['wrappingInExtensions'] === true) {
                // The genuine, signed assertion is parked where a lenient parser still finds a
                // valid signature, while the document's only Response-level assertion is forged.
                $extensions .= '<samlp:Extensions>' . $body . '</samlp:Extensions>';
                $body = $forged;
            } else {
                $body = $forged . $body;
            }
        }

        $destination = $c['destination'] === false
            ? ''
            : ' Destination="' . self::esc((string)$c['destination']) . '"';

        $inResponseTo = $c['inResponseTo'] === false
            ? ''
            : ' InResponseTo="' . self::esc((string)$c['inResponseTo']) . '"';

        $responseIssuer = $c['responseIssuer'] === false
            ? ''
            : '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
                . self::esc((string)$c['responseIssuer']) . '</saml:Issuer>';

        $xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' ID="' . self::esc((string)$c['responseId']) . '"'
            . ' Version="2.0" IssueInstant="' . self::time($now) . '"'
            . $destination . $inResponseTo . '>'
            . $responseIssuer
            . '<samlp:Status><samlp:StatusCode Value="' . self::esc((string)$c['status']) . '"/></samlp:Status>'
            . $extensions
            . $body
            . '</samlp:Response>';

        if ($c['signEnvelope'] === true) {
            $xml = Utils::addSign($xml, self::privateKey(), self::cert());
            $xml = self::stripDeclaration($xml);
        }

        if ($c['doctype'] === true) {
            $xml = '<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' . $xml;
        }

        return base64_encode($xml);
    }

    /**
     * @param array<string, mixed> $c
     */
    private static function assertionXml(array $c): string
    {
        // Never time(): response() puts its own resolved timestamp into $c precisely so that the
        // envelope and the assertion inside it cannot be dated a second apart.
        $now = (int)$c['now'];

        $conditions = '';
        if ($c['withConditions'] === true) {
            $window = '';
            if ($c['notBefore'] !== false) {
                $window .= ' NotBefore="' . self::time((int)$c['notBefore']) . '"';
            }
            if ($c['notOnOrAfter'] !== false) {
                $window .= ' NotOnOrAfter="' . self::time((int)$c['notOnOrAfter']) . '"';
            }

            $audience = $c['audience'] === false
                ? ''
                : '<saml:AudienceRestriction><saml:Audience>'
                    . self::esc((string)$c['audience'])
                    . '</saml:Audience></saml:AudienceRestriction>';

            $conditions = '<saml:Conditions' . $window . '>' . $audience . '</saml:Conditions>';
        }

        $scdInResponseTo = $c['scdInResponseTo'] ?? $c['inResponseTo'];
        $scd = '<saml:SubjectConfirmationData';
        if ($c['recipient'] !== false) {
            $scd .= ' Recipient="' . self::esc((string)$c['recipient']) . '"';
        }
        if ($scdInResponseTo !== false) {
            $scd .= ' InResponseTo="' . self::esc((string)$scdInResponseTo) . '"';
        }
        if ($c['scdNotOnOrAfter'] !== false) {
            $scd .= ' NotOnOrAfter="' . self::time((int)$c['scdNotOnOrAfter']) . '"';
        }
        $scd .= '/>';

        $attributes = '';
        /** @var array<string, list<string>> $declared */
        $declared = $c['attributes'];
        foreach ($declared as $name => $values) {
            $attributes .= '<saml:Attribute Name="' . self::esc((string)$name) . '">';
            foreach ($values as $value) {
                $attributes .= '<saml:AttributeValue>' . self::esc((string)$value) . '</saml:AttributeValue>';
            }
            $attributes .= '</saml:Attribute>';
        }

        if ($attributes !== '') {
            $attributes = '<saml:AttributeStatement>' . $attributes . '</saml:AttributeStatement>';
        }

        return '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' ID="' . self::esc((string)$c['assertionId']) . '"'
            . ' Version="2.0" IssueInstant="' . self::time($now) . '">'
            . '<saml:Issuer>' . self::esc((string)$c['issuer']) . '</saml:Issuer>'
            . '<saml:Subject>'
            . '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">'
            . self::esc((string)$c['nameId'])
            . '</saml:NameID>'
            . '<saml:SubjectConfirmation Method="' . self::esc((string)$c['method']) . '">'
            . $scd
            . '</saml:SubjectConfirmation>'
            . '</saml:Subject>'
            . $conditions
            . '<saml:AuthnStatement AuthnInstant="' . self::time($now) . '"'
            . ' SessionIndex="' . self::esc((string)$c['sessionIndex']) . '">'
            . '<saml:AuthnContext><saml:AuthnContextClassRef>'
            . 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
            . '</saml:AuthnContextClassRef></saml:AuthnContext>'
            . '</saml:AuthnStatement>'
            . $attributes
            . '</saml:Assertion>';
    }

    /**
     * The ID an assertion really carries. Utils::addSign() goes through xmlseclibs, which
     * overwrites the ID attribute with a generated one while building the Reference, so the id
     * a fixture asked for is not the id the signature is bound to.
     */
    public static function assertionId(string $assertionXml): string
    {
        $document = new \DOMDocument();
        $document->loadXML($assertionXml);

        $root = $document->documentElement;

        return $root instanceof \DOMElement ? $root->getAttribute('ID') : '';
    }

    private static function stripDeclaration(string $xml): string
    {
        return trim(preg_replace('/^<\?xml[^>]*\?>\s*/', '', $xml) ?? $xml);
    }

    private static function time(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }

    private static function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
