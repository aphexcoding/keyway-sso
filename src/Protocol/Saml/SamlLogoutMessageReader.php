<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;
use Throwable;

/**
 * The hostile half of Single Logout: everything both inbound logout messages have in common.
 *
 * SamlResponseReader is the model for this file and the resemblance is deliberate, not
 * copy-paste convenience: a LogoutRequest is the one message in SAML whose whole purpose is to
 * DESTROY a session, so a lenient reader here is a remote session-kill primitive for anybody who
 * can shape a URL. The same discipline applies - parser hardened before anything reads meaning,
 * one rejection code per class of failure, fail-closed on every uncertainty, and not one byte of
 * the document in the message the user sees.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THE SIGNATURE IS CHECKED OVER THE RAW QUERY STRING
 * ------------------------------------------------------------------------------------------
 *
 * On HTTP-Redirect the signature does not cover the XML. It covers the octets of the query
 * string (SAML 2.0 Bindings 3.4.4.1): `SAMLRequest`/`SAMLResponse`, then `RelayState` if it was
 * present, then `SigAlg`, each still percent-encoded exactly as the sender encoded it. That is
 * why verifyRedirectSignature() takes the raw query string and never an array: PHP's parse_str()
 * decodes, and re-encoding a decoded value is a guess about the sender's encoder. `%2F` vs `/`,
 * `+` vs `%20` and the ordering of parameters are all choices the sender made and we cannot
 * reproduce them - a verifier that re-encodes silently accepts documents whose signature never
 * verified, which is the classic way this binding is broken.
 *
 * A duplicated parameter is refused rather than resolved, for the same reason: `?SAMLRequest=a&
 * SAMLRequest=b` lets one layer sign the first and another read the second.
 *
 * ------------------------------------------------------------------------------------------
 * HTTP-REDIRECT ONLY, AND SAID OUT LOUD
 * ------------------------------------------------------------------------------------------
 *
 * Inbound logout messages are accepted on HTTP-Redirect and on nothing else. HTTP-POST SLO with
 * an enveloped XML signature is a second, differently-shaped verification path (canonicalisation,
 * reference pinning, the whole XSW surface SamlResponseReader deals with) and adding it untested
 * would be adding an unverified way in. The metadata this plugin publishes must therefore
 * advertise the Redirect binding only - if it ever advertises POST, this class is what has to
 * change first.
 */
abstract class SamlLogoutMessageReader
{
    protected const NS_SAML = Constants::NS_SAML;
    protected const NS_SAMLP = Constants::NS_SAMLP;

    /** Shown to the end user; identical for every failure, like in SamlResponseReader. */
    protected const USER_MESSAGE = 'We could not verify the single logout message from your identity provider.';

    /**
     * How old an inbound logout message may be. SAML puts no lifetime on a LogoutRequest, so
     * without a ceiling a captured URL stays valid forever; five minutes is the same order as
     * the login state TTL and well above any real redirect chain.
     */
    protected const MAX_MESSAGE_AGE = 300;

    /**
     * Inflate ceiling for the DEFLATE-ed parameter, in bytes. A logout message is a few hundred
     * bytes; the ceiling exists so that a compression bomb costs the attacker a 400 instead of
     * the site's memory limit.
     */
    protected const MAX_INFLATED_BYTES = 262144;

    /**
     * Signature algorithms accepted on the redirect binding, mapped to their OpenSSL digest.
     *
     * An allowlist, never a lookup that falls back to "whatever OpenSSL recognises". SHA-1 is
     * absent on purpose and its absence is a rule, not an oversight: `rsa-sha1` is still what
     * several IdPs default to, so accepting "the algorithm the message asked for" is the exact
     * downgrade this table exists to refuse.
     */
    protected const SIGNATURE_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => OPENSSL_ALGO_SHA256,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
    ];

    protected SamlConnectionConfig $config;
    protected ClockInterface $clock;

    /** Last rejection detail, for the diagnostics record. Never shown to the user. */
    protected string $detail = '';

    public function __construct(SamlConnectionConfig $config, ClockInterface $clock)
    {
        $this->config = $config;
        $this->clock = $clock;
    }

    /**
     * Administrator-facing detail of the last rejection (masked diagnostics record, never the
     * screen). Empty when nothing was rejected yet.
     */
    public function detail(): string
    {
        return $this->detail;
    }

    // -----------------------------------------------------------------------------------
    // Redirect binding
    // -----------------------------------------------------------------------------------

    /**
     * Splits a query string into single-valued, still-encoded parameters.
     *
     * Raw on purpose (see the class docblock) and single-valued on purpose: a repeated parameter
     * is rejected rather than resolved.
     *
     * @return array<string, string> Parameter name (decoded) => raw, still-encoded value.
     */
    protected function rawParameters(string $rawQuery): array
    {
        $rawQuery = trim($rawQuery);

        // Exactly one, never ltrim(): '??a=b' is not a query string with two decorative marks,
        // it is a query string whose first parameter is named '?a'.
        if (str_starts_with($rawQuery, '?')) {
            $rawQuery = substr($rawQuery, 1);
        }

        if ($rawQuery === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Logout endpoint was called with an empty query string.'
            );
        }

        $parameters = [];

        foreach (explode('&', $rawQuery) as $pair) {
            if ($pair === '') {
                continue;
            }

            $split = explode('=', $pair, 2);
            $name = rawurldecode($split[0]);
            $value = $split[1] ?? '';

            if (array_key_exists($name, $parameters)) {
                $this->fail(
                    IdentityReaderException::MALFORMED_RESPONSE,
                    sprintf('Query string repeats the "%s" parameter.', $name)
                );
            }

            $parameters[$name] = $value;
        }

        return $parameters;
    }

    /**
     * Verifies the redirect-binding signature over the octets as they arrived.
     *
     * @param array<string, string> $raw          Output of rawParameters().
     * @param string                $messageParam `SAMLRequest` or `SAMLResponse`.
     */
    protected function verifyRedirectSignature(array $raw, string $messageParam): void
    {
        $signature = $raw['Signature'] ?? '';
        $sigAlg = $raw['SigAlg'] ?? '';

        if ($signature === '' || $sigAlg === '') {
            // Fail-closed and unconditional: this plugin only enables SLO on a connection that
            // can sign (SamlConnectionConfig::canLogout()), so "the IdP does not sign" is not a
            // configuration we offer. An unsigned inbound LogoutRequest is a session-kill GET.
            $this->fail(
                IdentityReaderException::SIGNATURE_MISSING,
                'Logout message carries no Signature/SigAlg pair.'
            );
        }

        $algorithm = rawurldecode($sigAlg);

        if (!array_key_exists($algorithm, self::SIGNATURE_ALGORITHMS)) {
            $this->fail(
                IdentityReaderException::ALGORITHM_NOT_ALLOWED,
                sprintf('Signature algorithm "%s" is not on the allowlist.', $algorithm)
            );
        }

        // Bindings 3.4.4.1: exactly this order, exactly these members, RelayState only when the
        // sender actually sent it. Rebuilt from the RAW values, so what we hash is what arrived.
        $signed = $messageParam . '=' . ($raw[$messageParam] ?? '');
        if (array_key_exists('RelayState', $raw)) {
            $signed .= '&RelayState=' . $raw['RelayState'];
        }
        $signed .= '&SigAlg=' . $sigAlg;

        $decodedSignature = base64_decode(rawurldecode($signature), true);

        if ($decodedSignature === false || $decodedSignature === '') {
            $this->fail(
                IdentityReaderException::SIGNATURE_INVALID,
                'Signature parameter is not valid base64.'
            );
        }

        $publicKey = openssl_pkey_get_public(Utils::formatCert($this->config->idpX509Cert));

        if ($publicKey === false) {
            $this->fail(
                IdentityReaderException::SIGNATURE_INVALID,
                'Configured IdP certificate does not yield a public key.'
            );
        }

        $verified = openssl_verify(
            $signed,
            (string)$decodedSignature,
            $publicKey,
            self::SIGNATURE_ALGORITHMS[$algorithm]
        );

        if ($verified !== 1) {
            $this->fail(
                IdentityReaderException::SIGNATURE_INVALID,
                'Redirect signature does not verify against the configured IdP certificate.'
            );
        }
    }

    /**
     * base64 -> raw DEFLATE -> XML, with the inflate ceiling applied.
     *
     * @param array<string, string> $raw
     */
    protected function inflateMessage(array $raw, string $messageParam): string
    {
        $encoded = $raw[$messageParam] ?? '';

        if ($encoded === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('Query string carries no %s parameter.', $messageParam)
            );
        }

        $deflated = base64_decode(rawurldecode($encoded), true);

        if ($deflated === false || $deflated === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('%s is not valid base64.', $messageParam)
            );
        }

        // Local suppression, not error_reporting(0): the global switch stays flipped if anything
        // inside throws, and this is a hot path on an unauthenticated endpoint.
        $xml = @gzinflate((string)$deflated, self::MAX_INFLATED_BYTES);

        if ($xml === false || trim($xml) === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('%s is not a DEFLATE-ed document.', $messageParam)
            );
        }

        return (string)$xml;
    }

    // -----------------------------------------------------------------------------------
    // Parsing, hardened exactly as in SamlResponseReader
    // -----------------------------------------------------------------------------------

    /**
     * Entity loading stays off (LIBXML_NONET, no LIBXML_NOENT) AND a DOCTYPE is rejected
     * outright. Both, because either alone has been bypassed before: parameter entities need no
     * network, and "the parser is safe by default" is a property of a PHP build, not of us.
     */
    protected function loadDocument(string $xml): DOMDocument
    {
        $document = new DOMDocument();
        $document->preserveWhiteSpace = true;
        $document->formatOutput = false;

        $previous = libxml_use_internal_errors(true);
        $loaded = $document->loadXML($xml, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($loaded === false || !$document->documentElement instanceof DOMElement) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Logout message is not well-formed XML.'
            );
        }

        $this->rejectDoctype($document);

        return $document;
    }

    protected function rejectDoctype(DOMDocument $document): void
    {
        foreach ($document->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                $this->fail(
                    IdentityReaderException::DOCTYPE_REJECTED,
                    'Document contains a DOCTYPE declaration.'
                );
            }
        }
    }

    protected function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_SAMLP);
        $xpath->registerNamespace('saml', self::NS_SAML);

        return $xpath;
    }

    /**
     * @param string $localName `LogoutRequest` or `LogoutResponse`.
     */
    protected function requireRoot(DOMDocument $document, string $localName): DOMElement
    {
        $root = $document->documentElement;

        if (!$root instanceof DOMElement
            || $root->localName !== $localName
            || $root->namespaceURI !== self::NS_SAMLP
        ) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('Document root is not a samlp:%s element.', $localName)
            );
        }

        return $root;
    }

    /**
     * The message's own id. Mandatory: without it there is nothing to correlate an answer to and
     * nothing to burn in the replay guard.
     */
    protected function requireId(DOMElement $root): string
    {
        $id = trim($root->getAttribute('ID'));

        if ($id === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Logout message carries no ID.'
            );
        }

        return $id;
    }

    /**
     * Exact, never a prefix or substring comparison, and against the CONFIGURED endpoint rather
     * than anything derived from $_SERVER - the lesson from SamlResponseReader B8.
     *
     * MANDATORY here, unlike in SamlResponseReader where the attribute is checked only when
     * present. The difference is not nerves, it is the binding: SAML 2.0 Bindings 3.4.5.1 says a
     * SIGNED message MUST carry Destination, and this reader requires a signature
     * unconditionally. A message without one is therefore malformed by the standard we are
     * reading it under - and treating it as "optional" is a real attack in a federation, where
     * an administrator of another service provider at the same IdP can take a LogoutRequest
     * issued for THEIR endpoint and send the identical, correctly signed URL to ours. Issuer
     * matches, signature matches, the replay guard sees a first use, and we end the named user's
     * session. Destination is the only thing in the document that says who the message was for.
     *
     * There is always something to compare against: canLogout() is checked before parsing and
     * guarantees spSloUrl is set.
     */
    protected function checkDestination(DOMElement $root): void
    {
        if (!$root->hasAttribute('Destination')) {
            $this->fail(
                IdentityReaderException::DESTINATION_MISMATCH,
                'Signed logout message carries no Destination, so it names no endpoint.'
            );
        }

        $destination = trim($root->getAttribute('Destination'));

        if ($this->config->spSloUrl === null || $destination !== $this->config->spSloUrl) {
            $this->fail(
                IdentityReaderException::DESTINATION_MISMATCH,
                sprintf('Destination "%s" is not this logout endpoint.', $destination)
            );
        }
    }

    protected function checkIssuer(DOMDocument $document, DOMElement $root): void
    {
        $nodes = $this->xpath($document)->query('./saml:Issuer', $root);
        $issuer = $nodes instanceof DOMNodeList && $nodes->length > 0
            ? trim((string)$nodes->item(0)?->textContent)
            : '';

        if ($issuer === '' || $issuer !== $this->config->idpEntityId) {
            $this->fail(
                IdentityReaderException::ISSUER_MISMATCH,
                sprintf('Logout message issuer "%s" is not the configured IdP.', $issuer)
            );
        }
    }

    /**
     * IssueInstant is mandatory here even though the reader could live without it: it is the only
     * thing that stops a captured, perfectly signed logout URL from working next year.
     *
     * It is RETURNED, not merely checked, because the replay guard's retention has to be derived
     * from the same axis as the acceptance window. SamlResponseReader does exactly this with the
     * assertion's NotOnOrAfter: the registry entry must outlive the document, and the document's
     * lifetime is measured from ITS clock, not from the moment we happened to see it.
     *
     * @return int The message's IssueInstant, as a Unix timestamp.
     */
    protected function checkIssueInstant(DOMElement $root): int
    {
        $issueInstant = $this->samlTime($root->getAttribute('IssueInstant'));

        if ($issueInstant === null) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Logout message carries no parsable IssueInstant.'
            );
        }

        $now = $this->clock->now();
        $skew = $this->config->clockSkew;

        if ($issueInstant > $now + $skew) {
            $this->fail(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Logout message is dated in the future.'
            );
        }

        if ($issueInstant < $now - $skew - self::MAX_MESSAGE_AGE) {
            $this->fail(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Logout message is older than the accepted window.'
            );
        }

        return $issueInstant;
    }

    /**
     * The instant after which a message dated `$issueInstant` can no longer be accepted by
     * checkIssueInstant(), whatever our clock said when it first arrived.
     *
     * Twice the skew, and deliberately so: the message may already have been accepted with our
     * clock one skew BEHIND the IdP's, and it stays acceptable until our clock is one skew
     * AHEAD. A registry entry that expires any earlier is an entry the message outlives - which
     * is precisely the replay this guard exists to stop.
     */
    protected function replayHorizon(int $issueInstant): int
    {
        return $issueInstant + self::MAX_MESSAGE_AGE + (2 * $this->config->clockSkew);
    }

    /**
     * `NotOnOrAfter` is optional on a LogoutRequest; when the IdP does state one, it binds.
     */
    protected function checkNotOnOrAfter(DOMElement $root): void
    {
        if (!$root->hasAttribute('NotOnOrAfter')) {
            return;
        }

        $notOnOrAfter = $this->samlTime($root->getAttribute('NotOnOrAfter'));

        if ($notOnOrAfter === null) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'NotOnOrAfter is present but not parsable.'
            );
        }

        if ($this->clock->now() - $this->config->clockSkew >= $notOnOrAfter) {
            $this->fail(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Logout message NotOnOrAfter has passed.'
            );
        }
    }

    /**
     * Delegated to the library, like in SamlResponseReader: SAML instants have their own grammar
     * and a home-grown strtotime() would accept things the standard does not.
     */
    protected function samlTime(string $value): ?int
    {
        $value = trim($value);

        if ($value === '') {
            return null;
        }

        try {
            return (int)Utils::parseSAML2Time($value);
        } catch (Throwable) {
            return null;
        }
    }

    protected function fail(string $reasonCode, string $detail): never
    {
        $this->detail = $detail;

        // The user gets one neutral sentence; the administrator gets $detail in the masked
        // diagnostics record. The document, the certificate and the signature never appear.
        throw new IdentityReaderException($reasonCode, static::USER_MESSAGE);
    }
}
