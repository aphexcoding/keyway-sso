<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMDocument;
use DOMElement;
use InvalidArgumentException;

/**
 * The SAML 2.0 metadata document an administrator hands to their identity provider.
 *
 * This is the cheapest half of the integration and the one that decides whether the expensive
 * half ever gets a chance: every value an IdP admin would otherwise retype by hand - entity id,
 * ACS URL, binding, the certificate - is copied wrong at least once per deployment, and the
 * resulting failure surfaces on the IdP's side as a generic error with nothing on ours to read.
 *
 * ------------------------------------------------------------------------------------------
 * THE DOCUMENT DESCRIBES WHAT THIS PLUGIN ACTUALLY DOES - NOT WHAT SAML ALLOWS
 * ------------------------------------------------------------------------------------------
 *
 * Metadata is a promise. An IdP configures itself from it and then holds us to it, so every
 * flag here is pinned to a fact about the code rather than to what looks impressive:
 *
 *  - `AuthnRequestsSigned="false"` - SamlAuthnRequest deliberately does not sign requests (it
 *    says so in its own docblock: no SigAlg, no Signature). Declaring `true` would make an IdP
 *    that trusts metadata configure "require signed AuthnRequest" and reject every login we
 *    ever send. A false promise here costs more than the missing feature.
 *  - `WantAssertionsSigned="true"` - SamlResponseReader requires a signature unconditionally,
 *    so this one is simply true, and saying so lets a correctly behaving IdP fail loudly at
 *    configuration time instead of silently at login time.
 *  - AssertionConsumerService is HTTP-POST ONLY. It is the one binding this SP can receive on:
 *    SamlAuthnRequest::BINDING_HTTP_POST asks for it and the connection is wired as
 *    CallbackStyle::CrossSitePost. Advertising HTTP-Artifact or PAOS because the schema permits
 *    them would advertise an endpoint that answers with an error.
 *  - SingleLogoutService is emitted ONLY when an SLO URL is passed, and HTTP-Redirect is the
 *    only binding it is ever emitted with - the one binding SsoController::actionSlo can
 *    verify. The caller passes a URL only when SamlConnectionConfig::canLogout() holds on a
 *    connection whose protocol really is SAML (SettingsTranslator::spMetadata); an empty or
 *    guessed Location would tell the IdP to send LogoutRequests to a URL that refuses them,
 *    which looks to an admin exactly like a bug in their IdP. There is no SP-INITIATED logout:
 *    signing out of Craft does not sign anybody out of the identity provider.
 *  - The default NameIDFormat list is `unspecified` and nothing else. It is tempting to
 *    advertise `emailAddress`, but SamlResponseReader::readNameId() does not inspect the Format
 *    attribute at all, so we would be promising an enforcement we do not perform. When the
 *    reader starts checking the format, this default changes with it - not before.
 *  - The KeyDescriptor, when a certificate is supplied, is `use="encryption"`. We do not sign,
 *    so a signing key would be another promise with no code behind it; an encryption key is the
 *    one an IdP can actually use against us today (SamlConnectionConfig::canDecrypt()).
 *
 * ------------------------------------------------------------------------------------------
 * ELEMENT ORDER IS NOT COSMETIC
 * ------------------------------------------------------------------------------------------
 *
 * Inside SPSSODescriptor the children must appear as KeyDescriptor -> SingleLogoutService ->
 * NameIDFormat -> AssertionConsumerService. md:SSODescriptorType inherits its sequence from
 * md:RoleDescriptorType, and a sequence in XSD is ordered: a validating IdP parser rejects a
 * document whose elements are shuffled even though every value in it is correct. That failure
 * mode is invisible to any test that only greps for substrings, so there is a test that reads
 * the child node names in order.
 *
 * Built through DOM, never by concatenating strings - the same reason as in SamlAuthnRequest:
 * an entity id or an ACS URL containing `&` or `"` has to be escaped by the writer, not by us.
 *
 * Craft-free and Composer-free by construction, like the rest of Core\ and Protocol\. There is
 * no time() here either: `validUntil` arrives as an argument, because a document whose expiry
 * is read from the wall clock cannot be asserted on.
 */
final class SpMetadata
{
    private const NS_METADATA = 'urn:oasis:names:tc:SAML:2.0:metadata';
    private const NS_XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const PROTOCOL_SAML2 = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    private const BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    /** See the docblock: the only format the reader can honestly claim to accept. */
    public const NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified';

    /** Long enough to stay readable in Content-Disposition, short enough for every filesystem. */
    private const FILENAME_STEM_LIMIT = 60;

    private const FILENAME_SUFFIX = '-metadata.xml';

    private const FILENAME_FALLBACK = 'keyway-sso' . self::FILENAME_SUFFIX;

    /** SamlConnectionConfig::looksLikeCertificate()'s floor, kept identical on purpose. */
    private const CERTIFICATE_MIN_LENGTH = 256;

    private string $entityId;
    private string $acsUrl;
    private ?string $spX509Cert;
    private ?string $sloUrl;
    private ?int $validUntil;

    /** @var list<string> */
    private array $nameIdFormats;

    /**
     * @param string      $entityId      The SP entity id, exactly as the reader's audience check
     *                                   expects it.
     * @param string      $acsUrl        Absolute http(s) URL of the assertion consumer service.
     * @param string|null $spX509Cert    PEM or bare base64 DER; null emits no KeyDescriptor.
     * @param string|null $sloUrl        Absolute http(s) URL, or null while there is no SLO.
     * @param int|null    $validUntil    Unix timestamp, or null to omit the attribute entirely.
     * @param list<string>|null $nameIdFormats Null keeps the class default (see the docblock).
     */
    public function __construct(
        string $entityId,
        string $acsUrl,
        ?string $spX509Cert = null,
        ?string $sloUrl = null,
        ?int $validUntil = null,
        ?array $nameIdFormats = null
    ) {
        $entityId = trim($entityId);
        $acsUrl = trim($acsUrl);

        if ($entityId === '') {
            throw new InvalidArgumentException('SP entity id must not be empty.');
        }

        // DOM does not defend this one. `setAttribute()` accepts bytes that are not valid UTF-8
        // without a warning, `saveXML()` returns them, and the endpoint then serves HTTP 200 with
        // a body no parser will read - an error the administrator has no way of tracing back to a
        // settings field. A NUL byte is worse than unparseable: it TRUNCATES the value, so the
        // document would name a different entity id than the one SamlResponseReader compares the
        // Audience against, which is the one failure metadata exists to prevent.
        foreach (['SP entity id' => $entityId, 'ACS URL' => $acsUrl] as $label => $value) {
            if (preg_match('//u', $value) !== 1 || str_contains($value, "\0")) {
                throw new InvalidArgumentException($label . ' must be valid UTF-8 and free of NUL bytes.');
            }
        }

        if (!self::isHttpUrl($acsUrl)) {
            throw new InvalidArgumentException('ACS URL must be an absolute http(s) URL.');
        }

        if ($sloUrl !== null) {
            $sloUrl = trim($sloUrl);

            if (!self::isHttpUrl($sloUrl)) {
                throw new InvalidArgumentException(
                    'Single logout URL must be an absolute http(s) URL, or null.'
                );
            }
        }

        if ($spX509Cert !== null) {
            $spX509Cert = self::certificateBody($spX509Cert);
        }

        if ($nameIdFormats !== null) {
            $trimmed = [];

            foreach ($nameIdFormats as $format) {
                $format = trim((string)$format);

                if ($format === '') {
                    throw new InvalidArgumentException('NameID formats must not contain empty entries.');
                }

                $trimmed[] = $format;
            }

            if ($trimmed === []) {
                throw new InvalidArgumentException(
                    'NameID formats must be a non-empty list, or null for the default.'
                );
            }

            $nameIdFormats = $trimmed;
        }

        $this->entityId = $entityId;
        $this->acsUrl = $acsUrl;
        $this->spX509Cert = $spX509Cert;
        $this->sloUrl = $sloUrl;
        $this->validUntil = $validUntil;
        $this->nameIdFormats = $nameIdFormats ?? [self::NAMEID_UNSPECIFIED];
    }

    /**
     * The entity id this document names, normalised exactly as it was written into it.
     *
     * Exists so that a caller building a `Content-Disposition` header does not have to remember
     * which of the two strings it passed in - the raw setting or the trimmed one - matches the
     * document it is about to send.
     */
    public function entityId(): string
    {
        return $this->entityId;
    }

    /**
     * The whole document, XML declaration included, indented because a human reads it before an
     * IdP does.
     */
    public function toXml(): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = true;

        $entity = $document->createElementNS(self::NS_METADATA, 'md:EntityDescriptor');
        // Attached as it is built, top down: DOM only suppresses a redundant xmlns declaration
        // on a child when the ancestor carrying it is already in the tree. Build the branches
        // first and every ds: element repeats the namespace - valid, but noise in a file whose
        // whole job is to be read by a human before an IdP parses it.
        $document->appendChild($entity);
        $entity->setAttribute('entityID', $this->entityId);

        if ($this->validUntil !== null) {
            $entity->setAttribute('validUntil', self::samlTime($this->validUntil));
        }

        if ($this->spX509Cert !== null) {
            $entity->setAttributeNS(
                'http://www.w3.org/2000/xmlns/',
                'xmlns:ds',
                self::NS_XMLDSIG
            );
        }

        $descriptor = $document->createElementNS(self::NS_METADATA, 'md:SPSSODescriptor');
        $entity->appendChild($descriptor);
        $descriptor->setAttribute('protocolSupportEnumeration', self::PROTOCOL_SAML2);
        $descriptor->setAttribute('AuthnRequestsSigned', 'false');
        $descriptor->setAttribute('WantAssertionsSigned', 'true');

        // Order matters; see the class docblock.
        if ($this->spX509Cert !== null) {
            $this->appendKeyDescriptor($document, $descriptor);
        }

        if ($this->sloUrl !== null) {
            $logout = $document->createElementNS(self::NS_METADATA, 'md:SingleLogoutService');
            $descriptor->appendChild($logout);
            $logout->setAttribute('Binding', self::BINDING_HTTP_REDIRECT);
            $logout->setAttribute('Location', $this->sloUrl);
        }

        foreach ($this->nameIdFormats as $format) {
            $element = $document->createElementNS(self::NS_METADATA, 'md:NameIDFormat');
            $descriptor->appendChild($element);
            $element->appendChild($document->createTextNode($format));
        }

        $acs = $document->createElementNS(self::NS_METADATA, 'md:AssertionConsumerService');
        $descriptor->appendChild($acs);
        $acs->setAttribute('Binding', self::BINDING_HTTP_POST);
        $acs->setAttribute('Location', $this->acsUrl);
        $acs->setAttribute('index', '0');
        $acs->setAttribute('isDefault', 'true');

        return (string)$document->saveXML();
    }

    /**
     * A file name for Content-Disposition, derived from the entity id so that an admin with
     * several sites can tell two downloads apart.
     *
     * Reduced to `[A-Za-z0-9._-]` rather than merely escaped: the value reaches a response
     * header, where a quote, a semicolon or a bare CR/LF is a header-splitting problem and not
     * a cosmetic one. Deterministic, because the name shows up in support tickets.
     */
    public static function fileName(string $entityId): string
    {
        $stem = preg_replace('/[^A-Za-z0-9._-]+/', '-', $entityId) ?? '';
        $stem = preg_replace('/-{2,}/', '-', $stem) ?? '';
        $stem = trim($stem, '-._');

        if (strlen($stem) > self::FILENAME_STEM_LIMIT) {
            $stem = rtrim(substr($stem, 0, self::FILENAME_STEM_LIMIT), '-._');
        }

        if ($stem === '') {
            return self::FILENAME_FALLBACK;
        }

        return $stem . self::FILENAME_SUFFIX;
    }

    /** `<md:KeyDescriptor use="encryption">` wrapping the bare base64 DER. */
    private function appendKeyDescriptor(DOMDocument $document, DOMElement $parent): void
    {
        $descriptor = $document->createElementNS(self::NS_METADATA, 'md:KeyDescriptor');
        $parent->appendChild($descriptor);
        $descriptor->setAttribute('use', 'encryption');

        $keyInfo = $document->createElementNS(self::NS_XMLDSIG, 'ds:KeyInfo');
        $descriptor->appendChild($keyInfo);

        $data = $document->createElementNS(self::NS_XMLDSIG, 'ds:X509Data');
        $keyInfo->appendChild($data);

        $certificate = $document->createElementNS(self::NS_XMLDSIG, 'ds:X509Certificate');
        $data->appendChild($certificate);
        $certificate->appendChild($document->createTextNode((string)$this->spX509Cert));
    }

    /**
     * The base64 body of ONE X.509 certificate, or an exception.
     *
     * ------------------------------------------------------------------------------------------
     * THIS IS THE ONLY THING STANDING BETWEEN A SETTINGS FIELD AND AN ANONYMOUS ENDPOINT
     * ------------------------------------------------------------------------------------------
     *
     * The plugin stores an SP PRIVATE KEY one field away from where a certificate will live
     * (`samlSpPrivateKey`, for decrypting assertions), this document is served without a session
     * to anyone who asks, and identity providers re-fetch it on a schedule. Publishing that key
     * once is not a bug that can be taken back.
     *
     * TWO EARLIER VERSIONS OF THIS CHECK LEAKED, and both failures were the same mistake -
     * asking a question ABOUT PART of the value instead of matching the WHOLE of it:
     *
     *  1. "strip any `-----BEGIN ...-----` armour, then check the rest is base64" accepted a
     *     private key outright: the body of a PEM key block is base64 too.
     *  2. "refuse a value that has `-----BEGIN` but not `-----BEGIN CERTIFICATE-----`" accepted
     *     a value carrying BOTH - the `fullchain + key` paste, which is the single most common
     *     way an administrator fills a field like this - and then merged the two bodies into one
     *     `ds:X509Certificate`. It also still accepted a key with its armour removed by hand.
     *
     * So the value is now matched AS A WHOLE against exactly one anchored certificate block, and
     * the decoded bytes must parse as X.509. There is nothing left for a second block, a stray
     * key or a fingerprint to hide in.
     */
    private static function certificateBody(string $value): string
    {
        $armoured = '/\A\s*-----BEGIN CERTIFICATE-----(?<body>[A-Za-z0-9+\/=\s]+)-----END CERTIFICATE-----\s*\z/';

        if (preg_match($armoured, $value, $matches) === 1) {
            $body = $matches['body'];
        } elseif (!str_contains($value, '-----')) {
            // A bare base64 body, which is what most panels display. Legal, and it is exactly the
            // shape a de-armoured PRIVATE KEY has too - which is why openssl, not the shape, is
            // what decides below.
            //
            // MEASURED: this condition changes no verdict. Removing it leaves the suite green,
            // because anything carrying a `-` fails the base64 check a few lines down anyway. It
            // stays for the error MESSAGE - "one PEM block or its bare body" tells an
            // administrator what to paste; "must be base64" does not - and it is written down
            // here so nobody re-derives it as dead code and deletes the wrong one of the two.
            $body = $value;
        } else {
            throw new InvalidArgumentException(
                'SP certificate must be exactly one PEM X.509 CERTIFICATE block, or its bare '
                . 'base64 body. Anything else - a private key, a certificate bundled with a key, '
                . 'a chain - is refused: this document is published anonymously.'
            );
        }

        $body = preg_replace('/\s+/', '', $body) ?? '';

        // The floor SamlConnectionConfig::looksLikeCertificate() uses, kept identical on purpose:
        // no X.509 certificate is this short, and a SHA-256 fingerprint is 64 characters.
        if (
            strlen($body) < self::CERTIFICATE_MIN_LENGTH
            || preg_match('/\A[A-Za-z0-9+\/=]+\z/', $body) !== 1
        ) {
            throw new InvalidArgumentException(
                'SP certificate must be a PEM or base64 X.509 certificate, or null.'
            );
        }

        // THE CHECK THAT ACTUALLY DECIDES. Shape cannot tell a de-armoured certificate from a
        // de-armoured private key - both are base64 of DER-ish bytes - and this can:
        // openssl_x509_read() parses the structure.
        //
        // FAIL-CLOSED WHEN THE EXTENSION IS MISSING, rather than falling back to the shape rules.
        // Without openssl, those rules are exactly the gate that leaked twice already, and this
        // document is published anonymously. `composer.json` requires `ext-openssl` and Craft 5
        // requires it too, so this branch is unreachable on any install that could call it.
        if (!extension_loaded('openssl')) {
            throw new InvalidArgumentException(
                'Cannot verify an SP certificate without ext-openssl, so none is published. '
                . 'Shape alone does not distinguish a certificate from a private key.'
            );
        }

        {
            $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split($body, 64, "\n") . "-----END CERTIFICATE-----\n";

            // Errors are queued rather than thrown; drained so a refusal here cannot surface as
            // somebody else's confusing openssl error later in the request.
            $parsed = @openssl_x509_read($pem);

            while (openssl_error_string() !== false) {
                // drain
            }

            if ($parsed === false) {
                throw new InvalidArgumentException(
                    'SP certificate did not parse as an X.509 certificate. A private key, a '
                    . 'public key or a truncated paste all land here: this document is published '
                    . 'anonymously, so anything unrecognised is refused.'
                );
            }

            // WHAT GOES INTO THE DOCUMENT IS WHAT OPENSSL PARSED, NEVER WHAT THE CALLER PASSED -
            // and this is the third and last shape of the same leak, so it is worth being exact
            // about why. `openssl_x509_read()` reads the FIRST DER structure it finds and does
            // not complain about bytes after it, so `base64(DER(certificate) . DER(private key))`
            // is a value that passes the anchored pattern (one block, clean alphabet) AND parses
            // AND still carries the key. Re-exporting collapses the value to the certificate
            // openssl actually recognised: for a clean certificate the result is byte-for-byte
            // the input, and for a poisoned one everything past the certificate is gone. It also
            // bounds the response - a 24 MB paste leaves as 1.2 kB.
            if (openssl_x509_export($parsed, $exported) !== true) {
                throw new InvalidArgumentException(
                    'SP certificate parsed but could not be re-exported; it is not published.'
                );
            }

            $body = preg_replace(
                '/\s+/',
                '',
                str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $exported)
            ) ?? '';
        }

        return $body;
    }

    /** The same rule SamlConnectionConfig::isHttpUrl() applies; kept identical on purpose. */
    private static function isHttpUrl(string $url): bool
    {
        if ($url === '') {
            return false;
        }

        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));

        return ($scheme === 'https' || $scheme === 'http')
            && (string)parse_url($url, PHP_URL_HOST) !== '';
    }

    /** xsd:dateTime in UTC - the only form SAML metadata accepts for validUntil. */
    private static function samlTime(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }
}
