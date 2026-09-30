<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMDocument;
use Keyway\Sso\Core\Port\AuthenticationStarterInterface;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\RandomSourceInterface;
use Keyway\Sso\Core\State\StateStore;
use RuntimeException;

/**
 * The start of a SAML login: an AuthnRequest on the HTTP-Redirect binding, plus the state the
 * callback will be verified against.
 *
 * The other half of SamlResponseReader. The reader is the paranoid one - it treats the incoming
 * document as the attacker's - and this class is deliberately small, because a request is not a
 * security boundary: nothing here is trusted on the way back. What it does own is the state
 * record, and that IS the boundary, which is why the state is issued here and not by the caller.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THE XML IS BUILT HERE INSTEAD OF BY OneLogin\Saml2\AuthnRequest
 * ------------------------------------------------------------------------------------------
 *
 * This cuts against the grain of SamlResponseReader's contract A2 ("no hand-written protocol
 * parsing"), so it is a decision and not an oversight. A2 is about PARSING: the incoming
 * document is hostile, canonicalisation and signature verification are where SAML implementations
 * get broken, and re-implementing that is how you end up with an XSW hole. Generating a
 * twelve-line request we fully control carries none of that risk. Against that:
 * OneLogin\Saml2\AuthnRequest calls `time()` and `Utils::generateUniqueID()` directly, so its
 * output cannot be pinned by the injected ClockInterface and RandomSourceInterface - the id and
 * the IssueInstant would be untestable, and "untestable" for the id means the value we write
 * into the state record is the one value in this class nobody could ever assert on. It also
 * wants a full OneLogin\Saml2\Settings array, which would mean a second, looser description of
 * the connection living next to SamlConnectionConfig. Both arguments point the same way, so the
 * document is built here, through DOM rather than string concatenation, and every value that
 * comes from settings is escaped by the DOM writer rather than by us.
 *
 * ------------------------------------------------------------------------------------------
 * WHAT THIS DELIBERATELY DOES NOT DO - named, because a silent gap is worse than a known one
 * ------------------------------------------------------------------------------------------
 *
 *  - The request is NOT SIGNED. There is no SigAlg and no Signature query parameter, so an IdP
 *    configured to require signed authentication requests will refuse this login outright. That
 *    is a separate piece of work with its own key handling; it is not smuggled in here.
 *  - The request id IS written into the state (`request_id`) and is NOT yet checked against the
 *    response's InResponseTo. Storing it now is the point: the check is a reader change, and if
 *    the value were not already in the state, closing it would mean touching the starter again.
 *    Until then, treat it as bookkeeping, not as protection.
 *  - No NameIDPolicy, no ForceAuthn, no RequestedAuthnContext. Every one of them narrows what
 *    the IdP is allowed to answer with, and an MVP that guesses those narrows them wrongly for
 *    somebody. They belong in settings, when somebody asks.
 *
 * Nothing here reads the incoming request, the environment or the wall clock: the endpoint and
 * both entity ids come from SamlConnectionConfig, the time comes from ClockInterface and the id
 * comes from RandomSourceInterface. That is what makes the whole request reproducible in a test.
 */
final class SamlAuthnRequest implements AuthenticationStarterInterface
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * The binding the IdP should answer on. HTTP-POST, and it matches the only thing the rest of
     * the plugin can receive: the connection is wired as CallbackStyle::CrossSitePost and the
     * reader reads a base64 SAMLResponse form field.
     */
    private const BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /** 16 bytes -> 32 hex characters. The `_` prefix is not decoration: see makeId(). */
    private const ID_BYTES = 16;

    private SamlConnectionConfig $config;
    private StateStore $stateStore;
    private ClockInterface $clock;
    private RandomSourceInterface $random;

    public function __construct(
        SamlConnectionConfig $config,
        StateStore $stateStore,
        ClockInterface $clock,
        RandomSourceInterface $random
    ) {
        $this->config = $config;
        $this->stateStore = $stateStore;
        $this->clock = $clock;
        $this->random = $random;
    }

    /**
     * The handle this connection is known by in the login state, and the string
     * SamlResponseReader::protocol() reports. LoginConnection refuses a pair whose two halves
     * disagree, because that pair produces a login that always starts and never finishes.
     */
    public function connection(): string
    {
        return 'saml2';
    }

    /**
     * @param array<string, string> $context Bookkeeping from LoginFlow (the connection handle and
     *                                       the browser-binding decision) that the callback
     *                                       refuses the login without. It is merged, not
     *                                       replaced - and our own keys are applied last, so no
     *                                       caller can substitute the request id.
     */
    public function start(?string $returnUrl = null, array $context = []): SamlRedirect
    {
        $id = $this->makeId();
        $xml = $this->document($id);

        $state = $this->stateStore->issue($returnUrl, array_merge($context, [
            'protocol' => 'saml2',
            'request_id' => $id,
        ]));

        // SAML 2.0 Bindings section 3.4.4.1: DEFLATE (RFC 1951, raw - no zlib or gzip wrapper),
        // then base64, then URL encoding. gzdeflate() is the raw one; gzcompress() and
        // gzencode() both add a header the IdP will not read past.
        $deflated = gzdeflate($xml);

        if ($deflated === false) {
            // Unreachable in practice, and that is exactly why it has to be loud: the fallback
            // this replaced cast false to '' and would have sent `SAMLRequest=` to the IdP, where
            // the failure resurfaces as somebody else's generic error page with nothing on our
            // side to read. Every other refusal in this plugin is fail-closed with a reason.
            throw new RuntimeException('Could not DEFLATE the SAML request; ext-zlib is broken.');
        }

        $parameters = [
            'SAMLRequest' => base64_encode($deflated),
            'RelayState' => $state->value,
        ];

        $separator = str_contains($this->config->idpSsoUrl, '?') ? '&' : '?';
        $url = $this->config->idpSsoUrl
            . $separator
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        return new SamlRedirect($url, $state);
    }

    /**
     * `ID` is an xsd:ID, which is an XML Name: it may not start with a digit. Hex bytes can, so
     * the prefix is a correctness requirement rather than a convention - an IdP with a validating
     * parser rejects the request without it, and it does so intermittently, which is worse.
     */
    private function makeId(): string
    {
        return '_' . bin2hex($this->random->bytes(self::ID_BYTES));
    }

    /**
     * The request document. Attribute values go through DOM's writer, so an entity id or an ACS
     * URL containing `&` or `"` is escaped rather than breaking out of the markup.
     */
    private function document(string $id): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');

        $root = $document->createElementNS(self::NS_PROTOCOL, 'samlp:AuthnRequest');
        $root->setAttribute('ID', $id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', self::samlTime($this->clock->now()));
        $root->setAttribute('Destination', $this->config->idpSsoUrl);
        $root->setAttribute('ProtocolBinding', self::BINDING_HTTP_POST);
        $root->setAttribute('AssertionConsumerServiceURL', $this->config->acsUrl);

        $issuer = $document->createElementNS(self::NS_ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($this->config->spEntityId));
        $root->appendChild($issuer);

        $document->appendChild($root);

        // The element, not the document: the XML declaration is pointless inside a query
        // parameter and some IdPs choke on it after inflating.
        return (string)$document->saveXML($root);
    }

    /**
     * xsd:dateTime in UTC, which is the only form SAML allows for IssueInstant. Derived from the
     * injected clock, never from time().
     */
    private static function samlTime(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }
}
