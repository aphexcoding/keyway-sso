<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMDocument;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\RandomSourceInterface;
use Keyway\Sso\Core\State\StateStore;
use RuntimeException;

/**
 * Path 1 of SLO: the LogoutRequest this site sends when a user signs out locally.
 *
 * Built through DOMDocument rather than OneLogin\Saml2\LogoutRequest, for the reason already
 * settled for SamlAuthnRequest and not re-opened here: the library calls `time()` and
 * `generateUniqueID()` directly, so the ID and the IssueInstant could not be pinned by the
 * injected clock and random source - and the ID is the one value in this class that MUST be
 * assertable, because it is what the IdP's answer is later correlated against. Every value that
 * comes from settings goes through DOM's writer, so an entity id containing `&` or `"` is
 * escaped rather than breaking out of the markup.
 *
 * Unlike the AuthnRequest, this message IS SIGNED. Two reasons, both hard: SAML 2.0 Core 3.7.1
 * says logout messages SHOULD be signed and IdPs read that as MUST, and an unsigned
 * LogoutRequest would let anybody who can make the browser issue a GET terminate the user's IdP
 * session. Signing is over the query string (HTTP-Redirect binding), done by
 * SamlRedirectSignature.
 *
 * The request id is written into a one-shot state record and the token travels as RelayState.
 * That is the correlation SamlLogoutResponseReader enforces; the id itself never leaves the
 * server (see SamlLogoutRedirect).
 *
 * WHAT THIS DELIBERATELY DOES NOT DO:
 *  - No `Reason` attribute. It is optional, no IdP acts on it, and a wrong one is a promise.
 *  - No `NotOnOrAfter` on our own request: we have no basis for guessing how long the IdP may
 *    take, and a value we invent would make our own message expire in somebody else's clock.
 *  - No EncryptedID. The NameID we send is the one the IdP gave us at login; encrypting it to
 *    the IdP's key is a separate piece of work with its own key handling.
 */
final class SamlLogoutRequest
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** 16 bytes -> 32 hex characters. The `_` prefix keeps the id a valid xsd:ID. */
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
     * @param string      $nameId       The subject as the IdP named it at login - not our local
     *                                  username. Asking the IdP to log out an identifier it
     *                                  never issued produces a Requester error at best.
     * @param string|null $sessionIndex The session the IdP named at login, when it named one.
     * @param string|null $returnUrl    Where the browser should land after the round trip; the
     *                                  state store sanitises it, exactly as at login.
     */
    public function start(
        string $nameId,
        ?string $sessionIndex = null,
        ?string $nameIdFormat = null,
        ?string $returnUrl = null
    ): SamlLogoutRedirect {
        if (!$this->config->canLogout()) {
            throw new RuntimeException(
                'Single logout is not configured on this connection: it needs the IdP SLO URL, '
                . 'our own SLO URL and an SP private key to sign with.'
            );
        }

        if (trim($nameId) === '') {
            // Fail-closed: a LogoutRequest with an empty subject is a request to log out
            // "somebody", and some IdPs answer it by ending every session they have.
            throw new RuntimeException('A LogoutRequest needs the subject the IdP issued at login.');
        }

        $id = '_' . bin2hex($this->random->bytes(self::ID_BYTES));

        $state = $this->stateStore->issue($returnUrl, [
            'protocol' => 'saml2',
            'logout_request_id' => $id,
        ]);

        $xml = $this->document($id, $nameId, $sessionIndex, $nameIdFormat);

        $deflated = gzdeflate($xml);

        if ($deflated === false) {
            throw new RuntimeException('Could not DEFLATE the SAML logout request; ext-zlib is broken.');
        }

        $url = SamlRedirectSignature::url(
            (string)$this->config->idpSloUrl,
            [
                'SAMLRequest' => rawurlencode(base64_encode($deflated)),
                'RelayState' => rawurlencode($state->value),
            ],
            (string)$this->config->spPrivateKey
        );

        return new SamlLogoutRedirect($url, $state);
    }

    private function document(
        string $id,
        string $nameId,
        ?string $sessionIndex,
        ?string $nameIdFormat
    ): string {
        $document = new DOMDocument('1.0', 'UTF-8');

        $root = $document->createElementNS(self::NS_PROTOCOL, 'samlp:LogoutRequest');
        $root->setAttribute('ID', $id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->clock->now()));
        $root->setAttribute('Destination', (string)$this->config->idpSloUrl);

        $issuer = $document->createElementNS(self::NS_ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($this->config->spEntityId));
        $root->appendChild($issuer);

        $subject = $document->createElementNS(self::NS_ASSERTION, 'saml:NameID');
        if ($nameIdFormat !== null && trim($nameIdFormat) !== '') {
            $subject->setAttribute('Format', trim($nameIdFormat));
        }
        $subject->appendChild($document->createTextNode($nameId));
        $root->appendChild($subject);

        if ($sessionIndex !== null && trim($sessionIndex) !== '') {
            // Naming the session narrows the request to the one we actually hold. Omitting it
            // asks the IdP to end every session of this subject, which is a bigger hammer than
            // a local sign-out is entitled to.
            $index = $document->createElementNS(self::NS_PROTOCOL, 'samlp:SessionIndex');
            $index->appendChild($document->createTextNode(trim($sessionIndex)));
            $root->appendChild($index);
        }

        $document->appendChild($root);

        // The element, not the document: the XML declaration is pointless inside a query
        // parameter and some IdPs choke on it after inflating.
        return (string)$document->saveXML($root);
    }
}
