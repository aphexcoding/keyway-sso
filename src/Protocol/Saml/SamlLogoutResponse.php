<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMDocument;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\RandomSourceInterface;
use RuntimeException;

/**
 * Path 4 of SLO: our answer to an IdP-initiated LogoutRequest.
 *
 * ------------------------------------------------------------------------------------------
 * THE STATUS CODE IS A STATEMENT OF FACT, NOT A FORMALITY
 * ------------------------------------------------------------------------------------------
 *
 * An IdP running a logout across several service providers decides what to tell the user from
 * what we answer. Returning Success because "the HTTP part worked" is how a user is told they
 * are signed out everywhere while a session is still open here. So there is one named
 * constructor per honest outcome and no generic one:
 *
 *  - success()          - the session named in the request is gone.
 *  - partialLogout()    - top-level Success with second-level PartialLogout: some sessions of
 *                         this subject ended, some did not. SAML 2.0 Core 3.7.3.2 puts
 *                         PartialLogout at the SECOND level precisely because the request as
 *                         such was understood and honoured in part - it is not a Requester error.
 *  - unknownPrincipal() - Requester + UnknownPrincipal: we hold no session for that subject.
 *                         This is the answer when the NameID does not match the identity that
 *                         signed in. It is a normal outcome and must NOT be papered over by
 *                         ending the current browser's session instead - see
 *                         InboundLogoutRequest's docblock.
 *  - requesterError()   - Requester: the request was addressed to us but we cannot act on it.
 *  - responderError()   - Responder: our own failure, not theirs.
 *
 * Every one of them carries `InResponseTo` equal to the id of the request being answered. A
 * LogoutResponse without it, or with somebody else's id, is unanswerable: it teaches the IdP to
 * accept uncorrelated answers, which is the very thing we refuse on the way in.
 *
 * Built through DOM and signed over the query string, like SamlLogoutRequest, for the same
 * reasons and with the same clock and random source.
 */
final class SamlLogoutResponse
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    public const STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
    public const STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
    public const STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';
    public const STATUS_UNKNOWN_PRINCIPAL = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';

    private const ID_BYTES = 16;

    private SamlConnectionConfig $config;
    private ClockInterface $clock;
    private RandomSourceInterface $random;

    public function __construct(
        SamlConnectionConfig $config,
        ClockInterface $clock,
        RandomSourceInterface $random
    ) {
        $this->config = $config;
        $this->clock = $clock;
        $this->random = $random;
    }

    /** The session the IdP named is gone. */
    public function success(InboundLogoutRequest $request): SamlLogoutRedirect
    {
        return $this->answer($request, self::STATUS_SUCCESS, null);
    }

    /** Understood and honoured in part: some sessions of this subject are still open. */
    public function partialLogout(InboundLogoutRequest $request): SamlLogoutRedirect
    {
        return $this->answer($request, self::STATUS_SUCCESS, self::STATUS_PARTIAL_LOGOUT);
    }

    /** We hold no session for that subject. Nothing was ended. */
    public function unknownPrincipal(InboundLogoutRequest $request): SamlLogoutRedirect
    {
        return $this->answer($request, self::STATUS_REQUESTER, self::STATUS_UNKNOWN_PRINCIPAL);
    }

    /** Addressed to us, but we cannot act on it. */
    public function requesterError(InboundLogoutRequest $request): SamlLogoutRedirect
    {
        return $this->answer($request, self::STATUS_REQUESTER, null);
    }

    /** Our own failure. Said out loud so the IdP does not report a logout that did not happen. */
    public function responderError(InboundLogoutRequest $request): SamlLogoutRedirect
    {
        return $this->answer($request, self::STATUS_RESPONDER, null);
    }

    private function answer(
        InboundLogoutRequest $request,
        string $status,
        ?string $secondary
    ): SamlLogoutRedirect {
        if (!$this->config->canLogout()) {
            throw new RuntimeException('Single logout is not configured on this connection.');
        }

        $id = '_' . bin2hex($this->random->bytes(self::ID_BYTES));
        $xml = $this->document($id, $request->id, $status, $secondary);

        $deflated = gzdeflate($xml);

        if ($deflated === false) {
            throw new RuntimeException('Could not DEFLATE the SAML logout response; ext-zlib is broken.');
        }

        $parameters = ['SAMLResponse' => rawurlencode(base64_encode($deflated))];

        if ($request->rawRelayState !== null && $request->rawRelayState !== '') {
            // Echoed back byte for byte, still encoded as it arrived. RelayState is opaque to us
            // and re-encoding somebody else's encoding is a guess - and here it would also be a
            // guess we then sign, so the IdP would reject a signature that is arithmetically
            // correct over the wrong string.
            $parameters['RelayState'] = $request->rawRelayState;
        }

        return new SamlLogoutRedirect(SamlRedirectSignature::url(
            (string)$this->config->idpSloUrl,
            $parameters,
            (string)$this->config->spPrivateKey
        ));
    }

    private function document(
        string $id,
        string $inResponseTo,
        string $status,
        ?string $secondary
    ): string {
        $document = new DOMDocument('1.0', 'UTF-8');

        $root = $document->createElementNS(self::NS_PROTOCOL, 'samlp:LogoutResponse');
        $root->setAttribute('ID', $id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->clock->now()));
        $root->setAttribute('Destination', (string)$this->config->idpSloUrl);
        $root->setAttribute('InResponseTo', $inResponseTo);

        $issuer = $document->createElementNS(self::NS_ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($this->config->spEntityId));
        $root->appendChild($issuer);

        // Order matters: md/samlp sequences are ordered, and Issuer precedes Status.
        $statusElement = $document->createElementNS(self::NS_PROTOCOL, 'samlp:Status');
        $topCode = $document->createElementNS(self::NS_PROTOCOL, 'samlp:StatusCode');
        $topCode->setAttribute('Value', $status);

        if ($secondary !== null) {
            $nested = $document->createElementNS(self::NS_PROTOCOL, 'samlp:StatusCode');
            $nested->setAttribute('Value', $secondary);
            $topCode->appendChild($nested);
        }

        $statusElement->appendChild($topCode);
        $root->appendChild($statusElement);

        $document->appendChild($root);

        return (string)$document->saveXML($root);
    }
}
