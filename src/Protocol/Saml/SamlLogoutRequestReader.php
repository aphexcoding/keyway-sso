<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMElement;
use DOMNodeList;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\ReplayGuardInterface;

/**
 * Path 3 of SLO: an IdP-initiated LogoutRequest arriving at our endpoint.
 *
 * This is the most dangerous message the plugin reads. It is a GET, it arrives without any state
 * this site issued (nothing here was solicited), and if believed it ends somebody's session. So
 * the order of checks is the whole design:
 *
 *   1. raw-octet signature over the query string as it arrived    (is it from the IdP at all)
 *   2. inflate, parse with entities and DOCTYPE refused           (is it even a document)
 *   3. root element, ID                                           (is it the message we think)
 *   4. Issuer == configured IdP, Destination == our endpoint      (is it addressed to us)
 *   5. IssueInstant window, NotOnOrAfter when present             (is it still live)
 *   6. replay guard on the message ID                             (have we seen it before)
 *   7. only then the subject is read out                          (what is it asking)
 *
 * Cryptography first is not a stylistic choice: every later step touches attacker-controlled
 * structure, and doing any of that before the signature means doing work for anybody with a URL.
 *
 * What comes out is InboundLogoutRequest, whose docblock states the one rule this class cannot
 * enforce for the caller: the NameID is a value to MATCH against the identity that signed in,
 * never a selector to hand to a session store.
 */
final class SamlLogoutRequestReader extends SamlLogoutMessageReader
{
    private ReplayGuardInterface $replayGuard;

    public function __construct(
        SamlConnectionConfig $config,
        ClockInterface $clock,
        ReplayGuardInterface $replayGuard
    ) {
        parent::__construct($config, $clock);

        $this->replayGuard = $replayGuard;
    }

    /**
     * @param string $rawQuery The query string EXACTLY as received ($_SERVER['QUERY_STRING']).
     *                         Never an array, never a re-encoded one: see the parent docblock.
     */
    public function read(string $rawQuery): InboundLogoutRequest
    {
        $this->detail = '';

        if (!$this->config->canLogout()) {
            // Refusing before parsing: an endpoint that answers on a connection without SLO
            // configured is an endpoint answering with checks that were never configured either.
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Single logout is not configured on this connection.'
            );
        }

        $raw = $this->rawParameters($rawQuery);

        $this->verifyRedirectSignature($raw, 'SAMLRequest');

        $document = $this->loadDocument($this->inflateMessage($raw, 'SAMLRequest'));
        $root = $this->requireRoot($document, 'LogoutRequest');
        $id = $this->requireId($root);

        $this->checkIssuer($document, $root);
        $this->checkDestination($root);
        $issueInstant = $this->checkIssueInstant($root);
        $this->checkNotOnOrAfter($root);

        // Single use, on the IdP's own identifier. The signature stays valid forever, so without
        // this a captured logout URL is a replayable session-kill for the whole time window.
        //
        // The retention horizon comes from the MESSAGE, never from our clock at first sight:
        // the acceptance window is measured from IssueInstant, so an entry timed from now() sits
        // on a different axis and expires while the message is still acceptable. That gap is a
        // real replay - with the IdP's clock one skew ahead, the same URL kills the session again
        // minutes later. SamlResponseReader derives its horizon from the document for the same
        // reason.
        if (!$this->replayGuard->remember('slo:' . $id, $this->replayHorizon($issueInstant))) {
            $this->fail(
                IdentityReaderException::REPLAYED_ASSERTION,
                'Logout request id has already been accepted once.'
            );
        }

        [$nameId, $format] = $this->readNameId($root);

        return new InboundLogoutRequest(
            $id,
            $nameId,
            $format,
            $this->readSessionIndexes($root),
            array_key_exists('RelayState', $raw) ? $raw['RelayState'] : null
        );
    }

    /**
     * @return array{0: string, 1: ?string} [NameID, Format]
     */
    private function readNameId(DOMElement $root): array
    {
        $nodes = $this->xpath($root->ownerDocument)->query('./saml:NameID', $root);

        if (!$nodes instanceof DOMNodeList || $nodes->length !== 1) {
            // Exactly one, never "the first of several": two NameIDs mean two candidate
            // subjects, and picking one is picking whose session to end.
            $this->fail(
                IdentityReaderException::SUBJECT_MISSING,
                'LogoutRequest must carry exactly one saml:NameID.'
            );
        }

        $node = $nodes->item(0);

        if (!$node instanceof DOMElement) {
            $this->fail(
                IdentityReaderException::SUBJECT_MISSING,
                'NameID node is not an element.'
            );
        }

        // textContent, not firstChild->nodeValue: an XML comment inside the element truncates
        // the second reading and not the first (the SAML half of CVE-2017-11428). An
        // EncryptedID is a different element and is therefore refused here by construction.
        $nameId = trim((string)$node->textContent);

        if ($nameId === '') {
            $this->fail(
                IdentityReaderException::SUBJECT_MISSING,
                'NameID is empty or whitespace only.'
            );
        }

        $format = trim($node->getAttribute('Format'));

        return [$nameId, $format === '' ? null : $format];
    }

    /**
     * EVERY SessionIndex, not the first one.
     *
     * SAML allows a LogoutRequest to name several sessions and IdPs really do. Reading item(0)
     * and dropping the rest is not a security hole - it is a LIE to the IdP: we would end one
     * session, answer Success, and the IdP would tell the user they are signed out of sessions
     * that are still open. Refusing a multi-index request instead would be refusing a message
     * the standard permits, so the list travels up and the caller has to account for each one -
     * and answer partialLogout() when it cannot.
     *
     * @return list<string>
     */
    private function readSessionIndexes(DOMElement $root): array
    {
        $nodes = $this->xpath($root->ownerDocument)->query('./samlp:SessionIndex', $root);

        if (!$nodes instanceof DOMNodeList) {
            return [];
        }

        $indexes = [];
        foreach ($nodes as $node) {
            $value = trim((string)$node->textContent);
            if ($value !== '') {
                $indexes[] = $value;
            }
        }

        return $indexes;
    }
}
