<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMElement;
use DOMNodeList;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\State\StateStore;

/**
 * Path 2 of SLO: the IdP's answer to a LogoutRequest this site sent.
 *
 * Same discipline as SamlLogoutRequestReader, plus the one check that only applies to an answer:
 * CORRELATION. The RelayState carries the state token issued by SamlLogoutRequest, the state
 * record carries the id of the request we sent, and `InResponseTo` must equal it. Without that,
 * a signed logout response captured from any other site (or from this site's own previous
 * logout) would be accepted as the answer to whatever is in flight now - the same mistake
 * SamlResponseReader closes for login with its InResponseTo check.
 *
 * Correlation is not decoration, so it is not optional and it is not "if present": a response
 * with no InResponseTo, or with one that does not match, is refused as unsolicited.
 *
 * The state token is consumed (burnt) whether or not the rest of the document survives - that is
 * StateStore's contract, and a single-use token that survives a failed parse is a token an
 * attacker can grind against.
 */
final class SamlLogoutResponseReader extends SamlLogoutMessageReader
{
    private StateStore $stateStore;

    public function __construct(
        SamlConnectionConfig $config,
        ClockInterface $clock,
        StateStore $stateStore
    ) {
        parent::__construct($config, $clock);

        $this->stateStore = $stateStore;
    }

    /**
     * @param string $rawQuery The query string EXACTLY as received ($_SERVER['QUERY_STRING']).
     */
    public function read(string $rawQuery): InboundLogoutResponse
    {
        $this->detail = '';

        if (!$this->config->canLogout()) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Single logout is not configured on this connection.'
            );
        }

        $raw = $this->rawParameters($rawQuery);

        $this->verifyRedirectSignature($raw, 'SAMLResponse');

        $document = $this->loadDocument($this->inflateMessage($raw, 'SAMLResponse'));
        $root = $this->requireRoot($document, 'LogoutResponse');
        $id = $this->requireId($root);

        $this->checkIssuer($document, $root);
        $this->checkDestination($root);
        $this->checkIssueInstant($root);

        $inResponseTo = $this->correlate($raw, $root);
        [$status, $secondary] = $this->readStatus($document, $root);

        return new InboundLogoutResponse(
            $id,
            $inResponseTo,
            $status,
            $secondary,
            array_key_exists('RelayState', $raw) ? $raw['RelayState'] : null
        );
    }

    /**
     * @param array<string, string> $raw
     * @return string The id of our own LogoutRequest that this answers.
     */
    private function correlate(array $raw, DOMElement $root): string
    {
        $relayState = $raw['RelayState'] ?? '';

        if ($relayState === '') {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Logout response carries no RelayState, so no logout of ours matches it.'
            );
        }

        $validation = $this->stateStore->consume(rawurldecode($relayState));

        if (!$validation->valid) {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Logout state rejected: ' . $validation->reasonCode . '.'
            );
        }

        $requestId = $validation->context()['logout_request_id'] ?? '';

        if ($requestId === '') {
            // The state exists but was issued for something else (a login, say). Accepting it
            // would mean a login state could authorise a logout response.
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'State record carries no logout request id to match InResponseTo against.'
            );
        }

        $inResponseTo = trim($root->getAttribute('InResponseTo'));

        if ($inResponseTo === '' || !hash_equals($requestId, $inResponseTo)) {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'InResponseTo does not match the logout request id this site issued.'
            );
        }

        return $inResponseTo;
    }

    /**
     * @return array{0: string, 1: ?string} [top-level StatusCode, second-level StatusCode or null]
     */
    private function readStatus(\DOMDocument $document, DOMElement $root): array
    {
        $nodes = $this->xpath($document)->query('./samlp:Status/samlp:StatusCode', $root);

        if (!$nodes instanceof DOMNodeList || $nodes->length === 0) {
            $this->fail(
                IdentityReaderException::STATUS_NOT_SUCCESS,
                'Logout response carries no samlp:StatusCode.'
            );
        }

        $top = $nodes->item(0);
        $value = $top instanceof DOMElement ? trim($top->getAttribute('Value')) : '';

        if ($value === '') {
            $this->fail(
                IdentityReaderException::STATUS_NOT_SUCCESS,
                'Logout response StatusCode carries no Value.'
            );
        }

        $secondary = null;
        if ($top instanceof DOMElement) {
            $nested = $this->xpath($document)->query('./samlp:StatusCode', $top);
            if ($nested instanceof DOMNodeList && $nested->length > 0) {
                $node = $nested->item(0);
                $nestedValue = $node instanceof DOMElement ? trim($node->getAttribute('Value')) : '';
                $secondary = $nestedValue === '' ? null : $nestedValue;
            }
        }

        // A non-Success status is NOT a rejection here. The IdP saying "I could not do it" is a
        // truthful, correctly signed answer, and the caller still has a local session to end;
        // throwing would turn the IdP's honesty into an error page. The status is reported.
        return [$value, $secondary];
    }
}
