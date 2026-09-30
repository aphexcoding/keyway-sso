<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Core\Port\ReplayGuardInterface;
use Keyway\Sso\Core\State\StateStore;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * SAML 2.0 implementation of IdentityReaderInterface (contract sections A and B).
 *
 * Division of labour with onelogin/php-saml 4.3.2, stated explicitly because the contract says
 * a check that is "configured in the library" does not count as done:
 *
 *  DELEGATED to the library (contract A2 - no hand-written protocol parsing):
 *    - XML parsing and canonicalisation, signature verification (Utils::validateSign, which is
 *      xmlseclibs underneath), assertion decryption, SAML time parsing.
 *
 *  BUILT HERE, because 4.3.2 does not give the guarantee the contract asks for:
 *    - B1  the library counts assertions inside Response only and only after status/parse work;
 *          we count every `Assertion`/`EncryptedAssertion` element in the whole document, in any
 *          namespace, before anything else touches it.
 *    - B2  the library validates "a signature with this xpath verifies"; it never proves the
 *          Reference resolves to the assertion we then read. We pin URI -> Assertion/@ID, require
 *          the ID to be unique in the document, require the signature to be a direct child of
 *          that assertion and require an enveloped-signature transform.
 *    - B5  Response::isValid() checks the audience only `if (!empty($validAudiences))`, so a
 *          response with no AudienceRestriction passes. Here it is mandatory.
 *    - B6  the library accepts a SubjectConfirmationData with NO NotOnOrAfter, and compares the
 *          Recipient with `strpos($recipient, $currentURL) === false`, i.e. a substring test
 *          against a URL derived from $_SERVER. Here both are mandatory and exact.
 *    - B8  the library's Destination check is a prefix comparison against $_SERVER-derived URLs
 *          (and `relaxDestinationValidation` can switch it off). Here it is exact against the
 *          configured ACS URL, and there is no way to relax it.
 *    - A4  the library uses `time()` and a hard-coded 180 s drift, above the contract ceiling of
 *          120 s. All time comparisons here go through ClockInterface and the configured skew.
 *    - A5  the library has no replay registry at all.
 *    - A6  the library compares issuers only inside its strict branch and only for issuers it
 *          happens to find; here the assertion issuer is mandatory and exact.
 *    - A7  getAttributes() trims values and can collapse repeated names; we read the attribute
 *          statement of the verified node ourselves, byte for byte.
 *
 * Because of that, Response::isValid() is NOT on the accept path. Using it would mean accepting
 * its $_SERVER-derived URL handling and its `time()`, and it would put a second, looser set of
 * rules next to this one - the classic way a bypass is introduced by a later refactor.
 *
 * Failure discipline (A8, and the audience split closed as BL-2): every rejection throws
 * IdentityReaderException with a stable reason code and a neutral, user-safe sentence. The
 * detail an administrator needs stays in `detail()`, which callers put in the masked diagnostics
 * record; it never reaches the login screen.
 */
final class SamlResponseReader implements IdentityReaderInterface
{
    private const NS_SAML = Constants::NS_SAML;
    private const NS_SAMLP = Constants::NS_SAMLP;
    private const NS_DS = Constants::NS_DS;

    private const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /** Shown to the end user; deliberately identical for every cryptographic failure. */
    private const USER_MESSAGE = 'We could not verify the sign-in response from your identity provider.';

    private SamlConnectionConfig $config;
    private ClockInterface $clock;
    private StateStore $stateStore;
    private ReplayGuardInterface $replayGuard;

    /** Last rejection detail, for the diagnostics record. Never shown to the user. */
    private string $detail = '';

    public function __construct(
        SamlConnectionConfig $config,
        ClockInterface $clock,
        StateStore $stateStore,
        ReplayGuardInterface $replayGuard
    ) {
        $this->config = $config;
        $this->clock = $clock;
        $this->stateStore = $stateStore;
        $this->replayGuard = $replayGuard;
    }

    public function protocol(): string
    {
        return 'saml2';
    }

    /**
     * Administrator-facing detail of the last rejection (masked diagnostics record, never the
     * login screen). Empty when nothing was rejected yet.
     */
    public function detail(): string
    {
        return $this->detail;
    }

    /**
     * @param array<string, mixed> $request
     */
    public function read(array $request): IdentityPayload
    {
        $this->detail = '';

        $xml = $this->decodeResponse($request);

        // --- B10 / B1: cheapest and most important defences, before anything parses meaning.
        $document = $this->loadDocument($xml);
        $this->rejectDoctype($document);

        $assertionCount = $this->countAssertions($document);
        if ($assertionCount > 1) {
            $this->fail(
                IdentityReaderException::MULTIPLE_ASSERTIONS,
                sprintf('Response carries %d assertion elements; exactly one is allowed.', $assertionCount)
            );
        }

        $root = $document->documentElement;
        if (!$root instanceof DOMElement
            || $root->localName !== 'Response'
            || $root->namespaceURI !== self::NS_SAMLP
        ) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Document root is not a samlp:Response element.'
            );
        }

        // --- B4: a failed login must never be mistaken for an identity.
        $this->requireSuccessStatus($document);

        if ($assertionCount === 0) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Response reports Success but carries no assertion.'
            );
        }

        // --- B11: decrypt first, then run every check on the decrypted content.
        if ($this->hasEncryptedAssertion($document)) {
            $document = $this->decrypt($document);
            $this->rejectDoctype($document);

            if ($this->countAssertions($document) !== 1) {
                $this->fail(
                    IdentityReaderException::MULTIPLE_ASSERTIONS,
                    'Decrypted content does not contain exactly one assertion.'
                );
            }
        }

        $assertion = $this->singleAssertion($document);

        // --- A1 / B2 / B3: the signature must cover exactly the node we are about to read.
        $this->verifySignature($document, $assertion);

        // --- B8 / B7: envelope-level bindings.
        $this->checkDestination($document);
        $requestId = $this->consumeLoginState($request);
        $inResponseTo = $this->checkInResponseTo($document, $requestId);

        // --- A6 / B5 / B6 / B9: content of the node the signature covers.
        $this->checkIssuer($document, $assertion);
        $notOnOrAfter = $this->checkConditions($assertion);
        $this->checkSubjectConfirmation($assertion, $inResponseTo);
        $nameId = $this->readNameId($assertion);

        // --- A5: single use of the IdP's own identifier, on top of the login state above.
        $this->rememberAssertionId($assertion, $notOnOrAfter);

        return new IdentityPayload(
            $nameId,
            $this->readAttributes($assertion),
            $this->config->idpEntityId,
            $this->readSessionIndex($assertion)
        );
    }

    // -----------------------------------------------------------------------------------
    // Transport and parsing
    // -----------------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $request
     */
    private function decodeResponse(array $request): string
    {
        $encoded = $request['SAMLResponse'] ?? null;

        if (!is_string($encoded) || trim($encoded) === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Request carries no SAMLResponse field.'
            );
        }

        /** @var string $encoded */
        $xml = base64_decode(trim($encoded), true);

        if ($xml === false || trim($xml) === '') {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'SAMLResponse is not valid base64.'
            );
        }

        /** @var string $xml */
        return $xml;
    }

    /**
     * Entity loading stays off (LIBXML_NONET, no LIBXML_NOENT) AND a DOCTYPE is rejected
     * outright by rejectDoctype(). The contract asks for both because either one alone has been
     * bypassed before: parameter entities do not need the network, and "the parser is safe by
     * default" is a property of a PHP version, not of this code.
     */
    private function loadDocument(string $xml): DOMDocument
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
                'SAMLResponse is not well-formed XML.'
            );
        }

        return $document;
    }

    private function rejectDoctype(DOMDocument $document): void
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

    private function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_SAMLP);
        $xpath->registerNamespace('saml', self::NS_SAML);
        $xpath->registerNamespace('ds', self::NS_DS);

        return $xpath;
    }

    /**
     * Counts by local name across the WHOLE document and in ANY namespace. Namespace-scoped
     * counting is how wrapping payloads hide a second assertion: the parser that reads
     * attributes rarely cares which prefix declared it.
     */
    private function countAssertions(DOMDocument $document): int
    {
        $nodes = $this->xpath($document)->query(
            "//*[local-name()='Assertion' or local-name()='EncryptedAssertion']"
        );

        return $nodes instanceof DOMNodeList ? $nodes->length : 0;
    }

    private function hasEncryptedAssertion(DOMDocument $document): bool
    {
        $nodes = $this->xpath($document)->query("//*[local-name()='EncryptedAssertion']");

        return $nodes instanceof DOMNodeList && $nodes->length > 0;
    }

    private function singleAssertion(DOMDocument $document): DOMElement
    {
        $nodes = $this->xpath($document)->query('/samlp:Response/saml:Assertion');

        if (!$nodes instanceof DOMNodeList || $nodes->length !== 1) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Response does not carry exactly one saml:Assertion child.'
            );
        }

        $assertion = $nodes->item(0);
        if (!$assertion instanceof DOMElement) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Assertion node is not an element.'
            );
        }

        return $assertion;
    }

    // -----------------------------------------------------------------------------------
    // B4 status
    // -----------------------------------------------------------------------------------

    private function requireSuccessStatus(DOMDocument $document): void
    {
        $nodes = $this->xpath($document)->query('/samlp:Response/samlp:Status/samlp:StatusCode');

        if (!$nodes instanceof DOMNodeList || $nodes->length === 0) {
            $this->fail(
                IdentityReaderException::STATUS_NOT_SUCCESS,
                'Response carries no samlp:StatusCode.'
            );
        }

        $code = $nodes->item(0);
        $value = $code instanceof DOMElement ? trim($code->getAttribute('Value')) : '';

        if ($value !== Constants::STATUS_SUCCESS) {
            $this->fail(
                IdentityReaderException::STATUS_NOT_SUCCESS,
                sprintf('Status is "%s", not Success.', $value)
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // B11 decryption
    // -----------------------------------------------------------------------------------

    private function decrypt(DOMDocument $document): DOMDocument
    {
        if (!$this->config->canDecrypt()) {
            $this->fail(
                IdentityReaderException::DECRYPTION_FAILED,
                'Response carries an EncryptedAssertion but no SP private key is configured.'
            );
        }

        $pem = Utils::formatPrivateKey((string)$this->config->spPrivateKey, true);

        try {
            $encryptedData = $this->xpath($document)
                ->query("//*[local-name()='EncryptedAssertion']/*[local-name()='EncryptedData']")
                ?->item(0);

            if (!$encryptedData instanceof DOMElement) {
                throw new \RuntimeException('No EncryptedData inside EncryptedAssertion.');
            }

            $enc = new XMLSecEnc();
            $enc->setNode($encryptedData);
            $enc->type = $encryptedData->getAttribute('Type');

            $key = $enc->locateKey();
            if (!$key instanceof XMLSecurityKey) {
                throw new \RuntimeException('Unsupported encryption algorithm.');
            }

            $symmetric = null;
            $keyInfo = $enc->locateKeyInfo($key);
            if ($keyInfo instanceof XMLSecurityKey) {
                if ($keyInfo->isEncrypted) {
                    $encryptedCtx = $keyInfo->encryptedCtx;
                    $keyInfo->loadKey($pem, false, false);
                    $symmetric = $encryptedCtx->decryptKey($keyInfo);
                } else {
                    $keyInfo->loadKey($pem, false, false);
                }
            }

            if (empty($key->key)) {
                $key->loadKey($symmetric);
            }

            $decryptedXml = $enc->decryptNode($key, false);
            if (!is_string($decryptedXml) || trim($decryptedXml) === '') {
                throw new \RuntimeException('Decryption produced no document.');
            }

            $assertionDocument = $this->loadDocument($decryptedXml);
            $this->rejectDoctype($assertionDocument);

            $decrypted = $assertionDocument->documentElement;
            if (!$decrypted instanceof DOMElement
                || $decrypted->localName !== 'Assertion'
                || $decrypted->namespaceURI !== self::NS_SAML
            ) {
                throw new \RuntimeException('Decrypted content is not a saml:Assertion.');
            }

            $encryptedAssertion = $encryptedData->parentNode;
            if (!$encryptedAssertion instanceof DOMElement
                || !$encryptedAssertion->parentNode instanceof DOMElement
            ) {
                throw new \RuntimeException('EncryptedAssertion is not where it should be.');
            }

            $imported = $document->importNode($decrypted, true);
            $encryptedAssertion->parentNode->replaceChild($imported, $encryptedAssertion);

            // Reload from the serialised form so namespace fixups cannot leave the tree in a
            // state where the signature would be canonicalised differently than it is read.
            return $this->loadDocument((string)$document->saveXML());
        } catch (IdentityReaderException $already) {
            throw $already;
        } catch (Throwable $error) {
            $this->fail(
                IdentityReaderException::DECRYPTION_FAILED,
                'Assertion could not be decrypted: ' . $error->getMessage()
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // A1 / B2 / B3 signature
    // -----------------------------------------------------------------------------------

    private function verifySignature(DOMDocument $document, DOMElement $assertion): void
    {
        $assertionId = trim($assertion->getAttribute('ID'));

        if ($assertionId === '') {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                'Assertion has no ID, so no signature can be bound to it.'
            );
        }

        $xpath = $this->xpath($document);

        // An ID that occurs twice lets a Reference resolve to the attacker's copy. Both
        // spellings are counted: xmlseclibs resolves a reference with
        // //*[@Id="x" or @ID="x"] and takes the first hit in document order, so a decoy
        // spelled @Id must not depend on B1 having fired first.
        $literal = self::xpathLiteral($assertionId);
        $sameId = $xpath->query(sprintf('//*[@ID=%s or @Id=%s]', $literal, $literal));
        if ($sameId instanceof DOMNodeList && $sameId->length !== 1) {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                'Assertion ID is not unique within the document.'
            );
        }

        // B3: the signature must be ON the assertion. A signed envelope around an unsigned
        // assertion is the textbook wrapping setup and is rejected here, not tolerated.
        $signatures = $xpath->query('./ds:Signature', $assertion);
        if (!$signatures instanceof DOMNodeList || $signatures->length !== 1) {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                'Assertion does not carry exactly one direct ds:Signature child.'
            );
        }

        $signature = $signatures->item(0);
        if (!$signature instanceof DOMElement) {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                'Signature node is not an element.'
            );
        }

        // B2: the Reference must resolve to THIS assertion, and to nothing else.
        $references = $xpath->query('./ds:SignedInfo/ds:Reference', $signature);
        if (!$references instanceof DOMNodeList || $references->length !== 1) {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                'Signature must contain exactly one Reference.'
            );
        }

        $reference = $references->item(0);
        $uri = $reference instanceof DOMElement ? trim($reference->getAttribute('URI')) : '';

        if ($uri !== '#' . $assertionId) {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                sprintf('Signature reference "%s" does not cover the parsed assertion.', $uri)
            );
        }

        $transforms = $xpath->query('./ds:Transforms/ds:Transform/@Algorithm', $reference);
        $enveloped = false;
        if ($transforms instanceof DOMNodeList) {
            foreach ($transforms as $transform) {
                if (trim((string)$transform->nodeValue) === self::TRANSFORM_ENVELOPED) {
                    $enveloped = true;
                }
            }
        }

        if (!$enveloped) {
            $this->fail(
                IdentityReaderException::SIGNATURE_COVERAGE,
                'Signature does not use the enveloped-signature transform.'
            );
        }

        // Only now the cryptography, delegated (A2/A3): our configured certificate, never a
        // key or fingerprint taken from the message.
        try {
            $valid = Utils::validateSign(
                $document,
                $this->config->idpX509Cert,
                null,
                null,
                Utils::ASSERTION_SIGNATURE_XPATH
            );
        } catch (Throwable $error) {
            $this->fail(
                IdentityReaderException::SIGNATURE_INVALID,
                'Signature could not be verified: ' . $error->getMessage()
            );
        }

        if ($valid !== true) {
            $this->fail(
                IdentityReaderException::SIGNATURE_INVALID,
                'Signature does not verify against the configured IdP certificate.'
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // B7 / B8 envelope bindings
    // -----------------------------------------------------------------------------------

    private function checkDestination(DOMDocument $document): void
    {
        $root = $document->documentElement;
        if (!$root instanceof DOMElement || !$root->hasAttribute('Destination')) {
            return; // B8 applies "when present".
        }

        $destination = trim($root->getAttribute('Destination'));

        if ($destination !== $this->config->acsUrl) {
            $this->fail(
                IdentityReaderException::DESTINATION_MISMATCH,
                sprintf('Destination "%s" is not this endpoint.', $destination)
            );
        }
    }

    /**
     * @param array<string, mixed> $request
     * @return string The AuthnRequest id this site issued for this login.
     */
    private function consumeLoginState(array $request): string
    {
        $relayState = $request['RelayState'] ?? null;

        if (!is_string($relayState) || trim($relayState) === '') {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Response carries no RelayState, so no login of ours can be matched to it.'
            );
        }

        /** @var string $relayState */
        $validation = $this->stateStore->consume($relayState);

        if (!$validation->valid) {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Login state rejected: ' . $validation->reasonCode . '.'
            );
        }

        $requestId = $validation->context()['request_id'] ?? '';

        if ($requestId === '') {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Login state carries no request id to match InResponseTo against.'
            );
        }

        return $requestId;
    }

    private function checkInResponseTo(DOMDocument $document, string $requestId): string
    {
        $root = $document->documentElement;
        $inResponseTo = $root instanceof DOMElement ? trim($root->getAttribute('InResponseTo')) : '';

        // IdP-initiated flow is out of MVP scope, so a response with no InResponseTo is
        // unsolicited by definition.
        if ($inResponseTo === '' || !hash_equals($requestId, $inResponseTo)) {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'InResponseTo does not match the request id this site issued.'
            );
        }

        return $inResponseTo;
    }

    // -----------------------------------------------------------------------------------
    // A6 / B5 / B6 / B9 assertion content
    // -----------------------------------------------------------------------------------

    private function checkIssuer(DOMDocument $document, DOMElement $assertion): void
    {
        $xpath = $this->xpath($document);

        $assertionIssuer = $this->firstText($xpath->query('./saml:Issuer', $assertion));
        if ($assertionIssuer === null || trim($assertionIssuer) !== $this->config->idpEntityId) {
            $this->fail(
                IdentityReaderException::ISSUER_MISMATCH,
                sprintf('Assertion issuer "%s" is not the configured IdP.', (string)$assertionIssuer)
            );
        }

        $responseIssuer = $this->firstText($xpath->query('/samlp:Response/saml:Issuer'));
        if ($responseIssuer !== null && trim($responseIssuer) !== $this->config->idpEntityId) {
            $this->fail(
                IdentityReaderException::ISSUER_MISMATCH,
                sprintf('Response issuer "%s" is not the configured IdP.', $responseIssuer)
            );
        }
    }

    /**
     * @return int The assertion NotOnOrAfter, used as the replay retention horizon.
     */
    private function checkConditions(DOMElement $assertion): int
    {
        $xpath = $this->xpath($assertion->ownerDocument);
        $conditions = $xpath->query('./saml:Conditions', $assertion);

        if (!$conditions instanceof DOMNodeList || $conditions->length !== 1) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Assertion must carry exactly one Conditions element.'
            );
        }

        $node = $conditions->item(0);
        if (!$node instanceof DOMElement) {
            $this->fail(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Conditions node is not an element.'
            );
        }

        $notBefore = $this->samlTime($node->getAttribute('NotBefore'));
        $notOnOrAfter = $this->samlTime($node->getAttribute('NotOnOrAfter'));

        if ($notBefore === null || $notOnOrAfter === null) {
            // An assertion without both bounds has an unbounded lifetime in one direction,
            // which is a time failure, not a formatting quirk.
            $this->fail(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Conditions must carry both NotBefore and NotOnOrAfter.'
            );
        }

        $this->requireWithinWindow($notBefore, $notOnOrAfter, 'Conditions');

        // B5: the audience is mandatory here, unlike in the library.
        $audiences = [];
        $nodes = $xpath->query('./saml:AudienceRestriction/saml:Audience', $node);
        if ($nodes instanceof DOMNodeList) {
            foreach ($nodes as $audience) {
                $audiences[] = trim((string)$audience->textContent);
            }
        }

        if ($audiences === [] || !in_array($this->config->spEntityId, $audiences, true)) {
            $this->fail(
                IdentityReaderException::AUDIENCE_MISMATCH,
                sprintf(
                    'AudienceRestriction %s does not name this service provider.',
                    $audiences === [] ? '(absent)' : '"' . implode(', ', $audiences) . '"'
                )
            );
        }

        return (int)$notOnOrAfter;
    }

    private function checkSubjectConfirmation(DOMElement $assertion, string $inResponseTo): void
    {
        $xpath = $this->xpath($assertion->ownerDocument);
        $confirmations = $xpath->query('./saml:Subject/saml:SubjectConfirmation', $assertion);

        $bearer = null;
        if ($confirmations instanceof DOMNodeList) {
            foreach ($confirmations as $confirmation) {
                if ($confirmation instanceof DOMElement
                    && trim($confirmation->getAttribute('Method')) === Constants::CM_BEARER
                ) {
                    $bearer = $confirmation;
                    break;
                }
            }
        }

        if ($bearer === null) {
            $this->fail(
                IdentityReaderException::CONFIRMATION_INVALID,
                'Assertion carries no bearer SubjectConfirmation.'
            );
        }

        $dataNodes = $xpath->query('./saml:SubjectConfirmationData', $bearer);
        if (!$dataNodes instanceof DOMNodeList || $dataNodes->length !== 1) {
            $this->fail(
                IdentityReaderException::CONFIRMATION_INVALID,
                'Bearer confirmation must carry exactly one SubjectConfirmationData.'
            );
        }

        $data = $dataNodes->item(0);
        if (!$data instanceof DOMElement) {
            $this->fail(
                IdentityReaderException::CONFIRMATION_INVALID,
                'SubjectConfirmationData node is not an element.'
            );
        }

        $recipient = trim($data->getAttribute('Recipient'));
        if ($recipient !== $this->config->acsUrl) {
            $this->fail(
                IdentityReaderException::CONFIRMATION_INVALID,
                sprintf('Confirmation Recipient "%s" is not this endpoint.', $recipient)
            );
        }

        if ($data->hasAttribute('InResponseTo')
            && !hash_equals($inResponseTo, trim($data->getAttribute('InResponseTo')))
        ) {
            $this->fail(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Confirmation InResponseTo disagrees with the Response InResponseTo.'
            );
        }

        $notOnOrAfter = $this->samlTime($data->getAttribute('NotOnOrAfter'));
        if ($notOnOrAfter === null) {
            $this->fail(
                IdentityReaderException::CONFIRMATION_INVALID,
                'SubjectConfirmationData carries no NotOnOrAfter of its own.'
            );
        }

        $this->requireWithinWindow(
            $this->samlTime($data->getAttribute('NotBefore')),
            $notOnOrAfter,
            'SubjectConfirmationData'
        );
    }

    private function readNameId(DOMElement $assertion): string
    {
        $xpath = $this->xpath($assertion->ownerDocument);
        $nodes = $xpath->query('./saml:Subject/saml:NameID', $assertion);

        if (!$nodes instanceof DOMNodeList || $nodes->length !== 1) {
            $this->fail(
                IdentityReaderException::SUBJECT_MISSING,
                'Assertion must carry exactly one NameID.'
            );
        }

        $nameId = trim((string)$nodes->item(0)?->textContent);

        if ($nameId === '') {
            $this->fail(
                IdentityReaderException::SUBJECT_MISSING,
                'NameID is empty or whitespace only.'
            );
        }

        return $nameId;
    }

    private function rememberAssertionId(DOMElement $assertion, int $notOnOrAfter): void
    {
        $id = trim($assertion->getAttribute('ID'));

        if (!$this->replayGuard->remember($id, $notOnOrAfter + $this->config->clockSkew)) {
            $this->fail(
                IdentityReaderException::REPLAYED_ASSERTION,
                'Assertion id has already been accepted once.'
            );
        }
    }

    /**
     * A7: names and values are handed over byte for byte. Case folding and trimming here would
     * make the diagnostics panel lie about what the IdP actually sent.
     *
     * @return array<string, list<string>>
     */
    private function readAttributes(DOMElement $assertion): array
    {
        $xpath = $this->xpath($assertion->ownerDocument);
        $attributes = $xpath->query('./saml:AttributeStatement/saml:Attribute', $assertion);

        $out = [];
        if (!$attributes instanceof DOMNodeList) {
            return $out;
        }

        foreach ($attributes as $attribute) {
            if (!$attribute instanceof DOMElement) {
                continue;
            }

            $name = $attribute->getAttribute('Name');
            if (trim($name) === '') {
                continue;
            }

            $values = [];
            $valueNodes = $xpath->query('./saml:AttributeValue', $attribute);
            if ($valueNodes instanceof DOMNodeList) {
                foreach ($valueNodes as $value) {
                    $values[] = (string)$value->textContent;
                }
            }

            // Repeated Name: append rather than overwrite, so a duplicate cannot hide a value.
            $out[$name] = array_merge($out[$name] ?? [], $values);
        }

        return $out;
    }

    private function readSessionIndex(DOMElement $assertion): ?string
    {
        $nodes = $this->xpath($assertion->ownerDocument)
            ->query('./saml:AuthnStatement/@SessionIndex', $assertion);

        if (!$nodes instanceof DOMNodeList || $nodes->length === 0) {
            return null;
        }

        $value = trim((string)$nodes->item(0)?->nodeValue);

        return $value === '' ? null : $value;
    }

    // -----------------------------------------------------------------------------------
    // A4 time
    // -----------------------------------------------------------------------------------

    private function requireWithinWindow(?int $notBefore, int $notOnOrAfter, string $label): void
    {
        $now = $this->clock->now();
        $skew = $this->config->clockSkew;

        if ($notBefore !== null && $now + $skew < $notBefore) {
            $this->fail(
                IdentityReaderException::ASSERTION_EXPIRED,
                $label . ' is not valid yet.'
            );
        }

        if ($now - $skew >= $notOnOrAfter) {
            $this->fail(
                IdentityReaderException::ASSERTION_EXPIRED,
                $label . ' has expired.'
            );
        }
    }

    /**
     * Delegated to the library (A2): SAML instants have their own grammar and a home-grown
     * strtotime() here would accept things the standard does not.
     */
    private function samlTime(string $value): ?int
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

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    private function firstText(DOMNodeList|false $nodes): ?string
    {
        if (!$nodes instanceof DOMNodeList || $nodes->length === 0) {
            return null;
        }

        return (string)$nodes->item(0)?->textContent;
    }

    /**
     * Values from the document never get concatenated into an XPath expression unquoted.
     */
    private static function xpathLiteral(string $value): string
    {
        if (!str_contains($value, "'")) {
            return "'" . $value . "'";
        }

        $parts = array_map(
            static fn (string $part): string => "'" . $part . "'",
            explode("'", $value)
        );

        return 'concat(' . implode(', \'\'\'\', ', $parts) . ')';
    }

    private function fail(string $reasonCode, string $detail): never
    {
        $this->detail = $detail;

        // A8 / BL-2: the user gets one neutral sentence, the administrator gets $detail in the
        // masked diagnostics record. The raw response, the certificate and the exact clock
        // offset never appear in the message.
        throw new IdentityReaderException($reasonCode, self::USER_MESSAGE);
    }
}
