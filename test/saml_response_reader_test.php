<?php

declare(strict_types=1);

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Protocol\Saml\IdpCertificate;
use Keyway\Sso\Protocol\Saml\SamlConnectionConfig;
use Keyway\Sso\Protocol\Saml\SamlResponseReader;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\InMemoryReplayGuard;
use Keyway\Sso\Test\Support\InMemoryStateStorage;
use Keyway\Sso\Test\Support\SequenceRandomSource;
use Keyway\Sso\Test\Support\SamlFixtures;

/**
 * The malicious half of the SAML contract (IdentityReaderInterface, sections A and B).
 *
 * Every case here is a real, base64-encoded SAML response signed with a real RSA key generated
 * in-process, not a string that merely looks like one: a fixture that is not actually signed
 * cannot tell a working signature check from a missing one.
 *
 * One defect per fixture, and every rejection is asserted on its reason code rather than on the
 * bare fact that something was thrown - "it threw" is satisfied by a reader that rejects
 * everything, including the happy path.
 */
if (!class_exists(\OneLogin\Saml2\Utils::class)) {
    fwrite(STDOUT, "saml_response_reader       skipped: vendor absent (run composer install)\n");

    return [];
}

$now = time();

/**
 * @param array<string, mixed> $options
 * @return array{0: SamlResponseReader, 1: string, 2: InMemoryReplayGuard}
 */
$makeReader = static function (array $options = []) use ($now): array {
    $clock = new FixedClock((int)($options['now'] ?? $now));
    $storage = new InMemoryStateStorage();
    $stateStore = new StateStore(
        $storage,
        $clock,
        new SequenceRandomSource(),
        new RedirectGuard(),
        300
    );

    $state = $stateStore->issue('/admin', ['request_id' => (string)($options['requestId'] ?? 'KW_request_id')]);

    $config = new SamlConnectionConfig(
        (string)($options['idpEntityId'] ?? SamlFixtures::IDP_ENTITY_ID),
        (string)($options['cert'] ?? SamlFixtures::cert()),
        (string)($options['spEntityId'] ?? SamlFixtures::SP_ENTITY_ID),
        (string)($options['acsUrl'] ?? SamlFixtures::ACS_URL),
        SamlFixtures::IDP_SSO_URL,
        isset($options['spPrivateKey']) ? (string)$options['spPrivateKey'] : null,
        (int)($options['skew'] ?? 60)
    );

    // The SAME clock as the reader: the guard honours $expiresAt, and a wall-clock guard would
    // sweep the registry against a different clock than the one that set the horizon.
    $guard = new InMemoryReplayGuard($clock);

    return [new SamlResponseReader($config, $clock, $stateStore, $guard), $state->value, $guard];
};

/**
 * @param array<string, mixed> $fixture
 * @param array<string, mixed> $options
 */
$rejects = static function (
    string $expectedReason,
    array $fixture,
    array $options = []
) use ($makeReader, $now): void {
    [$reader, $relayState] = $makeReader($options);

    $error = Assert::throws(
        IdentityReaderException::class,
        static fn () => $reader->read([
            'SAMLResponse' => SamlFixtures::response(array_merge(['now' => $now], $fixture)),
            'RelayState' => $relayState,
        ]),
        'expected rejection with reason ' . $expectedReason
    );

    /** @var IdentityReaderException $error */
    Assert::same($expectedReason, $error->reasonCode(), 'reason code');
};

return [
    // ------------------------------------------------- the settings screen and this reader
    //
    // THE GAP THIS CASE CLOSES (measured 2026-09-22): every fixture in this file feeds the
    // reader a PEM block, because that is what SamlFixtures::cert() returns - so nothing here
    // ever exercised the OTHER shape the settings screen accepts, and nothing noticed that the
    // two runtime paths disagreed about it. Single logout reads the certificate through
    // Utils::formatCert(), which adds the armour itself; sign-in hands the raw value to
    // Utils::validateSign() -> XMLSecurityKey::loadKey(), which calls openssl_x509_read(), and
    // that does not read base64 without armour. Result, before SamlConnectionConfig normalised
    // it: bare base64 SAVED CLEANLY and failed every login with a signature error.
    //
    // The assertion is the contract itself, in one place: WHAT THE SAVE-TIME GATE ACCEPTS, THIS
    // READER CAN VERIFY A SIGNATURE WITH. A gate that blesses a value the reader chokes on is
    // worse than no gate - it moves the failure three screens away from the field that caused
    // it and puts a green tick over it.
    'every certificate shape the settings screen accepts really verifies a signature' =>
        static function () use ($makeReader, $now): void {
            $pem = SamlFixtures::cert();
            $bare = preg_replace(
                '/\s+/',
                '',
                str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $pem)
            ) ?? '';

            Assert::notContains('-', $bare, 'the bare shape really has no armour left');

            foreach (
                [
                    'PEM block' => $pem,
                    'bare base64 body' => $bare,
                    'bare body as a panel wraps it' => chunk_split($bare, 64, "\n"),
                ] as $shape => $certificate
            ) {
                // 1. The settings screen would let an administrator save this.
                Assert::doesNotThrow(
                    static fn () => IdpCertificate::assertUsable($certificate),
                    $shape . ': the save-time gate accepts it'
                );

                // 2. And a real, really-signed response verifies against it.
                [$reader, $relayState] = $makeReader(['cert' => $certificate]);

                $payload = $reader->read([
                    'SAMLResponse' => SamlFixtures::response(['now' => $now]),
                    'RelayState' => $relayState,
                ]);

                Assert::same('alice@example.test', $payload->nameId(), $shape . ': the login works');
            }
        },

    // The other direction, so the case above cannot pass by accident on a reader that verifies
    // nothing: a DIFFERENT certificate, equally well formed, must not verify this signature.
    'a certificate the gate accepts still has to be the right one' =>
        static function () use ($makeReader, $now): void {
            Assert::doesNotThrow(static fn () => IdpCertificate::assertUsable(SamlFixtures::foreignCert()));

            [$reader, $relayState] = $makeReader(['cert' => SamlFixtures::foreignCert()]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => SamlFixtures::response(['now' => $now]),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::SIGNATURE_INVALID, $error->reasonCode());
        },

    // ---------------------------------------------------------------- happy path (A7, B*)
    'a correct response yields the identity, attributes byte for byte' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader();

            $payload = $reader->read([
                'SAMLResponse' => SamlFixtures::response(['now' => $now]),
                'RelayState' => $relayState,
            ]);

            Assert::true($payload instanceof IdentityPayload);
            Assert::same('alice@example.test', $payload->nameId());
            Assert::same(SamlFixtures::IDP_ENTITY_ID, $payload->issuer());
            Assert::same('_session_1', $payload->sessionIndex());

            // A7: the padded name and the mixed-case value arrive untouched.
            Assert::sameList(['  Email  ', 'Groups'], $payload->names());
            Assert::sameList(['Alice@Example.TEST'], $payload->values('  Email  '));
            Assert::sameList(['Staff', 'Admins'], $payload->values('Groups'));
            Assert::same('saml2', $reader->protocol());
        },

    // ---------------------------------------------------------------- B1 / A1
    'B1: a response carrying two assertions is rejected outright' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::MULTIPLE_ASSERTIONS, ['secondAssertion' => true]);
        },

    'A1/B1: a forged COPY of the signed assertion is rejected (CVE-2017-11427 shape)' =>
        static function () use ($rejects): void {
            // The injected assertion is the genuinely signed one with the subject swapped to
            // admin@example.test. A reader that verifies "a signature, somewhere" and then reads
            // "an assertion, somewhere" grants an administrator session here.
            $rejects(IdentityReaderException::MULTIPLE_ASSERTIONS, ['secondAssertion' => true]);
        },

    'A1/B1: wrapping with the signed original parked in samlp:Extensions is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::MULTIPLE_ASSERTIONS, ['wrappingInExtensions' => true]);
        },

    // ---------------------------------------------------------------- B2 / A1
    'B2: the reference pin fires before any cryptography when the URI names another node' =>
        static function () use ($rejects): void {
            // The ID is renamed after signing, so the signature would not verify either; the
            // point of this case is the ORDER - the URI pin rejects before validateSign runs,
            // so a crypto library that resolves references loosely never gets the chance.
            $rejects(IdentityReaderException::SIGNATURE_COVERAGE, ['breakReference' => true]);
        },

    'B2: a decoy element carrying the assertion ID is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SIGNATURE_COVERAGE, ['duplicateId' => true]);
        },

    'B2: a signature that is not a direct child of the assertion does not cover it' =>
        static function () use ($rejects): void {
            // The Reference still names this assertion, so the URI pin passes; only the nesting
            // rule stands between this document and a signature detached from what it signs.
            $rejects(IdentityReaderException::SIGNATURE_COVERAGE, ['nestSignature' => true]);
        },

    'B2: a reference without the enveloped-signature transform is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SIGNATURE_COVERAGE, ['stripEnvelopedTransform' => true]);
        },

    // ---------------------------------------------------------------- B3
    'B3: an unsigned assertion inside a signed envelope is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SIGNATURE_COVERAGE, [
                'signAssertion' => false,
                'signEnvelope' => true,
            ]);
        },

    'A1/A3: an assertion signed with a foreign key is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SIGNATURE_INVALID, ['signWith' => 'foreign']);
        },

    'A1: tampering with the signed assertion breaks the signature' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader();

            $xml = base64_decode(SamlFixtures::response(['now' => $now]), true);
            $tampered = str_replace('alice@example.test', 'admin@example.test', (string)$xml);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => base64_encode($tampered),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::SIGNATURE_INVALID, $error->reasonCode());
        },

    'B9/A7: a comment inside NameID does not truncate the subject' =>
        static function () use ($makeReader, $now): void {
            // XML comment truncation (CVE-2017-11428 family: GitLab, Duo, OneLogin, 2018).
            // Comments are excluded from canonicalisation for a `#id` reference, so this
            // document is CORRECTLY SIGNED and is accepted - as it should be. What must not
            // happen is reading only the first text node: `alice` would silently match a
            // different account than `alice@example.test`.
            [$reader, $relayState] = $makeReader();

            $payload = $reader->read([
                'SAMLResponse' => SamlFixtures::response(['now' => $now, 'commentInNameId' => true]),
                'RelayState' => $relayState,
            ]);

            Assert::same('alice@example.test', $payload->nameId(), 'subject must stay whole');
        },

    // ---------------------------------------------------------------- B4
    'B4: a non-Success status never reaches the core' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::STATUS_NOT_SUCCESS, [
                'status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
            ]);
        },

    // ---------------------------------------------------------------- B5 / A4
    'B5/A4: an expired NotOnOrAfter is rejected' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'notBefore' => $now - 900,
                'notOnOrAfter' => $now - 300,
                'scdNotOnOrAfter' => $now + 300,
            ]);
        },

    'B5/A4: a NotBefore in the future is rejected' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'notBefore' => $now + 600,
                'notOnOrAfter' => $now + 900,
            ]);
        },

    'A4: skew is symmetric and bounded, it does not swallow a ten minute drift' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'notBefore' => $now - 1200,
                'notOnOrAfter' => $now - 121,
            ], ['skew' => 120]);

            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SamlConnectionConfig(
                    SamlFixtures::IDP_ENTITY_ID,
                    SamlFixtures::cert(),
                    SamlFixtures::SP_ENTITY_ID,
                    SamlFixtures::ACS_URL,
                    SamlFixtures::IDP_SSO_URL,
                    null,
                    121
                ),
                'skew above the contract ceiling must not be configurable'
            );
        },

    'B5: Conditions without NotOnOrAfter is rejected (unbounded lifetime)' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, ['notOnOrAfter' => false]);
        },

    'B5: Conditions without NotBefore is rejected (both bounds are mandatory)' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, ['notBefore' => false]);
        },

    'B5: a wrong audience is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::AUDIENCE_MISMATCH, [
                'audience' => 'https://someone-else.example.test/metadata',
            ]);
        },

    'B5: a missing AudienceRestriction is rejected, unlike in the library default' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::AUDIENCE_MISMATCH, ['audience' => false]);
        },

    // ---------------------------------------------------------------- B6
    'B6: a SubjectConfirmationData without its own NotOnOrAfter is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::CONFIRMATION_INVALID, ['scdNotOnOrAfter' => false]);
        },

    'B6: a wrong Recipient is rejected, and a prefix is not a match' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::CONFIRMATION_INVALID, [
                'recipient' => SamlFixtures::ACS_URL . '.evil.test/acs',
            ]);
        },

    'B6: a non-bearer confirmation method is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::CONFIRMATION_INVALID, [
                'method' => 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key',
            ]);
        },

    'B6: an expired confirmation window is rejected separately from Conditions' =>
        static function () use ($rejects, $now): void {
            $rejects(IdentityReaderException::ASSERTION_EXPIRED, [
                'scdNotOnOrAfter' => $now - 300,
            ]);
        },

    // ---------------------------------------------------------------- B7
    'B7: an InResponseTo we never issued is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::UNSOLICITED_RESPONSE, [
                'inResponseTo' => 'KW_some_other_request',
            ]);
        },

    'B7: a response with no InResponseTo is unsolicited in MVP scope' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::UNSOLICITED_RESPONSE, ['inResponseTo' => false]);
        },

    'B7: the login state is single use, so the same response cannot be replayed' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader();

            $response = SamlFixtures::response(['now' => $now]);
            $reader->read(['SAMLResponse' => $response, 'RelayState' => $relayState]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => $response,
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::UNSOLICITED_RESPONSE, $error->reasonCode());
        },

    // ---------------------------------------------------------------- A5
    'A5: a repeated Assertion ID is rejected even with a fresh login state' =>
        static function () use ($now): void {
            $clock = new FixedClock($now);
            $storage = new InMemoryStateStorage();
            $stateStore = new StateStore(
                $storage,
                $clock,
                new SequenceRandomSource(),
                new RedirectGuard(),
                300
            );
            $config = new SamlConnectionConfig(
                SamlFixtures::IDP_ENTITY_ID,
                SamlFixtures::cert(),
                SamlFixtures::SP_ENTITY_ID,
                SamlFixtures::ACS_URL,
                SamlFixtures::IDP_SSO_URL
            );
            $guard = new InMemoryReplayGuard($clock);
            $reader = new SamlResponseReader($config, $clock, $stateStore, $guard);

            // One captured response, replayed against a brand new login state. The state store
            // cannot see anything wrong with it - the token is fresh and unused - so the only
            // thing standing between the attacker and a second session is A5.
            $response = SamlFixtures::response(['now' => $now, 'inResponseTo' => 'KW_one']);

            $first = $stateStore->issue('/admin', ['request_id' => 'KW_one']);
            $reader->read(['SAMLResponse' => $response, 'RelayState' => $first->value]);

            $second = $stateStore->issue('/admin', ['request_id' => 'KW_one']);
            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => $response,
                    'RelayState' => $second->value,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::REPLAYED_ASSERTION, $error->reasonCode());
            Assert::same(1, $guard->count());
        },

    // ---------------------------------------------------------------- B8
    'B8: a Destination pointing somewhere else is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::DESTINATION_MISMATCH, [
                'destination' => 'https://craft.example.test/sso/acs-of-another-site',
            ]);
        },

    // ---------------------------------------------------------------- B9
    'B9: a whitespace-only NameID is rejected rather than mapped to nobody' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::SUBJECT_MISSING, ['nameId' => '   ']);
        },

    // ---------------------------------------------------------------- B10
    'B10: a document with a DOCTYPE and an external entity is rejected' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::DOCTYPE_REJECTED, ['doctype' => true]);
        },

    // ---------------------------------------------------------------- A6
    'A6: a foreign issuer INSIDE the signed assertion is rejected, exact match only' =>
        static function () use ($rejects): void {
            // Envelope issuer left correct on purpose: this is the issuer that sits inside the
            // signed region, and it needs its own check rather than borrowing the envelope's.
            $rejects(IdentityReaderException::ISSUER_MISMATCH, [
                'issuer' => SamlFixtures::IDP_ENTITY_ID . '.evil.test',
            ]);
        },

    'A6: a foreign issuer on the Response envelope is rejected too' =>
        static function () use ($rejects): void {
            $rejects(IdentityReaderException::ISSUER_MISMATCH, [
                'responseIssuer' => SamlFixtures::IDP_ENTITY_ID . '.evil.test',
            ]);
        },

    // ---------------------------------------------------------------- A8
    'A8: the user-facing message leaks neither the response nor the certificate' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => SamlFixtures::response([
                        'now' => $now,
                        'audience' => 'https://someone-else.example.test/metadata',
                    ]),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::AUDIENCE_MISMATCH, $error->reasonCode());
            Assert::notContains('someone-else.example.test', $error->getMessage());
            Assert::notContains('BEGIN CERTIFICATE', $error->getMessage());
            Assert::notContains('saml', strtolower($error->getMessage()));

            // The administrator half of the split (BL-2) keeps the detail out of the message.
            Assert::contains('someone-else.example.test', $reader->detail());
        },

    'the reader offers its detail to LoginFlow, which is how it reaches the diagnostics row' =>
        static function () use ($makeReader): void {
            [$reader] = $makeReader();

            Assert::true($reader instanceof \Keyway\Sso\Core\Port\RejectionDetailInterface);
        },

    'A8: a malformed body is a reason code, not a stack trace' =>
        static function () use ($makeReader): void {
            [$reader, $relayState] = $makeReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => 'not base64 at all $$$',
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::MALFORMED_RESPONSE, $error->reasonCode());
        },

    // ---------------------------------------------------------------- B11 encrypted assertions
    //
    // Until 1.0.2 this path had no test at all and the documentation said so ("unverified").
    // The fixtures are encrypted for real (SamlFixtures::encryptAssertion): AES-256-CBC for the
    // assertion, RSA-OAEP for the session key, to the service provider's certificate.
    'B11: an encrypted, signed assertion is decrypted and then read like any other' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader(['spPrivateKey' => SamlFixtures::spKey()]);

            $payload = $reader->read([
                'SAMLResponse' => SamlFixtures::encryptAssertion(
                    SamlFixtures::response(['now' => $now]),
                    SamlFixtures::spCert()
                ),
                'RelayState' => $relayState,
            ]);

            Assert::true($payload instanceof IdentityPayload);
            Assert::same('alice@example.test', $payload->nameId());
            Assert::same(SamlFixtures::IDP_ENTITY_ID, $payload->issuer());
            Assert::sameList(['Staff', 'Admins'], $payload->values('Groups'), 'attributes come out of the ciphertext');
        },

    'B11: the fixture really is encrypted - the plaintext assertion is not in the message' =>
        static function () use ($now): void {
            $xml = (string)base64_decode(SamlFixtures::encryptAssertion(
                SamlFixtures::response(['now' => $now]),
                SamlFixtures::spCert()
            ), true);

            Assert::contains('EncryptedAssertion', $xml);
            Assert::contains('EncryptedKey', $xml);
            Assert::notContains('alice@example.test', $xml, 'the subject is inside the ciphertext');
            Assert::notContains('<saml:Assertion', $xml);
        },

    'B11: an encrypted assertion with no SP private key configured is refused, and says why' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader();

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => SamlFixtures::encryptAssertion(
                        SamlFixtures::response(['now' => $now]),
                        SamlFixtures::spCert()
                    ),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::DECRYPTION_FAILED, $error->reasonCode());
            Assert::contains('no SP private key is configured', $reader->detail());
        },

    'B11: an assertion encrypted to somebody else\'s certificate is refused' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader(['spPrivateKey' => SamlFixtures::spKey()]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => SamlFixtures::encryptAssertion(
                        SamlFixtures::response(['now' => $now]),
                        SamlFixtures::foreignCert()
                    ),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::DECRYPTION_FAILED, $error->reasonCode());
            Assert::notContains('BEGIN', $reader->detail(), 'no key material in the detail');
        },

    // "Decryption success is not validation" (B11). Anyone can encrypt to our certificate - it
    // is public by design - so the ciphertext proves nothing about who wrote the assertion.
    'B11: an unsigned assertion is refused even though it decrypted' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader(['spPrivateKey' => SamlFixtures::spKey()]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => SamlFixtures::encryptAssertion(
                        SamlFixtures::response(['now' => $now, 'signAssertion' => false]),
                        SamlFixtures::spCert()
                    ),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::SIGNATURE_COVERAGE, $error->reasonCode());
        },

    'B11: an assertion signed by somebody else is refused even though it decrypted' =>
        static function () use ($makeReader, $now): void {
            [$reader, $relayState] = $makeReader(['spPrivateKey' => SamlFixtures::spKey()]);

            $error = Assert::throws(
                IdentityReaderException::class,
                static fn () => $reader->read([
                    'SAMLResponse' => SamlFixtures::encryptAssertion(
                        SamlFixtures::response(['now' => $now, 'signWith' => 'foreign']),
                        SamlFixtures::spCert()
                    ),
                    'RelayState' => $relayState,
                ])
            );

            /** @var IdentityReaderException $error */
            Assert::same(IdentityReaderException::SIGNATURE_INVALID, $error->reasonCode());
        },

    // ---------------------------------------------------------------- A3 configuration
    'A3: a fingerprint cannot be configured in place of a certificate' =>
        static function (): void {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SamlConnectionConfig(
                    SamlFixtures::IDP_ENTITY_ID,
                    'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
                    SamlFixtures::SP_ENTITY_ID,
                    SamlFixtures::ACS_URL,
                    SamlFixtures::IDP_SSO_URL
                )
            );

            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new SamlConnectionConfig(
                    SamlFixtures::IDP_ENTITY_ID,
                    SamlFixtures::cert(),
                    SamlFixtures::SP_ENTITY_ID,
                    '/sso/acs',
                    SamlFixtures::IDP_SSO_URL
                ),
                'a relative ACS URL cannot be compared with a Recipient'
            );
        },
];
