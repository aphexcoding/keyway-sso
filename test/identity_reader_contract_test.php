<?php

declare(strict_types=1);

use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Test\Support\Assert;

/**
 * The contract in IdentityReaderInterface is the only thing standing between the protocol layer
 * and an authentication bypass: the core does no cryptography and cannot re-check anything the
 * reader waved through. It is therefore treated as code and tested as code.
 *
 * These cases lock the clauses whose absence is exploitable. They fail loudly if a later turn
 * trims the contract down to something an implementation can satisfy while still being wrong -
 * which is exactly what happened to the first draft ("the Response OR the Assertion is signed",
 * literally satisfied by XML Signature Wrapping, CVE-2017-11427).
 */
$contract = static function (): string {
    $doc = (new ReflectionClass(IdentityReaderInterface::class))->getDocComment();

    return $doc === false ? '' : $doc;
};

/**
 * @param list<string> $needles
 */
$requireAll = static function (string $haystack, array $needles, string $label): void {
    foreach ($needles as $needle) {
        Assert::contains($needle, $haystack, $label . ' - missing clause');
    }
};

return [
    'the contract forbids trusting a signature that covers the wrong node' =>
        static function () use ($contract, $requireAll): void {
            $doc = $contract();

            $requireAll($doc, [
                'EXACTLY ONE ASSERTION',
                'more than one `saml:Assertion`',
                'ATTRIBUTES COME FROM THE SIGNED ASSERTION',
                'the node the verified signature references',
                'Signature Wrapping',
                'CVE-2017-11427',
            ], 'signature wrapping');

            Assert::notContains(
                'the signature over the Response or the Assertion is',
                $doc,
                'the wording that a wrapping attack satisfies literally must not come back'
            );
        },

    'the SAML half names every check a bypass would otherwise skip' =>
        static function () use ($contract, $requireAll): void {
            $requireAll($contract(), [
                'samlp:Status',
                'status:Success',
                'SubjectConfirmation',
                'cm:bearer',
                'Recipient',
                'NotOnOrAfter',
                'NotBefore',
                'AudienceRestriction',
                'InResponseTo',
                'Destination',
                'NAMEID MUST BE PRESENT AND NON-EMPTY',
                'XXE AND DTD ARE OFF',
                'DOCTYPE',
                'ENCRYPTED ASSERTIONS',
            ], 'SAML');
        },

    'clock skew is expressed as a number, not as an intention' =>
        static function () use ($contract): void {
            $doc = $contract();

            Assert::contains('CLOCK SKEW', $doc);
            Assert::true(
                preg_match('/at most (\d+) seconds/', $doc, $m) === 1,
                'the skew allowance must be a concrete number the implementer can code against'
            );
            Assert::true((int)($m[1] ?? 0) > 0 && (int)($m[1] ?? 0) <= 300, 'skew stays small');
        },

    'the OIDC half exists at all, and makes nonce mandatory' =>
        static function () use ($contract, $requireAll): void {
            $doc = $contract();

            $requireAll($doc, [
                'C. OIDC',
                '`nonce` IS MANDATORY',
                'THE READER MUST NOT SHIP',
                'never a reason to skip the check',
            ], 'OIDC nonce');

            Assert::contains(
                'equivalent of `InResponseTo`',
                $doc,
                'nonce must be named as the OIDC twin of InResponseTo, or it reads as optional'
            );
        },

    'the OIDC half pins the algorithms and the key source' =>
        static function () use ($contract, $requireAll): void {
            $requireAll($contract(), [
                'ALGORITHM ALLOW LIST',
                'RS256',
                'ES256',
                '`alg: none` IS REJECTED',
                'HMAC ALGORITHMS',
                'HS256',
                'JWKS',
                'openid-configuration',
                '`kid` MUST MATCH',
                'at_hash',
                'c_hash',
                'PKCE IS MANDATORY',
                'code_challenge_method = S256',
                'azp',
            ], 'OIDC verification');
        },

    'every rejection has a stable, distinct reason code' => static function (): void {
        $reasons = IdentityReaderException::reasons();

        Assert::same(count($reasons), count(array_unique($reasons)), 'codes must be distinct');
        Assert::true(count($reasons) >= 20, 'one code per class of rejection, not a token few');

        foreach ([
            IdentityReaderException::SIGNATURE_COVERAGE,
            IdentityReaderException::MULTIPLE_ASSERTIONS,
            IdentityReaderException::STATUS_NOT_SUCCESS,
            IdentityReaderException::CONFIRMATION_INVALID,
            IdentityReaderException::SUBJECT_MISSING,
            IdentityReaderException::DOCTYPE_REJECTED,
            IdentityReaderException::ALGORITHM_NOT_ALLOWED,
            IdentityReaderException::NONCE_MISMATCH,
            IdentityReaderException::KEY_NOT_FOUND,
            IdentityReaderException::TOKEN_HASH_MISMATCH,
        ] as $code) {
            Assert::true(IdentityReaderException::isKnownReason($code), $code);
        }
    },

    'an invented reason code is refused at the throw site' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new IdentityReaderException('whatever_went_wrong', 'Login failed.')
        );

        $exception = new IdentityReaderException(
            IdentityReaderException::NONCE_MISMATCH,
            'The sign-in response did not belong to this browser session.'
        );

        Assert::same(IdentityReaderException::NONCE_MISMATCH, $exception->reasonCode());
        Assert::notContains('eyJhbGciOi', $exception->getMessage(), 'no raw token in the message');
    },
];
