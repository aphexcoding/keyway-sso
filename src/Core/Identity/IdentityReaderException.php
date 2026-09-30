<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Identity;

use InvalidArgumentException;
use RuntimeException;

/**
 * Thrown by the protocol layer when a SAML response or an OIDC token cannot be trusted.
 *
 * The message is safe to show to an end user. Everything that could help an attacker -
 * the raw response, certificate details, the exact clock skew - stays out of it and belongs
 * in the diagnostics record instead.
 *
 * The reason codes are the machine-readable half of the contract in IdentityReaderInterface:
 * one code per class of rejection, stable across releases, safe to log and to match on in the
 * diagnostics panel. A reader that cannot express its rejection with one of these codes is
 * rejecting for a reason nobody designed for, which is itself worth reviewing.
 */
final class IdentityReaderException extends RuntimeException
{
    // Universal (contract section A).
    public const SIGNATURE_INVALID = 'signature_invalid';
    public const SIGNATURE_COVERAGE = 'signature_coverage';
    /**
     * Nothing was signed at all. Distinct from SIGNATURE_INVALID on purpose: "the signature did
     * not verify" and "there was no signature and we required one" are different operator
     * problems - the first is a key mismatch, the second is an IdP configured not to sign (or a
     * forged message that simply left the parameter out).
     */
    public const SIGNATURE_MISSING = 'signature_missing';
    public const MALFORMED_RESPONSE = 'malformed_response';
    public const ISSUER_MISMATCH = 'issuer_mismatch';
    public const AUDIENCE_MISMATCH = 'audience_mismatch';
    public const ASSERTION_EXPIRED = 'assertion_expired';
    public const REPLAYED_ASSERTION = 'replayed_assertion';
    public const UNSOLICITED_RESPONSE = 'unsolicited_response';
    public const SUBJECT_MISSING = 'subject_missing';
    /**
     * Two sources named two different people. Distinct from SUBJECT_MISSING on purpose: this is
     * not "we found no subject" but "the second document describes somebody else", which is the
     * shape of an account mix-up attack (OIDC C10: a userinfo response whose `sub` disagrees
     * with the verified id token).
     */
    public const SUBJECT_MISMATCH = 'subject_mismatch';

    // SAML (contract section B).
    public const MULTIPLE_ASSERTIONS = 'multiple_assertions';
    public const STATUS_NOT_SUCCESS = 'status_not_success';
    public const CONFIRMATION_INVALID = 'confirmation_invalid';
    public const DESTINATION_MISMATCH = 'destination_mismatch';
    public const DOCTYPE_REJECTED = 'doctype_rejected';
    public const DECRYPTION_FAILED = 'decryption_failed';

    // OIDC (contract section C).
    public const ALGORITHM_NOT_ALLOWED = 'algorithm_not_allowed';
    public const KEY_NOT_FOUND = 'key_not_found';
    public const NONCE_MISMATCH = 'nonce_mismatch';
    public const TOKEN_HASH_MISMATCH = 'token_hash_mismatch';
    public const DISCOVERY_FAILED = 'discovery_failed';

    private string $reasonCode;

    public function __construct(string $reasonCode, string $message)
    {
        if (!self::isKnownReason($reasonCode)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown identity reader reason code "%s". Add it to IdentityReaderException '
                . 'instead of inventing one at the call site.',
                $reasonCode
            ));
        }

        parent::__construct($message);
        $this->reasonCode = $reasonCode;
    }

    public function reasonCode(): string
    {
        return $this->reasonCode;
    }

    /**
     * @return list<string>
     */
    public static function reasons(): array
    {
        return array_values((new \ReflectionClass(self::class))->getConstants());
    }

    public static function isKnownReason(string $reasonCode): bool
    {
        return in_array($reasonCode, self::reasons(), true);
    }
}
