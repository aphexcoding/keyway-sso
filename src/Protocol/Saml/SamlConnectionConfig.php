<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use InvalidArgumentException;

/**
 * Everything the SAML reader is allowed to trust, fixed at construction time.
 *
 * Immutable on purpose: the verification key, the audience and the ACS URL are the three values
 * an attacker would most like to influence, and a settings object that can be mutated after the
 * reader was built is a settings object that can be mutated between two checks.
 *
 * No permissive defaults. Every value that would weaken a check when left unset is a required
 * constructor argument, and the two that do have defaults (skew, replay retention) default to
 * the strict end of their range. This is the lesson from BL-1: a default that "just works" for
 * a broken IdP is a default that works for an attacker too.
 *
 * Note on key material (contract A3): the IdP is identified by a CERTIFICATE, never by a
 * fingerprint. onelogin/php-saml still supports fingerprint-only configuration and that path is
 * deliberately unreachable from here - a fingerprint match verifies which certificate travelled
 * inside the message, and the message is the attacker's document.
 */
final class SamlConnectionConfig
{
    /** Contract A4: the ceiling is part of the contract, not a preference. */
    public const MAX_CLOCK_SKEW = 120;

    public readonly string $idpEntityId;
    public readonly string $idpX509Cert;
    public readonly string $spEntityId;
    public readonly string $acsUrl;

    /**
     * Where the AuthnRequest is sent (the IdP's HTTP-Redirect SSO endpoint). Read only by
     * SamlAuthnRequest; the reader never needs it, but it lives here because a connection
     * described in two objects is a connection whose two descriptions drift apart.
     */
    public readonly string $idpSsoUrl;

    /**
     * The IdP's Single Logout endpoint (HTTP-Redirect), and ours.
     *
     * Both are nullable and both default to null, because a connection without SLO is the
     * normal case and has to stay expressible: an IdP that does not offer SLO is not a
     * misconfiguration. `canLogout()` is the single question the logout classes ask, so a
     * half-configured connection (their endpoint but not ours, or no signing key) can never
     * produce a LogoutRequest that goes somewhere we cannot be answered at.
     */
    public readonly ?string $idpSloUrl;

    /** Our SLO endpoint: the value Destination must carry on an inbound logout message. */
    public readonly ?string $spSloUrl;

    public readonly ?string $spPrivateKey;
    public readonly int $clockSkew;

    public function __construct(
        string $idpEntityId,
        string $idpX509Cert,
        string $spEntityId,
        string $acsUrl,
        string $idpSsoUrl,
        ?string $spPrivateKey = null,
        int $clockSkew = 60,
        ?string $idpSloUrl = null,
        ?string $spSloUrl = null
    ) {
        $idpEntityId = trim($idpEntityId);
        $spEntityId = trim($spEntityId);
        $acsUrl = trim($acsUrl);
        $idpSsoUrl = trim($idpSsoUrl);
        $idpX509Cert = trim($idpX509Cert);
        $idpSloUrl = $idpSloUrl === null ? null : trim($idpSloUrl);
        $spSloUrl = $spSloUrl === null ? null : trim($spSloUrl);

        if ($idpEntityId === '') {
            throw new InvalidArgumentException('IdP entity id must not be empty.');
        }

        if ($spEntityId === '') {
            throw new InvalidArgumentException('SP entity id must not be empty.');
        }

        if ($acsUrl === '' || !self::isHttpUrl($acsUrl)) {
            throw new InvalidArgumentException('ACS URL must be an absolute http(s) URL.');
        }

        if ($idpSsoUrl === '' || !self::isHttpUrl($idpSsoUrl)) {
            throw new InvalidArgumentException('IdP SSO URL must be an absolute http(s) URL.');
        }

        if (!self::looksLikeCertificate($idpX509Cert)) {
            throw new InvalidArgumentException(
                'IdP signing certificate must be a PEM or base64 X.509 certificate. '
                . 'A fingerprint is not accepted: it proves which certificate the message '
                . 'carried, not which certificate we trust.'
            );
        }

        if ($idpSloUrl !== null && !self::isHttpUrl($idpSloUrl)) {
            throw new InvalidArgumentException('IdP SLO URL must be an absolute http(s) URL or null.');
        }

        if ($spSloUrl !== null && !self::isHttpUrl($spSloUrl)) {
            throw new InvalidArgumentException('SP SLO URL must be an absolute http(s) URL or null.');
        }

        if ($spPrivateKey !== null && trim($spPrivateKey) === '') {
            throw new InvalidArgumentException(
                'SP private key must be a key or null, never an empty string.'
            );
        }

        if ($clockSkew < 0 || $clockSkew > self::MAX_CLOCK_SKEW) {
            throw new InvalidArgumentException(sprintf(
                'Clock skew must be between 0 and %d seconds.',
                self::MAX_CLOCK_SKEW
            ));
        }

        $this->idpEntityId = $idpEntityId;
        $this->idpX509Cert = self::armour($idpX509Cert);
        $this->spEntityId = $spEntityId;
        $this->acsUrl = $acsUrl;
        $this->idpSsoUrl = $idpSsoUrl;
        $this->idpSloUrl = $idpSloUrl;
        $this->spSloUrl = $spSloUrl;
        $this->spPrivateKey = $spPrivateKey === null ? null : trim($spPrivateKey);
        $this->clockSkew = $clockSkew;
    }

    public function canDecrypt(): bool
    {
        return $this->spPrivateKey !== null;
    }

    /**
     * Whether Single Logout is usable on this connection AT ALL.
     *
     * All three parts are required together on purpose. Without the IdP endpoint there is
     * nowhere to send a LogoutRequest; without our own endpoint we cannot state a Destination
     * the IdP can echo back, and an inbound message could not be pinned to this endpoint;
     * without a private key we cannot sign, and SAML 2.0 Core 3.7.1 says logout messages
     * SHOULD be signed - an unsigned LogoutRequest is refused by every IdP worth integrating
     * with, and accepting an unsigned inbound one would make session termination a GET request
     * anybody could forge.
     */
    public function canLogout(): bool
    {
        return $this->idpSloUrl !== null
            && $this->spSloUrl !== null
            && $this->spPrivateKey !== null;
    }

    private static function isHttpUrl(string $url): bool
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));

        return ($scheme === 'https' || $scheme === 'http')
            && (string)parse_url($url, PHP_URL_HOST) !== '';
    }

    /**
     * The certificate as PEM, whatever shape the administrator pasted.
     *
     * NORMALISED HERE, ON THE BOUNDARY, BECAUSE THE TWO RUNTIME PATHS DISAGREE ABOUT SHAPE and
     * the disagreement is invisible until somebody tries to log in:
     *
     *  - single logout reads it through `Utils::formatCert()` (SamlLogoutMessageReader), which
     *    adds the armour itself, so a bare base64 body works there;
     *  - SIGN-IN does not. SamlResponseReader hands the value to `Utils::validateSign()`, which
     *    reaches `XMLSecurityKey::loadKey($cert, false, true)` and calls `openssl_x509_read()`
     *    on the raw string (xmlseclibs, src/XMLSecurityKey.php:365). openssl_x509_read() does
     *    not read base64 without armour.
     *
     * MEASURED, same certificate in two shapes, through the whole SamlResponseReader::read():
     * PEM -> signature verified; bare base64 -> IdentityReaderException, "We could not verify
     * the sign-in response from your identity provider." The settings screen (_settings.twig)
     * has always promised "PEM or base64", so the promise was false for the half of the
     * administrators whose identity provider panel shows the bare body.
     *
     * It is done in the CONSTRUCTOR rather than in SettingsTranslator because this object is
     * what both readers actually read (`$this->config->idpX509Cert`). Normalising one layer up
     * would leave the broken shape reachable through every other caller - including the test
     * fixtures, which is precisely how a reader-only mismatch survives unnoticed.
     *
     * This is still shape work, not validation: no openssl call, nothing rejected that was
     * accepted before. Whether the bytes are a certificate at all is decided at save time, by
     * IdpCertificate (SettingsTranslator::problems()).
     *
     * PUBLIC because the save-time gate has to ask openssl about THE STRING THE READERS WILL
     * GET, not about its own idea of it. IdpCertificate calls this and checks the result; a
     * second copy of the rule there is exactly how the sign-in mismatch above stayed invisible.
     */
    public static function armour(string $value): string
    {
        // The same question looksLikeCertificate() asks, deliberately identical: a value it
        // called "already armoured" must not be re-armoured here, or the two would disagree
        // about the same string.
        if (str_contains($value, 'BEGIN CERTIFICATE')) {
            return $value;
        }

        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(preg_replace('/\s+/', '', $value) ?? '', 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    /**
     * Deliberately shape-based rather than "does OpenSSL like it": the point is to reject a
     * fingerprint (hex or colon-separated) and other short strings, not to re-parse X.509.
     */
    private static function looksLikeCertificate(string $value): bool
    {
        if ($value === '') {
            return false;
        }

        if (str_contains($value, 'BEGIN CERTIFICATE')) {
            return true;
        }

        $compact = preg_replace('/\s+/', '', $value) ?? '';

        if (strlen($compact) < 256) {
            // A SHA-256 fingerprint is 64 hex characters; no X.509 certificate is this short.
            return false;
        }

        return preg_match('/^[A-Za-z0-9+\/=]+$/', $compact) === 1;
    }
}
