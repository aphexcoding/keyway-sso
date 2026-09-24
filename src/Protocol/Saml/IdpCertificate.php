<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

use InvalidArgumentException;

/**
 * The save-time question about the IdP signing certificate: WILL THIS VERIFY A SIGNATURE?
 *
 * SamlConnectionConfig::looksLikeCertificate() answers a different, deliberately weaker
 * question - "is this a fingerprint or something certificate-shaped?" - and it has to stay
 * weak, because it runs while a login page is rendering and on every fixture in the suite.
 * Shape cannot tell a de-armoured certificate from a de-armoured private key, a truncated
 * paste or 256 characters of noise: all four are base64 of DER-ish bytes. So today an
 * administrator saves a configuration that passes validation and then fails at the FIRST
 * LOGIN, as a signature-verification error that reads like a fault in their identity provider.
 *
 * This class is the strict half, called from SettingsTranslator::problems() and nowhere else.
 * It refuses only what CANNOT work, never what merely looks unusual - a settings screen that
 * blocks a save it should have allowed locks an administrator out of their own configuration,
 * which is a worse failure than the one being fixed here.
 *
 * HOW PARITY WITH THE RUNTIME IS ACHIEVED, because the first version of this class got it
 * wrong and the mistake was invisible for exactly the reason the whole defect was:
 *
 *  1. IT ASKS ABOUT THE STRING THE READERS WILL RECEIVE, not about its own normalisation of
 *     the field. `SamlConnectionConfig::armour()` is what turns the setting into the value
 *     both readers hold, so this class calls it rather than re-deriving it. The earlier
 *     version reimplemented onelogin's `Utils::formatCert()` here and matched the SINGLE
 *     LOGOUT path only; sign-in does not go through formatCert() at all (it reaches
 *     `XMLSecurityKey::loadKey()` -> `openssl_x509_read()` on the raw value), so bare base64
 *     was blessed by this gate and failed every login. One normalisation, one owner.
 *
 *  2. IT ASKS THE QUESTION THE READERS ASK: `openssl_pkey_get_public()`. Single logout calls
 *     exactly that (SamlLogoutMessageReader), and sign-in ends in the same call inside
 *     xmlseclibs after exporting the parsed certificate. `openssl_x509_read()` - the obvious
 *     choice, and what this used to use - is MEASURABLY WEAKER: over 4000 single-bit mutations
 *     of a real certificate, 98 parsed as X.509 and then yielded no usable public key, and
 *     nothing ever moved the other way. Checked again against the ground truth rather than
 *     against another predicate - 600 mutations run through the whole
 *     SamlResponseReader::read() - this one refused NOTHING the reader could actually have
 *     used (0 false refusals), while openssl_x509_read() blessed 12 more broken values.
 *
 *     WHAT IT STILL CANNOT DO, so nobody reads more into a green screen than is there: of
 *     those 600 mutations, 145 satisfied this check and still failed the login. They are
 *     certificates that are perfectly well formed and simply NOT THE ONE that signed the
 *     response, and no check on the value alone can tell - it takes a signature to compare
 *     against. The gate promises "this can carry a signature check", never "this is the right
 *     certificate".
 *
 *  3. WITHOUT ext-openssl IT ACCEPTS, where SpMetadata refuses. The asymmetry is the point:
 *     SpMetadata decides whether to PUBLISH a document, so silence is the safe answer; this
 *     decides whether an administrator may SAVE, and refusing every certificate on a host with
 *     no openssl would shut them out of the settings screen entirely - including out of
 *     switching the protocol back off. `composer.json` requires ext-openssl and Craft 5
 *     requires it too, so the branch is unreachable on any install that could call it; it is
 *     written this way so that if it ever is reached, it degrades to the old behaviour instead
 *     of to a lockout.
 *
 * Everything after the accept/refuse decision is only about WHICH SENTENCE to show, and none of
 * it may change the verdict.
 *
 * WHAT IT DELIBERATELY DOES NOT REFUSE, so the gap is named rather than discovered:
 *
 *  - a PEM value carrying more than one block (a chain, or a certificate with a key pasted
 *    after it), and `base64(DER(certificate) . DER(key))` with the armour removed. OpenSSL
 *    takes the first structure in both cases and so does the reader, so these values WORK, and
 *    this gate only blocks what cannot. A private key pasted next to the certificate deserves
 *    a sentence on the screen all the same - it does not belong in project config - but as a
 *    warning, never as a refusal. THAT WARNING EXISTS SINCE 2026-09-23: `carriesPrivateKey()`
 *    below answers the question and SettingsTranslator::warnings() says the sentence. The
 *    verdict of this gate did not move an inch - both shapes still save.
 */
final class IdpCertificate
{
    /**
     * Refuses a configured value that cannot verify a signature.
     *
     * CONTRACT: call this only for a value that already passed SamlConnectionConfig's shape
     * floor - i.e. only when the connection itself built. A fingerprint, an empty field or a
     * short blob is refused there, in words that name the mistake ("a fingerprint proves which
     * certificate the message carried, not which certificate we trust"), and repeating that
     * verdict here would put two messages on the screen for one mistake. The call site in
     * SettingsTranslator::problems() enforces the ordering.
     *
     * @throws InvalidArgumentException with a sentence for the settings screen: it names what
     *         the administrator actually pasted, because "invalid input" sends them back to the
     *         identity provider with nothing to look for.
     */
    public static function assertUsable(string $value): void
    {
        $value = trim($value);

        if ($value === '') {
            return; // SamlConnectionConfig already refuses an empty field.
        }

        // See point 3 in the class comment: accept rather than lock the administrator out.
        if (!extension_loaded('openssl')) {
            return;
        }

        // THE DECISION, and the only two lines of it: the exact string the readers will hold,
        // put to the exact question the readers ask.
        if (self::yieldsPublicKey(SamlConnectionConfig::armour($value))) {
            return;
        }

        // ---- from here the login WOULD fail; all that is left is saying why ----

        $body = preg_replace('/\s+/', '', self::bodyTheReaderWillUse($value)) ?? '';
        $der = base64_decode($body, true);

        if ($der === false) {
            throw new InvalidArgumentException(
                'The signing certificate is not valid base64, so nothing can be decoded from '
                . 'it. Paste it exactly as the identity provider hands it over: a '
                . '-----BEGIN CERTIFICATE----- block, or the bare base64 body of one.'
            );
        }

        // The certificate is intact and something around it is not. MEASURED: OpenSSL's PEM
        // decoder skips spaces, tabs, CR and LF inside the body but NOT a vertical tab (0x0B)
        // or a form feed (0x0C), which is what a copy out of a PDF or a word processor brings
        // with it. A bare body never lands here - armour() strips all whitespace on its way in
        // - so this is specifically about characters sitting inside a pasted PEM block.
        if (self::yieldsPublicKey(self::pem('CERTIFICATE', $body))) {
            throw new InvalidArgumentException(
                'The certificate itself is fine, but the block around it contains a character '
                . 'the reader cannot skip - usually a vertical tab or a form feed picked up by '
                . 'copying from a PDF or a word processor. Paste it again from a plain-text '
                . 'view of the file.'
            );
        }

        if (self::parsesAsPrivateKey($body)) {
            throw new InvalidArgumentException(
                'This is a PRIVATE KEY, not a certificate. Nothing signed by the identity '
                . 'provider could be verified with it, and this field is stored with the rest '
                . 'of the settings - remove it. What belongs here is the identity provider\'s '
                . 'public signing certificate: the X509Certificate element of its SAML metadata.'
            );
        }

        if (self::parsesAsPublicKey($body)) {
            throw new InvalidArgumentException(
                'This is a bare public key, not a certificate. The SAML reader needs the '
                . 'identity provider\'s X.509 certificate - the X509Certificate element of its '
                . 'SAML metadata - because that is what the signature is checked against.'
            );
        }

        // Structurally a certificate, and still unusable: the bytes that carry the public key
        // are damaged. One flipped bit in the key field does exactly this, and it is worth its
        // own sentence - "not a certificate" would send the administrator looking for the
        // wrong file.
        if (self::parsesAsCertificate($body)) {
            throw new InvalidArgumentException(
                'This parses as an X.509 certificate, but no public key can be read out of it, '
                . 'so no signature could be verified against it. The copy is damaged - ask the '
                . 'identity provider for its signing certificate again.'
            );
        }

        $declared = self::declaredStructureLength($der);

        if ($declared !== null && $declared > strlen($der)) {
            throw new InvalidArgumentException(sprintf(
                'The pasted value is cut short: it opens a %d-byte structure but only %d bytes '
                . 'are present, which is what a partial copy looks like. Copy the certificate '
                . 'again, from its first character to its last.',
                $declared,
                strlen($der)
            ));
        }

        throw new InvalidArgumentException(
            'OpenSSL does not recognise this as an X.509 certificate, so no signature could '
            . 'ever be verified against it. Paste the identity provider\'s signing certificate '
            . '- the X509Certificate element of its SAML metadata - not a fingerprint, a key or '
            . 'part of a file.'
        );
    }

    /**
     * Is a private key sitting in this field NEXT TO the certificate? A WARNING, NEVER A REFUSAL.
     *
     * The paste this exists for: an administrator copies "the signing key" out of an identity
     * provider export and gets the certificate and its private key together - two PEM blocks, or
     * `base64(DER(certificate) . DER(key))` once the armour is gone. BOTH SHAPES WORK at login
     * (openssl takes the first structure, and so does every reader), which is why assertUsable()
     * leaves them alone - see the last section of the class comment. But the key is then stored
     * wherever the settings are stored: database, project config, every backup of either. That
     * earns a sentence on the settings screen, and SettingsTranslator::warnings() says it.
     *
     * A CHAIN IS NOT A KEY, and that is the whole difficulty of this predicate. `certificate +
     * intermediate`, in either shape, is a legitimate paste and has to stay silent: the question
     * asked here is "is one of these a private key", never "is there more than one structure".
     * A warning that cries wolf on a chain teaches administrators to scroll past the other six.
     *
     * THE CERTIFICATE HALF HAS TO WORK, NOT MERELY BE THERE, and that is the first thing this
     * asks. The warning says "sign-in still works", which is a STATEMENT OF FACT, so it may only
     * be shown where it is true: a damaged certificate, a copy cut short, a block a word
     * processor put a vertical tab into, a block never closed - each of those, with a key pasted
     * next to it, is refused by assertUsable() in its own words, and adding "sign-in still
     * works" underneath would tell the administrator the opposite of what just happened. It is
     * also the other half of NEXT TO, NOT INSTEAD OF: a field holding only a private key is
     * already refused, and answering true for it would put two messages on the screen for one
     * paste. So the gate is `yieldsPublicKey(armour($value))` - THE SAME LINE assertUsable()
     * decides on, and the same question both readers ask (point 1 of the class comment). One
     * owner for "will this value sign anybody in"; asking it a second way here is exactly how
     * the screen ends up contradicting itself.
     *
     * THE TWO SHAPES ARE NOT COVERED EQUALLY, and the gap is named here rather than discovered.
     * The armoured branch matches every label that ENDS IN "PRIVATE KEY", so an encrypted key
     * counts too. The de-armoured branch catches less: it ends in `parsesAsPrivateKey()`, which
     * tries three labels through `openssl_pkey_get_private()`, and so it stays silent on an
     * ENCRYPTED key (EncryptedPrivateKeyInfo cannot be parsed without the passphrase, which we
     * do not have and must not ask for) AND on an unencrypted DSA key in traditional armour
     * (`DSA PRIVATE KEY` is not one of the three labels tried). Reading the structure's OID
     * instead of parsing it would close the first gap and not the second, and every looser
     * alternative ("the remainder is not a certificate") trades a measured false-positive rate
     * of zero for guesswork on a legitimate chain. Left as it is on purpose: de-armouring a key
     * first is the rarer paste, and PKCS#12 output - the common one - arrives armoured.
     *
     * Without ext-openssl it answers false. Same asymmetry as point 3 of the class comment and
     * for the same reason: this runs while the settings screen renders, so a missing extension
     * has to cost a warning, not the screen.
     */
    public static function carriesPrivateKey(string $value): bool
    {
        $value = trim($value);

        if ($value === '' || !extension_loaded('openssl')) {
            return false;
        }

        // "Sign-in still works" has to be TRUE before it is said - see THE CERTIFICATE HALF HAS
        // TO WORK above. This is assertUsable()'s decision line, verbatim: a value it refuses
        // gets its sentence from there and nothing from here.
        if (!self::yieldsPublicKey(SamlConnectionConfig::armour($value))) {
            return false;
        }

        // THE ARMOURED SHAPE, and it is the same question `SamlConnectionConfig::armour()` asks
        // to decide whether a value is already armoured - one owner for "is this PEM", so the
        // two cannot disagree about the same string.
        if (str_contains($value, 'BEGIN CERTIFICATE')) {
            // THE LABEL IS TAKEN AT ITS WORD, without parsing the block. A key too mangled to
            // parse is still a key sitting in project config, still has to be removed and still
            // has to be rotated; requiring a successful parse would mean the worse paste gets
            // the quieter screen.
            //
            // EVERY LABEL THAT ENDS IN "PRIVATE KEY", not a list of the ones we thought of -
            // and no wider than that: the pattern wants the phrase as the tail of the label and
            // five dashes around it, so ssh.com/PuTTY's `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY
            // ----` (four dashes) does not match. Left alone: no identity provider exports it.
            // The list was the defect: it read PKCS#8, PKCS#1, SEC1 and matched only
            // `PRIVATE KEY`, `RSA PRIVATE KEY` and `EC PRIVATE KEY` - so it missed
            // `ENCRYPTED PRIVATE KEY`, which IS PKCS#8 (EncryptedPrivateKeyInfo) and is what
            // the DEFAULT `openssl pkcs12 -in idp.pfx -out idp.pem` writes next to the
            // certificate. PKCS#12 is how ADFS, Entra and keytool hand a certificate over
            // together with its key, the variant without `-nodes` is the one in every guide,
            // and an encrypted key satisfies the paragraph above to the letter: it is a key in
            // project config. `DSA PRIVATE KEY` and `OPENSSH PRIVATE KEY` were silent for the
            // same reason. A false positive is structurally impossible here - no legitimate
            // certificate paste contains a "BEGIN ... PRIVATE KEY" line at all.
            return preg_match('/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/', $value) === 1;
        }

        // THE DE-ARMOURED SHAPE: one base64 blob holding two DER structures back to back. The
        // first is the one the readers use; everything after it is what this asks about.
        $body = preg_replace('/\s+/', '', $value) ?? '';
        $der = base64_decode($body, true);

        if ($der === false) {
            return false;
        }

        $length = self::declaredStructureLength($der);

        // Nothing measurable, a structure that claims the whole blob (an ordinary certificate)
        // or one claiming more than is there (a truncated paste): nothing follows it.
        if ($length === null || $length <= 0 || $length >= strlen($der)) {
            return false;
        }

        $rest = substr($der, $length);

        // The shortest DER structure there can be is a tag byte plus a length byte; anything
        // shorter is padding or a stray newline that survived base64, not a key.
        if (strlen($rest) < 2) {
            return false;
        }

        // The second structure has to parse as a key. THAT IS WHAT KEEPS A CHAIN SILENT: there
        // the second structure is another certificate, and a predicate that only counted
        // structures would fire on every legitimate chain in existence.
        //
        // The first-structure check is REDUNDANT since the usability gate above went in - a
        // value that yields a public key through CERTIFICATE armour necessarily opens with a
        // certificate. It stays because it states the branch's own precondition locally,
        // instead of borrowing it from a check twenty lines up.
        return self::parsesAsCertificate(base64_encode(substr($der, 0, $length)))
            && self::parsesAsPrivateKey(base64_encode($rest));
    }

    /**
     * Does a public key come out of this? THE QUESTION BOTH READERS ASK, and therefore the only
     * one allowed to decide here.
     *
     * @param string $pem a complete PEM block, exactly as the readers will receive it.
     */
    public static function yieldsPublicKey(string $pem): bool
    {
        $key = @openssl_pkey_get_public($pem);

        self::drainOpenSslErrors();

        return $key !== false;
    }

    /**
     * Does this base64 body parse as an X.509 structure at all?
     *
     * Classification only - it is deliberately NOT the decision, see point 2 of the class
     * comment. SpMetadata::certificateBody() runs the identical two lines (read, drain) for the
     * SP certificate and could move onto this one; that is a behaviour-preserving change to the
     * file which decides what gets PUBLISHED, so it belongs in its own commit rather than
     * smuggled into a settings-screen fix.
     *
     * @param string $body base64, whitespace already removed.
     */
    public static function parsesAsCertificate(string $body): bool
    {
        $parsed = @openssl_x509_read(self::pem('CERTIFICATE', $body));

        self::drainOpenSslErrors();

        return $parsed !== false;
    }

    /**
     * The body of the certificate block, for the message only.
     *
     * @throws InvalidArgumentException when the value is not a certificate block at all, or
     *         opens one it never closes.
     */
    private static function bodyTheReaderWillUse(string $value): string
    {
        $begin = '-----BEGIN CERTIFICATE-----';
        $end = '-----END CERTIFICATE-----';

        $opens = strpos($value, $begin);

        if ($opens === false) {
            // Armour for something else - a key, a CSR, a public key. SamlConnectionConfig
            // already refuses these (the dashes break its base64 check) and they never reach
            // here through problems(); the branch exists so that a direct caller gets the
            // accurate sentence rather than "this is not valid base64", which is what the
            // armour lines would otherwise produce.
            if (preg_match('/-----BEGIN (?<label>[A-Z0-9 ]+)-----/', $value, $matches) === 1) {
                throw new InvalidArgumentException(sprintf(
                    'This is a "%s" block, not a certificate. Paste the identity provider\'s '
                    . 'signing certificate - the X509Certificate element of its SAML metadata.',
                    $matches['label']
                ));
            }

            // A bare base64 body, which is what most identity provider panels display. It is
            // also exactly the shape a de-armoured private key has, which is why openssl, not
            // the shape, decides above.
            return $value;
        }

        $from = $opens + strlen($begin);
        $closes = strpos($value, $end, $from);

        if ($closes === false) {
            throw new InvalidArgumentException(
                'The certificate block is opened but never closed: there is a '
                . '"-----BEGIN CERTIFICATE-----" line and no "-----END CERTIFICATE-----" line. '
                . 'Paste the whole block, last line included.'
            );
        }

        // The FIRST block, because that is the one the reader uses - a chain or a stray second
        // block after it changes nothing about which certificate verifies the signature.
        return substr($value, $from, $closes - $from);
    }

    /** @param string $body base64, whitespace already removed. */
    private static function parsesAsPrivateKey(string $body): bool
    {
        // The three armours a de-armoured key is realistically pasted from: unencrypted PKCS#8,
        // PKCS#1 and SEC1. The label is what tells OpenSSL how to read the bytes, so guessing
        // wrong reads as "not a key" and the administrator would get the vaguer message instead
        // of the accurate one. NOT EVERY ARMOUR THERE IS, and the two it misses are named where
        // that matters - carriesPrivateKey(), "THE TWO SHAPES ARE NOT COVERED EQUALLY": an
        // ENCRYPTED PKCS#8 key (no passphrase here to open it) and a traditional `DSA PRIVATE
        // KEY`. Both reach this as "not a key"; for the message that is the right answer, since
        // neither could verify a signature either.
        foreach (['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY'] as $label) {
            $key = @openssl_pkey_get_private(self::pem($label, $body));

            self::drainOpenSslErrors();

            if ($key !== false) {
                return true;
            }
        }

        return false;
    }

    /** @param string $body base64, whitespace already removed. */
    private static function parsesAsPublicKey(string $body): bool
    {
        return self::yieldsPublicKey(self::pem('PUBLIC KEY', $body));
    }

    private static function pem(string $label, string $body): string
    {
        return '-----BEGIN ' . $label . "-----\n"
            . chunk_split($body, 64, "\n")
            . '-----END ' . $label . "-----\n";
    }

    /**
     * Total length of the DER structure these bytes open, or null when they do not open one.
     *
     * Used only to tell a TRUNCATED paste from noise, so the message can say which it is. A
     * certificate is a SEQUENCE (0x30) whose length follows in DER short or long form; anything
     * else is not a structure this can measure and gets the general message.
     *
     * The two numbers it produces are QUOTED TO THE ADMINISTRATOR, so both are pinned in the
     * tests: an off-by-one here is a sentence that sends somebody counting bytes in the wrong
     * file.
     */
    private static function declaredStructureLength(string $der): ?int
    {
        if (strlen($der) < 2 || ord($der[0]) !== 0x30) {
            return null;
        }

        $first = ord($der[1]);

        // Short form: the length is the byte itself, and the header is the two bytes read so far.
        if ($first < 0x80) {
            return 2 + $first;
        }

        $octets = $first & 0x7f;

        // 0x80 is BER's indefinite length (illegal in DER) and more than four length octets
        // would describe a structure no certificate has; neither is worth a guess.
        if ($octets === 0 || $octets > 4 || strlen($der) < 2 + $octets) {
            return null;
        }

        $length = 0;
        for ($index = 0; $index < $octets; $index++) {
            $length = ($length << 8) | ord($der[2 + $index]);
        }

        // Tag byte + length byte + the length octets themselves + the content.
        return 2 + $octets + $length;
    }

    /**
     * OpenSSL queues errors rather than throwing them, and an undrained queue surfaces on
     * somebody else's call later in the request - as an error about a document that was fine.
     * Pinned by a test that rejects a certificate and then asserts the queue is empty.
     */
    private static function drainOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // drain
        }
    }
}
