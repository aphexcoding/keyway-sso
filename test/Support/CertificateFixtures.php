<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

/**
 * One real X.509 certificate, its matching private key, and the bad pastes built out of the two.
 *
 * Everything here is PARSED AND NEVER SIGNED WITH, which is what lets the bytes be pinned. The
 * settings screen has to tell a certificate from a de-armoured private key, from a chain, from a
 * certificate with a key stuck to it and from a copy that stopped halfway, and shape alone can
 * tell none of them apart - so each of those pastes is a named fixture below rather than
 * something a test assembles inline and gets subtly wrong.
 *
 * WHY PINNED BYTES RATHER THAN A KEY PAIR GENERATED PER RUN. SamlFixtures generates its pair in
 * process, and that is right there: those tests SIGN documents, so the key has to be live. Here
 * nothing is signed - the values are only ever parsed - and pinned bytes buy three things the
 * generated ones cannot:
 *
 *  - the suite keeps running where `openssl_csr_new()` cannot (no openssl.cnf, ext-openssl
 *    absent). settings_translator_test is the file that deliberately needs neither a vendor
 *    directory nor a CMS, and a fixture that fatals on a bare host would take it down with it;
 *  - a failure names the same bytes on every machine, instead of a serial number that changes
 *    every run;
 *  - it costs nothing, on a suite that finishes in under a second.
 *
 * A freshly generated certificate is still exercised, in settings_translator_test, so no rule
 * here can pass "just for these bytes": the case there builds one with openssl_pkey_new() +
 * openssl_csr_new() + openssl_csr_sign() through SamlFixtures::cert(), and runs it through the
 * same gate both armoured and de-armoured.
 *
 * Generated once with `openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=keyway-sso-test`.
 * IT SIGNS NOTHING AND GUARDS NOTHING - the private key below is published in this repository on
 * purpose, because a test that proves a private key is REFUSED, or that one pasted next to the
 * certificate is WARNED ABOUT, needs a real private key to refuse and to warn about. Never reuse
 * either value anywhere.
 */
final class CertificateFixtures
{
    /** The certificate, base64, no armour and no line breaks. */
    private const CERTIFICATE_BODY =
        'MIIDFTCCAf2gAwIBAgIUKjyoDqnhHPBCMMQ02Qh2HOzcx4wwDQYJKoZIhvcNAQELBQAwGjEY'
        . 'MBYGA1UEAwwPa2V5d2F5LXNzby10ZXN0MB4XDTI2MDkxNTAxMDIxMFoXDTM2MDkxMjAxMDIx'
        . 'MFowGjEYMBYGA1UEAwwPa2V5d2F5LXNzby10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'
        . 'MIIBCgKCAQEAlUqdMyGZ8ypLB5wTQoseOtdkoHfkfPO5RKlDZL3YAKcIfeNH9RLcoTu8qES1'
        . 'Joiw9vLJZzjIiFNhEW88ny/ULMDx6sG9CTUVBidVdt1XMQmrKXQP0hX+sxFno6HAN9WZpQzr'
        . 'bMpetAIyn14vFw29UiGcFY5/ASXKI4tPBOhnBlo6cPZ2vH/E7e5n6NgGKQDdAL9cJKKrobTc'
        . '29x5nT2VG0v7M6JwYhojYcdt2hMOX+QIMQSw+TQ+XVRXSUjaMbnuS5wrDbEWNHQdivsCdQ2h'
        . 'dxqaLmrMRcIMNu6ui9HDLnPgVBW0Cden6gpWU59itEzt9AbsryY3jLx6CMJcpzEzDQIDAQAB'
        . 'o1MwUTAdBgNVHQ4EFgQUmwHB+iqQt28/r0CdElNdXxKH7GMwHwYDVR0jBBgwFoAUmwHB+iqQ'
        . 't28/r0CdElNdXxKH7GMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAfUeV'
        . '7UL6zsEeB7PlSrq6cpFiTfFiyC1yZ7dDHDjs+m/iLk0K4/Jtv95e5Ri0VhsvbNZ2Ht/9DSph'
        . 'HAGiboKnzn7oCPXmbUPvjgaSR979ZOCSPiiZe+8zOoZstCX06hiPN8pNe7+GAUn6PqC32LPf'
        . 'S8jQRbQBa4sOgniFl3BHG1r4RiazPB1S7BaTZfJ1q5fRFUYxIOQmHm+Pot4P/xV+tn2B6RMb'
        . 'pm3CCC1LU+lJaoj2nE3lDAkafvSbX7Tg6xHvt1CN5N7yavySKImOt+zy4oPL6FDGX2qzAHe+'
        . 'f4psN1CSWNdGz2MnWtrKOaw6xlVPPWoVeoMcaOaZfci/p8E6zg==';

    /** The matching private key (PKCS#8), base64. Never a certificate, and never acceptable as one. */
    private const PRIVATE_KEY_BODY =
        'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCVSp0zIZnzKksHnBNCix46'
        . '12Sgd+R887lEqUNkvdgApwh940f1EtyhO7yoRLUmiLD28slnOMiIU2ERbzyfL9QswPHqwb0J'
        . 'NRUGJ1V23VcxCaspdA/SFf6zEWejocA31ZmlDOtsyl60AjKfXi8XDb1SIZwVjn8BJcoji08E'
        . '6GcGWjpw9na8f8Tt7mfo2AYpAN0Av1wkoquhtNzb3HmdPZUbS/szonBiGiNhx23aEw5f5Agx'
        . 'BLD5ND5dVFdJSNoxue5LnCsNsRY0dB2K+wJ1DaF3GpouasxFwgw27q6L0cMuc+BUFbQJ16fq'
        . 'ClZTn2K0TO30BuyvJjeMvHoIwlynMTMNAgMBAAECggEAIt9Rdgqgx+S2rvndo9sUPiFnH3ax'
        . '+CAERE4XcHZJ+OkLekB3Y/86ay0lhda6y9v9HkobEpH4gaOcVnK54eNNuAB/4drMedSc6xmQ'
        . 'BJpyTgGYqi+yrFu36YMkxtu3JzOtVpj8eyaQVZL32TMqY8OxV/iC2aQ19YIqw/+7/wT8X8aj'
        . 'OJeVzle40p0/w8Vdmd4hz4K8ru47roynJBL67gbZgE9n9fNVzERklGDbXEApi8zoV0k/Ku4M'
        . 'eOrJLHUHtaxdGm8e6B4k3QWFXvxGw22wNuRD0/cDDjYFlXYVt77g+1W6+1Dyw/fvAjB6twtp'
        . 'dYOM+QV9EkolekzECB9NRQgbbwKBgQDRdQQln/blkfx7689ZmVanv/yDgNj5KoJEjHBxJtcG'
        . 'Cv3pH/tlmBBVrbruadC+RsHmvPVO2l3NKZ/OTKAKzFQ2FmOB0ofUXB9rOacnbV080jlNKd+F'
        . 'xRaA/Fpwf8SNU0P3W2bArpfKDboThYSAWoR+Ao2YtEUnz3PivENLPWNDJwKBgQC2dxIonDZX'
        . '0NXyXARPw0i4SBW6r8ND7pWBuxKVRI/sDDwJ+hyoSD/83YFrT5c+IVYrYigs7kvaqhsxyD0U'
        . 'WVBeTS5ngbryLNdT98iAON8UpCLiPT7Cm07g1THVnc4rk5XQJ3MfqAdRsEY+4hpw42ChkRfV'
        . 'O9XAoAGfXpFsS7joqwKBgF5MYUaTIvOt6s7blilPeIzjSUrm+kgLFETKOWEnzEyDLFcFOAhA'
        . 'ErKQGYV2jCzt7CP2VDZg5zQTlkepha/2177WC4yJ/O7lXpvGg/OjMAPO3U9ZF7HAzmXZttnJ'
        . 'G/NIVmQJeVQsBlhIH8rkJIgouFeGzLrABhZrNlAQ0/cOtx6nAoGAeIBAZMNtfCc18/3i9w4/'
        . '6zvn5ceHzEg3QlraVevWpIwb5nbgEB7O618ZxlXkyypW7wW/BJVHURyAIytbcyHc2rpcCA17'
        . '+c21UwXTyyJD6SzQwNqzpO/Octs5MxspekvYZ4R2GhTs6Hzil0rZLW5sdacNt0vxyWmiSK66'
        . 'mWuUrUsCgYEAoqiWScy15QyXbg2waWoNg1WWeNogITT39jA7L06x869o77/T0DwlLG6GcNep'
        . 'Es5wxjmiuP8bwjMgzN2gHj9bkmIfXzuJCdz12Ub8XU/bMsf9b6iJTPMRe8fjBrx5qhXDugbd'
        . 'Z45jbtZBQW3u9qOWfYiZoi8kCCjURRfH61eBe9w=';

    private function __construct()
    {
    }

    /** The bare base64 body, which is what most identity-provider panels display. */
    public static function body(): string
    {
        return self::CERTIFICATE_BODY;
    }

    /** The same certificate as a PEM block, which is what the rest of them hand out. */
    public static function pem(): string
    {
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(self::CERTIFICATE_BODY, 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    /** The private key body, de-armoured: the paste that used to save cleanly and fail at login. */
    public static function privateKeyBody(): string
    {
        return self::PRIVATE_KEY_BODY;
    }

    /**
     * The same certificate with one bit flipped inside the public key, still a well-formed
     * X.509 structure and no longer usable.
     *
     * THE OFFSET AND THE BIT ARE PINNED, not searched for at run time: this value exists to
     * pin the difference between `openssl_x509_read()` (which accepts it) and
     * `openssl_pkey_get_public()` (which does not, and is what both SAML readers really call),
     * so it has to be the same value on every machine. Found once by walking every single-bit
     * mutation of the certificate above and taking the first where the two disagree.
     */
    public static function damagedBody(): string
    {
        $der = (string)base64_decode(self::CERTIFICATE_BODY, true);
        $der[145] = chr(ord($der[145]) ^ 0x02);

        return base64_encode($der);
    }

    /**
     * The certificate as a PEM block with one character OpenSSL's base64 decoder will not skip.
     *
     * MEASURED: spaces, tabs, CR and LF are skipped inside the body; a vertical tab (0x0B) and
     * a form feed (0x0C) are not. Those two are what a copy out of a PDF or a word processor
     * carries, and inside an armoured block nothing strips them before the reader sees them.
     */
    public static function pemWithUnskippableWhitespace(): string
    {
        $body = substr(self::CERTIFICATE_BODY, 0, 100) . "\x0b" . substr(self::CERTIFICATE_BODY, 100);

        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split($body, 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    /**
     * The first $characters of the certificate body: a paste that was cut short.
     *
     * Still legal base64 (the default is a multiple of four) and still long enough to clear the
     * "this is not a fingerprint" floor, so it reaches the check under test instead of being
     * refused one layer earlier.
     */
    public static function truncatedBody(int $characters = 400): string
    {
        return substr(self::CERTIFICATE_BODY, 0, $characters);
    }

    /** The private key as a PEM block: the shape an identity-provider export hands over. */
    public static function privateKeyPem(): string
    {
        return self::block('PRIVATE KEY', self::PRIVATE_KEY_BODY);
    }

    /**
     * Certificate first, private key after it - one field, two PEM blocks.
     *
     * PINS A VALUE THAT MUST SAVE AND MUST WARN, both halves at once. It saves because
     * PEM_read_bio skips the blocks it was not asked for, so `openssl_pkey_get_public()` finds
     * the certificate and the login works (measured: it does); it warns because the key is now
     * in the settings table whether the login cares or not. Refusing it would block a save on a
     * configuration that signs in, which is the failure the save-time gate exists to avoid.
     */
    public static function pemWithPrivateKeyAppended(): string
    {
        return self::pem() . self::privateKeyPem();
    }

    /**
     * The same paste with the blocks the other way round: key first, certificate after.
     *
     * A SEPARATE FIXTURE BECAUSE THE ORDER IS NOT COSMETIC. It is the order an export written
     * "key then cert" produces, it still saves (openssl walks past the key block to reach the
     * certificate), and a detector that only looked after the certificate block would miss it -
     * a silent screen on exactly the paste that leaks a key.
     */
    public static function pemWithPrivateKeyFirst(): string
    {
        return self::privateKeyPem() . self::pem();
    }

    /**
     * `base64(DER(certificate) . DER(private key))`: the same mistake with the armour stripped.
     *
     * PINS THE SHAPE NOTHING BUT OPENSSL CAN READ. Two DER structures in one blob look exactly
     * like one long certificate to every shape rule we have, and the readers take the first
     * structure and succeed - so this value used to save, work, and quietly carry a private key
     * into project config with nobody told. 793 bytes of certificate, then 1217 of key.
     */
    public static function bodyWithPrivateKeyAppended(): string
    {
        return base64_encode(self::der(self::CERTIFICATE_BODY) . self::der(self::PRIVATE_KEY_BODY));
    }

    /**
     * `base64(DER(certificate) . DER(certificate))`: a chain, de-armoured.
     *
     * THE FALSE-POSITIVE GUARD, and the reason the warning cannot simply count structures. This
     * is the same shape as bodyWithPrivateKeyAppended() - two DER structures in one blob - and
     * it is a legitimate paste that must stay silent. The second copy stands in for an
     * intermediate certificate; what matters to the test is that it is a certificate and not a
     * key, which is the only thing telling the two pastes apart.
     */
    public static function chainBody(): string
    {
        return base64_encode(self::der(self::CERTIFICATE_BODY) . self::der(self::CERTIFICATE_BODY));
    }

    /** The same chain armoured: two CERTIFICATE blocks, and still nothing to warn about. */
    public static function chainPem(): string
    {
        return self::pem() . self::pem();
    }

    private static function der(string $body): string
    {
        return (string)base64_decode($body, true);
    }

    private static function block(string $label, string $body): string
    {
        return '-----BEGIN ' . $label . "-----\n"
            . chunk_split($body, 64, "\n")
            . '-----END ' . $label . "-----\n";
    }
}
