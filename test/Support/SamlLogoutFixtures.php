<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use OneLogin\Saml2\Utils;

/**
 * Builds real, really-signed HTTP-Redirect logout messages for the SLO reader tests.
 *
 * The key pair is SamlFixtures' IdP pair, so a fixture signed here verifies against exactly the
 * certificate the connection trusts - and a fixture signed with `signWith => 'foreign'` is the
 * "somebody else's certificate" case, not a broken string.
 *
 * String assembly is acceptable here and only here: these ARE the attacker's messages, and an
 * attacker is not bound by "no string surgery". Production code builds through DOM.
 *
 * The signature is computed over the query string octets exactly as the sender would emit them
 * (SAML 2.0 Bindings 3.4.4.1), which is what lets the `reEncoded` case below exist at all: it
 * changes the percent-encoding WITHOUT touching the signature, so it is only caught by a
 * verifier that hashes the raw octets.
 */
final class SamlLogoutFixtures
{
    public const IDP_SLO_URL = 'https://idp.example.test/slo';
    public const SP_SLO_URL = 'https://craft.example.test/sso/slo';

    public const SIG_ALG_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    public const SIG_ALG_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    /**
     * An IdP-initiated LogoutRequest as a raw query string.
     *
     * `now` IS REQUIRED and there is deliberately no fallback to time(). A fixture that reads the
     * wall clock on its own is a second, unsynchronised clock in a suite whose readers all run on
     * a FixedClock, and the two can straddle a second boundary. Every caller already knows the
     * timestamp it pinned its reader to; making it say so removes the class of bug rather than
     * one instance of it.
     *
     * @param array<string, mixed> $o
     */
    public static function requestQuery(array $o): string
    {
        if (!isset($o['now'])) {
            throw new \RuntimeException(
                'SamlLogoutFixtures::requestQuery() needs an explicit now: pass the '
                . 'timestamp the reader under test is pinned to, never the wall clock.'
            );
        }

        $now = (int)$o['now'];

        $defaults = [
            'id' => '_logoutreq_' . bin2hex(random_bytes(8)),
            'issuer' => SamlFixtures::IDP_ENTITY_ID,
            'destination' => self::SP_SLO_URL,
            'nameId' => 'alice@example.test',
            'nameIdFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'sessionIndex' => '_session_1',
            'issueInstant' => $now,
            'notOnOrAfter' => false,
            'relayState' => 'back-to-the-cp',
            'doctype' => false,
            'secondNameId' => false,
            'commentInNameId' => false,
        ];

        $c = array_merge($defaults, $o);

        $destination = $c['destination'] === false
            ? ''
            : ' Destination="' . self::esc((string)$c['destination']) . '"';

        $notOnOrAfter = $c['notOnOrAfter'] === false
            ? ''
            : ' NotOnOrAfter="' . self::time((int)$c['notOnOrAfter']) . '"';

        $nameIdText = self::esc((string)$c['nameId']);
        if ($c['commentInNameId'] === true) {
            // Comment truncation (CVE-2017-11428 shape). Here the signature covers the query
            // string, so the comment cannot break it at all - only the reader's choice of
            // textContent over firstChild->nodeValue decides whether the subject stays whole.
            $cut = (int)floor(strlen($nameIdText) / 2);
            $nameIdText = substr($nameIdText, 0, $cut) . '<!---->' . substr($nameIdText, $cut);
        }

        $nameId = '<saml:NameID Format="' . self::esc((string)$c['nameIdFormat']) . '">'
            . $nameIdText . '</saml:NameID>';

        if ($c['secondNameId'] === true) {
            $nameId .= '<saml:NameID Format="' . self::esc((string)$c['nameIdFormat']) . '">'
                . 'admin@example.test</saml:NameID>';
        }

        $sessionIndex = $c['sessionIndex'] === false
            ? ''
            : '<samlp:SessionIndex>' . self::esc((string)$c['sessionIndex']) . '</samlp:SessionIndex>';

        if (($c['extraSessionIndex'] ?? false) !== false) {
            // SAML allows several, and IdPs send several.
            $sessionIndex .= '<samlp:SessionIndex>'
                . self::esc((string)$c['extraSessionIndex']) . '</samlp:SessionIndex>';
        }

        $xml = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' ID="' . self::esc((string)$c['id']) . '" Version="2.0"'
            . ' IssueInstant="' . self::time((int)$c['issueInstant']) . '"'
            . $destination . $notOnOrAfter . '>'
            . '<saml:Issuer>' . self::esc((string)$c['issuer']) . '</saml:Issuer>'
            . $nameId
            . $sessionIndex
            . '</samlp:LogoutRequest>';

        if ($c['doctype'] === true) {
            $xml = '<!DOCTYPE samlp:LogoutRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' . $xml;
        }

        if (($c['xmlOverride'] ?? false) !== false) {
            // Substituted AFTER the document is built and BEFORE it is deflated and signed, so
            // the result is a properly signed message with a body of our choosing. That order is
            // the whole point: the reader verifies the signature before it inflates anything, so
            // an unsigned oversized body would never reach the inflate ceiling at all - it would
            // be refused as signature_missing and the test would be measuring the wrong guard.
            $xml = (string)$c['xmlOverride'];
        }

        return self::query('SAMLRequest', $xml, $c);
    }

    /**
     * The IdP's answer to a LogoutRequest of ours, as a raw query string.
     *
     * `now` IS REQUIRED and there is deliberately no fallback to time(). A fixture that reads the
     * wall clock on its own is a second, unsynchronised clock in a suite whose readers all run on
     * a FixedClock, and the two can straddle a second boundary. Every caller already knows the
     * timestamp it pinned its reader to; making it say so removes the class of bug rather than
     * one instance of it.
     *
     * @param array<string, mixed> $o
     */
    public static function responseQuery(array $o): string
    {
        if (!isset($o['now'])) {
            throw new \RuntimeException(
                'SamlLogoutFixtures::responseQuery() needs an explicit now: pass the '
                . 'timestamp the reader under test is pinned to, never the wall clock.'
            );
        }

        $now = (int)$o['now'];

        $defaults = [
            'id' => '_logoutresp_' . bin2hex(random_bytes(8)),
            'issuer' => SamlFixtures::IDP_ENTITY_ID,
            'destination' => self::SP_SLO_URL,
            'inResponseTo' => '_our_request_id',
            'issueInstant' => $now,
            'status' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'secondaryStatus' => false,
            'relayState' => null,      // the suite passes the real state token
            'doctype' => false,
        ];

        $c = array_merge($defaults, $o);

        $destination = $c['destination'] === false
            ? ''
            : ' Destination="' . self::esc((string)$c['destination']) . '"';

        $inResponseTo = $c['inResponseTo'] === false
            ? ''
            : ' InResponseTo="' . self::esc((string)$c['inResponseTo']) . '"';

        $status = $c['status'] === false
            ? '<samlp:Status/>'
            : '<samlp:Status><samlp:StatusCode Value="' . self::esc((string)$c['status']) . '">'
                . ($c['secondaryStatus'] === false
                    ? ''
                    : '<samlp:StatusCode Value="' . self::esc((string)$c['secondaryStatus']) . '"/>')
                . '</samlp:StatusCode></samlp:Status>';

        $xml = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' ID="' . self::esc((string)$c['id']) . '" Version="2.0"'
            . ' IssueInstant="' . self::time((int)$c['issueInstant']) . '"'
            . $destination . $inResponseTo . '>'
            . '<saml:Issuer>' . self::esc((string)$c['issuer']) . '</saml:Issuer>'
            . $status
            . '</samlp:LogoutResponse>';

        if ($c['doctype'] === true) {
            $xml = '<!DOCTYPE samlp:LogoutResponse [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' . $xml;
        }

        return self::query('SAMLResponse', $xml, $c);
    }

    /**
     * Deflate, base64, percent-encode, sign - in that order, over the octets we emit.
     *
     * @param array<string, mixed> $c Recognised knobs: relayState (null/false to omit),
     *                                sigAlg, signWith ('foreign'), unsigned, tamperSignature,
     *                                reEncoded, duplicateMessage, rawMessageOverride.
     */
    private static function query(string $messageParam, string $xml, array $c): string
    {
        $deflated = gzdeflate($xml);

        if ($deflated === false) {
            throw new \RuntimeException('gzdeflate failed in the fixture.');
        }

        $encodedMessage = rawurlencode(base64_encode($deflated));

        if (isset($c['rawMessageOverride'])) {
            $encodedMessage = (string)$c['rawMessageOverride'];
        }

        $sigAlg = (string)($c['sigAlg'] ?? self::SIG_ALG_SHA256);

        $signed = $messageParam . '=' . $encodedMessage;

        $relayState = $c['relayState'] ?? null;
        if ($relayState !== null && $relayState !== false) {
            $signed .= '&RelayState=' . rawurlencode((string)$relayState);
        }

        $signed .= '&SigAlg=' . rawurlencode($sigAlg);

        $emitted = $signed;

        if (($c['reEncoded'] ?? false) === true) {
            // The classic bypass: same DECODED value, different octets. A verifier that
            // re-encodes what parse_str() gave it accepts this; one that hashes what arrived
            // does not. `~` is unreserved, so rawurldecode('%7E') === rawurldecode('~').
            // `-` is unreserved, so rawurldecode('%2D') === rawurldecode('-'); the SigAlg URL
            // always contains one, which makes this case deterministic rather than dependent on
            // what the base64 happened to produce.
            $emitted = str_replace('-', '%2D', $emitted);
        }

        if (($c['unsigned'] ?? false) === true) {
            return $emitted;
        }

        $key = ($c['signWith'] ?? null) === 'foreign'
            ? SamlFixtures::foreignKey()
            : SamlFixtures::privateKey();

        $algorithm = match ($sigAlg) {
            self::SIG_ALG_SHA1 => OPENSSL_ALGO_SHA1,
            default => OPENSSL_ALGO_SHA256,
        };

        $private = openssl_pkey_get_private(Utils::formatPrivateKey($key, true));

        if ($private === false) {
            throw new \RuntimeException('Fixture private key could not be loaded.');
        }

        $signature = '';
        openssl_sign($signed, $signature, $private, $algorithm);

        if (($c['tamperSignature'] ?? false) === true) {
            $signature = strrev($signature);
        }

        $query = $emitted . '&Signature=' . rawurlencode(base64_encode($signature));

        if (($c['duplicateMessage'] ?? false) === true) {
            $query .= '&' . $messageParam . '=' . $encodedMessage;
        }

        return $query;
    }

    private static function time(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }

    private static function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
