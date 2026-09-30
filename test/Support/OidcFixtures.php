<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Firebase\JWT\JWT;
use RuntimeException;

/**
 * Builds real, really-signed OIDC material for the reader tests.
 *
 * Key pairs are generated in-process on first use - two RSA keys for the provider (one current,
 * one it "rotates" to), one P-256 EC key, and one unrelated RSA key that plays the attacker.
 * Nothing here is committed and nothing expires. They are TEST keys: they sign fixtures inside
 * this test run and nothing else.
 *
 * The hostile fixtures are assembled by hand (string concatenation, base64url by hand). That is
 * acceptable here and only here: the fixture is the attacker's document, and an attacker is not
 * bound by "use the library". Production code parses with the library, per contract A2.
 */
final class OidcFixtures
{
    public const ISSUER = 'https://idp.example.test/realms/keyway';
    public const CLIENT_ID = 'keyway-craft';
    public const CLIENT_SECRET = 'test-client-secret';
    public const REDIRECT_URI = 'https://craft.example.test/sso/oidc/callback';

    public const KID_RSA = 'rsa-sig-1';
    public const KID_RSA_ROTATED = 'rsa-sig-2';
    public const KID_EC = 'ec-sig-1';
    public const KID_OCT = 'oct-hmac-1';
    public const KID_ENC = 'rsa-enc-1';

    /** The secret an `oct` entry in a public JWKS would publish to the world. */
    public const OCT_SECRET = 'this-symmetric-secret-is-published-in-the-jwks-for-everyone';

    /** @var array<string, array{private: string, public: string, details: array<mixed>}> */
    private static array $keys = [];

    public static function discoveryUrl(): string
    {
        return self::ISSUER . '/.well-known/openid-configuration';
    }

    public static function authorizationEndpoint(): string
    {
        return self::ISSUER . '/protocol/openid-connect/auth';
    }

    public static function tokenEndpoint(): string
    {
        return self::ISSUER . '/protocol/openid-connect/token';
    }

    public static function jwksUri(): string
    {
        return self::ISSUER . '/protocol/openid-connect/certs';
    }

    public static function userinfoEndpoint(): string
    {
        return self::ISSUER . '/protocol/openid-connect/userinfo';
    }

    /**
     * @param array<string, mixed> $overrides Null value removes the field.
     * @return array<string, mixed>
     */
    public static function discovery(array $overrides = []): array
    {
        $document = [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::authorizationEndpoint(),
            'token_endpoint' => self::tokenEndpoint(),
            'jwks_uri' => self::jwksUri(),
            'userinfo_endpoint' => self::userinfoEndpoint(),
            'end_session_endpoint' => self::ISSUER . '/protocol/openid-connect/logout',
            // Exactly what the Keycloak test realm advertises, HS* and all.
            'id_token_signing_alg_values_supported' => [
                'PS384', 'RS384', 'EdDSA', 'ES384', 'HS256', 'HS512', 'ES256', 'RS256',
                'HS384', 'ES512', 'PS256', 'PS512', 'RS512',
            ],
            'code_challenge_methods_supported' => ['plain', 'S256'],
        ];

        foreach ($overrides as $name => $value) {
            if ($value === null) {
                unset($document[$name]);
                continue;
            }

            $document[$name] = $value;
        }

        return $document;
    }

    /**
     * @param list<string> $names Any of: rsa, rotated, ec, oct, enc.
     * @return array<string, mixed>
     */
    public static function jwks(array $names = ['rsa']): array
    {
        $keys = [];

        foreach ($names as $name) {
            $keys[] = match ($name) {
                'rsa' => self::rsaJwk('rsa', self::KID_RSA),
                'rotated' => self::rsaJwk('rotated', self::KID_RSA_ROTATED),
                'foreign' => self::rsaJwk('foreign', self::KID_RSA),
                'ec' => self::ecJwk(),
                'oct' => [
                    'kty' => 'oct',
                    'kid' => self::KID_OCT,
                    'alg' => 'HS256',
                    'use' => 'sig',
                    'k' => self::base64Url(self::OCT_SECRET),
                ],
                'enc' => self::rsaJwk('rotated', self::KID_ENC) + [],
                default => throw new RuntimeException('Unknown fixture key ' . $name),
            };

            if ($name === 'enc') {
                // `use: enc` with an otherwise perfectly acceptable `alg: RS256`. The point is to
                // isolate the `use` filter: labelled RSA-OAEP it would already fall out on the
                // algorithm allow list and the `use` check would have no proof of its own.
                $last = count($keys) - 1;
                $keys[$last]['use'] = 'enc';
                $keys[$last]['alg'] = 'RS256';
            }
        }

        return ['keys' => $keys];
    }

    /**
     * A signed id token. `alg` and `kid` default to the provider's current RSA key.
     *
     * @param array<string, mixed> $claims   Merged over the defaults; null removes a claim.
     *                                       Must carry `__now`; see claims().
     * @param array<string, mixed> $options  alg, kid, signingKey (fixture key name).
     */
    public static function idToken(array $claims, array $options = []): string
    {
        $algorithm = (string)($options['alg'] ?? 'RS256');
        $keyName = (string)($options['signingKey'] ?? ($algorithm === 'ES256' ? 'ec' : 'rsa'));
        $kid = array_key_exists('kid', $options) ? $options['kid'] : self::defaultKid($keyName);

        $payload = self::claims($claims);

        $material = match (true) {
            str_starts_with($algorithm, 'HS') => (string)($options['hmacKey'] ?? self::publicKey($keyName)),
            default => self::privateKey($keyName),
        };

        return JWT::encode($payload, $material, $algorithm, $kid === null ? null : (string)$kid);
    }

    /**
     * A token assembled by hand: any header, any claims, any signature (empty by default).
     *
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public static function rawToken(array $header, array $claims, string $signature = ''): string
    {
        return self::base64Url((string)json_encode($header))
            . '.' . self::base64Url((string)json_encode(self::claims($claims)))
            . '.' . ($signature === '' ? '' : self::base64Url($signature));
    }

    /**
     * The default, valid claim set. `nonce`, `exp` and `iat` are almost always overridden by the
     * caller, because they depend on the login under test.
     *
     * `__now` IS REQUIRED and there is deliberately no fallback to time(). A fixture that reads
     * the wall clock on its own is a second, unsynchronised clock in a suite whose readers all
     * run on a FixedClock: the two can straddle a second boundary and produce a red that no
     * later run reproduces. Making the caller state the timestamp removes the class of bug
     * instead of one instance of it - every case already has the clock it pinned its reader to.
     *
     * @param array<string, mixed> $overrides Must carry `__now`; null value removes a claim.
     * @return array<string, mixed>
     */
    public static function claims(array $overrides): array
    {
        if (!isset($overrides['__now'])) {
            throw new RuntimeException(
                'OidcFixtures::claims() needs an explicit __now: pass the timestamp the reader '
                . 'under test is pinned to, never the wall clock.'
            );
        }

        $now = (int)$overrides['__now'];
        unset($overrides['__now']);

        $claims = [
            'iss' => self::ISSUER,
            'sub' => 'f:9d4e:test.user',
            'aud' => self::CLIENT_ID,
            'exp' => $now + 300,
            'iat' => $now,
            'auth_time' => $now,
            'jti' => 'jti-' . substr(hash('sha256', (string)$now), 0, 16),
            'typ' => 'ID',
            'sid' => 'session-index-1',
            'preferred_username' => 'test.user',
            'email' => 'test.user@example.test',
            // Mixed case on purpose: contract A7 says names come back exactly as sent.
            'Groups' => ['craft-admins', 'craft-editors'],
        ];

        foreach ($overrides as $name => $value) {
            if ($value === null) {
                unset($claims[$name]);
                continue;
            }

            $claims[$name] = $value;
        }

        return $claims;
    }

    /**
     * OpenID Connect Core 1.0 section 3.1.3.6: left-most half of the SHA-256 digest, base64url.
     */
    public static function tokenHash(string $value): string
    {
        $digest = hash('sha256', $value, true);

        return self::base64Url(substr($digest, 0, intdiv(strlen($digest), 2)));
    }

    public static function privateKey(string $name = 'rsa'): string
    {
        return self::key($name)['private'];
    }

    public static function publicKey(string $name = 'rsa'): string
    {
        return self::key($name)['public'];
    }

    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * One P-256 coordinate, base64url, RFC 7518 section 6.2.1.2: ALWAYS the full 32 octets.
     *
     * Public so a test can feed it a short coordinate directly. Without that, the padding is only
     * exercised when OpenSSL happens to hand back a truncated one (~1% of generated keys), which
     * is precisely how the original defect hid: a guard that only fires 1% of the time is not a
     * guard, it is the same lottery with extra steps.
     */
    public static function ecCoordinate(string $raw): string
    {
        return self::base64Url(str_pad($raw, 32, "\0", STR_PAD_LEFT));
    }

    private static function defaultKid(string $keyName): string
    {
        return match ($keyName) {
            'ec' => self::KID_EC,
            'rotated' => self::KID_RSA_ROTATED,
            default => self::KID_RSA,
        };
    }

    /**
     * @return array<string, mixed>
     */
    private static function rsaJwk(string $name, string $kid): array
    {
        $details = self::key($name)['details'];

        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => self::base64Url((string)$details['rsa']['n']),
            'e' => self::base64Url((string)$details['rsa']['e']),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function ecJwk(): array
    {
        $details = self::key('ec')['details'];

        return [
            'kty' => 'EC',
            'kid' => self::KID_EC,
            'alg' => 'ES256',
            'use' => 'sig',
            'crv' => 'P-256',
            // LEFT-PADDED TO THE CURVE SIZE, and this is a real bug fix rather than tidiness.
            // OpenSSL hands back the coordinate as a big-endian integer with leading zero bytes
            // dropped, so roughly 1 in 100 freshly generated P-256 keys yields a 31-byte x or y
            // (measured: 4 in 400). RFC 7518 section 6.2.1.2 requires the full 32 bytes, so the
            // short ones produced a JWK that could not verify its own token - and since the key
            // is generated per run, the suite failed at random about once every hundred
            // executions, in an OIDC signature case that reads exactly like a real sign-in bug.
            // A real identity provider pads; only this fixture did not.
            'x' => self::ecCoordinate((string)$details['ec']['x']),
            'y' => self::ecCoordinate((string)$details['ec']['y']),
        ];
    }

    /**
     * @return array{private: string, public: string, details: array<mixed>}
     */
    private static function key(string $name): array
    {
        if (isset(self::$keys[$name])) {
            return self::$keys[$name];
        }

        $config = $name === 'ec'
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];

        $pkey = openssl_pkey_new($config);
        if ($pkey === false) {
            throw new RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }

        openssl_pkey_export($pkey, $private);
        $details = openssl_pkey_get_details($pkey);

        if (!is_array($details)) {
            throw new RuntimeException('openssl_pkey_get_details failed.');
        }

        return self::$keys[$name] = [
            'private' => (string)$private,
            'public' => (string)$details['key'],
            'details' => $details,
        ];
    }
}
