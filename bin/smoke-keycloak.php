<?php

declare(strict_types=1);

/**
 * Live smoke check against the Keycloak test realm. NOT part of the test suite on purpose:
 * `php bin/test.php` must never need a network, a container or a credential file.
 *
 * Usage:  php bin/smoke-keycloak.php        (needs ~/.keyway/keycloak.env and the container up)
 * Exit:   0 when every check passes, 1 otherwise.
 *
 * What it proves that the unit suite cannot: that OidcDiscovery and JwksKeyStore handle a REAL
 * provider document and a REAL id token - a document written by Keycloak, not by our fixtures,
 * with Keycloak's own key rotation layout (one `use: sig` key plus one `use: enc` key) and a
 * token signed by the real realm key.
 *
 * Two honest caveats about what it does NOT prove:
 *
 *  1. The test realm speaks plain http on loopback, and OidcConnectionConfig refuses anything
 *     but https with no exception and no override - correctly, because that rule protects the
 *     root of trust. So this script fetches the documents itself with curl and rewrites the
 *     scheme in the DISCOVERY document before handing it to the code under test. The JWKS is
 *     passed through untouched. What is exercised here is the parsing, validation and key
 *     selection half of C4/C5; the transport half (https, certificate verification, no
 *     redirects) lives in CurlHttpClient and is not reachable against an http IdP by design.
 *  2. The id token is obtained with the resource owner password grant, because an authorization
 *     code needs a browser. It is a real token from a real IdP, signed by the real key, but it
 *     carries no `nonce` - which is why the full OidcTokenReader is not run here: it would
 *     refuse the token, correctly, under C7.
 */

$base = dirname(__DIR__);

require $base . '/src/autoload.php';

$vendorAutoload = $base . '/vendor/autoload.php';
if (!is_file($vendorAutoload)) {
    fwrite(STDERR, "vendor/ is absent; run composer install first.\n");
    exit(1);
}
require $vendorAutoload;

spl_autoload_register(static function (string $class) use ($base): void {
    $prefix = 'Keyway\\Sso\\Test\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $path = $base . '/test/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Support\InMemoryKeyValueCache;
use Keyway\Sso\Core\Support\SystemClock;
use Keyway\Sso\Protocol\Oidc\JwksKeyStore;
use Keyway\Sso\Protocol\Oidc\OidcConnectionConfig;
use Keyway\Sso\Protocol\Oidc\OidcDiscovery;
use Keyway\Sso\Protocol\Oidc\RejectionDetail;
use Keyway\Sso\Test\Support\FakeHttpClient;

$failures = 0;

$check = static function (string $label, callable $assertion) use (&$failures): void {
    try {
        $note = $assertion();
        printf("  ok    %s%s\n", $label, is_string($note) && $note !== '' ? ' - ' . $note : '');
    } catch (Throwable $error) {
        $failures++;
        printf("  FAIL  %s\n        %s: %s\n", $label, $error::class, $error->getMessage());
    }
};

$expect = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

// ---------------------------------------------------------------- credentials and raw fetches

$envFile = getenv('KEYWAY_KEYCLOAK_ENV') ?: (getenv('HOME') . '/.keyway/keycloak.env');
if (!is_file($envFile)) {
    fwrite(STDERR, "No credentials file at {$envFile}.\n");
    exit(1);
}

// Parsed by hand rather than with parse_ini_file(): the file is a shell env file, and the ini
// parser trips over the human comment at the top of it.
$env = [];
foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
        continue;
    }

    [$name, $value] = explode('=', $line, 2);
    $env[trim($name)] = trim(trim($value), "'\"");
}

foreach (['KEYCLOAK_BASE', 'KEYCLOAK_REALM', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET',
          'KEYCLOAK_TEST_USER', 'KEYCLOAK_TEST_PASS'] as $required) {
    if (($env[$required] ?? '') === '') {
        fwrite(STDERR, "Credentials file is missing {$required}.\n");
        exit(1);
    }
}

/**
 * Raw fetch, used only to get the documents off the loopback IdP; see caveat 1 above.
 *
 * @param array<string, string> $form
 */
$fetch = static function (string $url, ?array $form = null): string {
    $handle = curl_init($url);
    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_FOLLOWLOCATION => false,
    ]);

    if ($form !== null) {
        curl_setopt($handle, CURLOPT_POST, true);
        curl_setopt($handle, CURLOPT_POSTFIELDS, http_build_query($form));
    }

    $body = curl_exec($handle);
    $error = curl_error($handle);
    curl_close($handle);

    if (!is_string($body) || $body === '') {
        throw new RuntimeException('Fetch failed for ' . $url . ': ' . $error);
    }

    return $body;
};

$httpIssuer = rtrim($env['KEYCLOAK_BASE'], '/') . '/realms/' . $env['KEYCLOAK_REALM'];
$httpsIssuer = 'https://' . substr($httpIssuer, strlen('http://'));

printf("Keycloak smoke check\n  realm issuer: %s\n\n", $httpIssuer);

$discoveryRaw = $fetch($httpIssuer . '/.well-known/openid-configuration');
$discoveryDocument = json_decode($discoveryRaw, true);
if (!is_array($discoveryDocument)) {
    fwrite(STDERR, "Discovery document is not JSON.\n");
    exit(1);
}

$jwksRaw = $fetch((string)$discoveryDocument['jwks_uri']);
$jwksDocument = json_decode($jwksRaw, true);

// Scheme rewrite, and nothing else (caveat 1). The JWKS is untouched.
$rewritten = [];
foreach ($discoveryDocument as $name => $value) {
    $rewritten[$name] = is_string($value) ? str_replace($httpIssuer, $httpsIssuer, $value) : $value;
}

$clock = new SystemClock();
$cache = new InMemoryKeyValueCache($clock);
$http = new FakeHttpClient();
$http->onJson($httpsIssuer . '/.well-known/openid-configuration', $rewritten);
$http->onJson((string)$rewritten['jwks_uri'], $jwksDocument);

$config = new OidcConnectionConfig(
    $httpsIssuer,
    $env['OIDC_CLIENT_ID'],
    $env['OIDC_CLIENT_SECRET'],
    'https://craft.example.test/sso/oidc/callback'
);

$detail = new RejectionDetail();
$discovery = new OidcDiscovery($config, $http, $cache, $clock, $detail);
$keys = new JwksKeyStore($config, $discovery, $http, $cache, $clock, $detail);

// ------------------------------------------------------------------------------- the checks

$published = [];
foreach ($jwksDocument['keys'] ?? [] as $jwk) {
    $published[] = sprintf(
        '%s/%s/%s (kid %s)',
        $jwk['kty'] ?? '?',
        $jwk['use'] ?? '-',
        $jwk['alg'] ?? '-',
        substr((string)($jwk['kid'] ?? '?'), 0, 8)
    );
}

printf("  provider publishes %d key(s): %s\n\n", count($published), implode(', ', $published));

$signingKid = null;
$encryptionKid = null;
foreach ($jwksDocument['keys'] ?? [] as $jwk) {
    if (($jwk['use'] ?? null) === 'sig' && ($jwk['alg'] ?? null) === 'RS256') {
        $signingKid ??= (string)$jwk['kid'];
    }
    if (($jwk['use'] ?? null) === 'enc') {
        $encryptionKid ??= (string)$jwk['kid'];
    }
}

$check('C4: the real discovery document validates and names its endpoints', static function () use ($discovery, $expect, $httpsIssuer): string {
    $metadata = $discovery->metadata();
    $expect($metadata->issuer === $httpsIssuer, 'issuer mismatch');
    $expect($metadata->tokenEndpoint !== '', 'no token endpoint');
    $expect($metadata->jwksUri !== '', 'no jwks uri');

    return 'token, jwks and userinfo endpoints accepted';
});

$check('C5: the real signing kid selects an RS256 key', static function () use ($keys, $signingKid, $expect): string {
    $expect(is_string($signingKid), 'the realm publishes no RS256 signing key');
    $key = $keys->keyFor($signingKid);
    $expect($key->getAlgorithm() === 'RS256', 'selected key is not RS256');

    return 'kid ' . substr((string)$signingKid, 0, 8);
});

$check('C4: the real encryption key is never offered as a verification key', static function () use ($keys, $encryptionKid, $expect): string {
    if (!is_string($encryptionKid)) {
        return 'realm publishes no encryption key; nothing to filter';
    }

    try {
        $keys->keyFor($encryptionKid);
    } catch (IdentityReaderException $error) {
        $expect($error->reasonCode() === IdentityReaderException::KEY_NOT_FOUND, 'wrong reason code');

        return 'kid ' . substr($encryptionKid, 0, 8) . ' refused';
    }

    throw new RuntimeException('the encryption key was handed out for verification');
});

$check('C5: an invented kid is refused', static function () use ($keys, $expect): string {
    try {
        $keys->keyFor('kid-that-does-not-exist');
    } catch (IdentityReaderException $error) {
        $expect($error->reasonCode() === IdentityReaderException::KEY_NOT_FOUND, 'wrong reason code');

        return 'after one rate-limited refresh';
    }

    throw new RuntimeException('an invented kid produced a key');
});

$idToken = null;
$check('a real id token can be obtained from the realm', static function () use ($fetch, $env, $httpIssuer, &$idToken, $expect): string {
    $response = $fetch($httpIssuer . '/protocol/openid-connect/token', [
        'grant_type' => 'password',
        'client_id' => $env['OIDC_CLIENT_ID'],
        'client_secret' => $env['OIDC_CLIENT_SECRET'],
        'username' => $env['KEYCLOAK_TEST_USER'],
        'password' => $env['KEYCLOAK_TEST_PASS'],
        'scope' => 'openid profile email',
    ]);

    $decoded = json_decode($response, true);
    $expect(is_array($decoded) && isset($decoded['id_token']), 'no id_token in the token response');

    $idToken = (string)$decoded['id_token'];

    return 'password grant, ' . strlen($idToken) . ' bytes (not printed)';
});

$check('C4/C5: the real id token verifies against the key the store selected', static function () use (&$idToken, $keys, $signingKid, $expect): string {
    $expect(is_string($idToken), 'no token to verify');

    $header = json_decode((string)base64_decode(strtr(explode('.', (string)$idToken)[0], '-_', '+/')), true);
    $expect(is_array($header), 'unreadable header');
    $expect($header['alg'] === 'RS256', 'the realm signed with ' . (string)$header['alg']);

    $key = $keys->keyFor((string)$header['kid']);
    $claims = JWT::decode((string)$idToken, $key);

    $expect(isset($claims->sub) && $claims->sub !== '', 'no sub in the verified token');

    $groups = isset($claims->groups) ? implode(', ', (array)$claims->groups) : '(no groups claim)';

    return sprintf('sub %s, groups: %s', substr((string)$claims->sub, 0, 12) . '...', $groups);
});

$check('C3: the same token re-signed as HS256 with the public key does not verify', static function () use (&$idToken, $keys, $signingKid, $expect): string {
    $expect(is_string($idToken), 'no token to forge from');

    $key = $keys->keyFor((string)$signingKid);
    $material = $key->getKeyMaterial();
    $details = is_object($material) ? openssl_pkey_get_details($material) : null;
    $expect(is_array($details) && isset($details['key']), 'could not export the public key');

    $segments = explode('.', (string)$idToken);
    $claims = json_decode((string)base64_decode(strtr($segments[1], '-_', '+/')), true);
    $expect(is_array($claims), 'unreadable claims');

    // The forgery a public JWKS makes possible: sign with the PUBLIC key as an HMAC secret.
    $forged = JWT::encode($claims, (string)$details['key'], 'HS256', (string)$signingKid);

    try {
        JWT::decode($forged, new Key($material, 'RS256'));
    } catch (Throwable $error) {
        return 'refused: ' . $error->getMessage();
    }

    throw new RuntimeException('an HS256 forgery verified against the provider key');
});

printf("\n%s\n", $failures === 0 ? 'all checks passed' : $failures . ' check(s) failed');

exit($failures === 0 ? 0 : 1);
