<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\HttpClientInterface;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Core\Port\RejectionDetailInterface;
use Keyway\Sso\Core\Port\ReplayGuardInterface;
use Keyway\Sso\Core\State\StateStore;
use stdClass;
use Throwable;

/**
 * OIDC implementation of IdentityReaderInterface (contract sections A and C).
 *
 * Division of labour, stated explicitly because the contract says a check that is merely
 * "configured in the library" does not count as done:
 *
 *  DELEGATED to firebase/php-jwt 7.1.0 (A2 - no hand-written protocol crypto):
 *    - signature verification and JWT decoding: JWT::decode(), with a single Key that THIS class
 *      selected by `kid` beforehand;
 *    - JWK to key material: JWK::parseKeySet(), through JwksKeyStore.
 *
 *  BUILT HERE, because the library does not give the guarantee the contract asks for:
 *    - C1/C2/C3 the allow list. JWT::$supported_algs (vendor/firebase/php-jwt/src/JWT.php:57-69)
 *      contains HS256, HS384, HS512, ES256K, PS256 and EdDSA, and it is a PUBLIC STATIC array
 *      any code in the process can edit. decode() does reject a token whose `alg` disagrees with
 *      the algorithm on the Key it was handed (JWT.php:154), but that is a key/header agreement
 *      check, not a policy: hand it an HS256 Key - which JWK::parseKey() will happily build from
 *      an `oct` entry in a public JWKS (JWK.php:187-192) - and HS256 verifies. So the header is
 *      checked against a fixed list here, BEFORE any key is fetched and before any crypto runs,
 *      and JwksKeyStore applies the same list to the key material.
 *    - C5 the `kid` rule. decode() ignores `kid` entirely when it is given a single Key
 *      (JWT.php:483-485) and, with a CachedKeySet, turns an unknown `kid` into an unrate-limited
 *      HTTP fetch (JWT.php:491-493, CachedKeySet.php:84). Key selection happens in JwksKeyStore
 *      instead, with a rate-limited one-refresh-per-kid rule.
 *    - C6/A4 time and claims. decode() checks `exp`/`nbf`/`iat` against \time() and the global
 *      JWT::$leeway (JWT.php:43, 105, 168-193) - process-global mutable state, and no
 *      ClockInterface in sight. Those globals are pinned to our clock and our skew for the
 *      duration of the call and restored afterwards, and then every time claim is checked AGAIN
 *      here, authoritatively. `aud`, `azp` and `sub` the library does not look at at all.
 *    - C7 `nonce`, C8 PKCE, C9 `at_hash`/`c_hash`, C10 userinfo, C11 `state`: none of them exist
 *      in firebase/php-jwt, which is a JWT library and not an OIDC client.
 *
 * league/oauth2-client 2.9.0 is deliberately NOT on this path, for the same reason
 * SamlResponseReader does not call Response::isValid(): it would add a second, looser set of
 * rules next to this one. Concretely - PKCE is opt-in there and off by default
 * (AbstractProvider::getPkceMethod() returns null, src/Provider/AbstractProvider.php:399-402),
 * `plain` is a supported option (AbstractProvider.php:74, 446-447), the verifier is kept on the
 * provider object for the integrator to persist wherever they like (AbstractProvider.php:295-310),
 * there is no `nonce` anywhere in the package, no id token verification of any kind, and its
 * HTTP goes through a Guzzle client the integrator can replace, TLS options included
 * (AbstractProvider.php:151-155, 235). Everything it would have done for us is a form-encoded
 * POST, which is HttpClientInterface's job here.
 *
 * Back-channel failure mapping, so the reason codes stay honest: a call that could not be
 * completed at all (DNS, TLS, timeout, size cap) is DISCOVERY_FAILED - we never reached the
 * provider; a call that completed and returned something unusable is MALFORMED_RESPONSE.
 */
final class OidcTokenReader implements IdentityReaderInterface, RejectionDetailInterface
{
    use RejectsWithDetail;

    /**
     * How stale an `iat` may be (plus the configured skew) before the token is treated as
     * replayed from a log rather than freshly minted. Contract C6 says "not absurdly old"; this
     * is the number that makes it checkable. It matches StateStore::DEFAULT_TTL: the login state
     * would have expired by then anyway, so a longer window would only ever accept tokens no
     * live login could have produced.
     */
    public const MAX_ID_TOKEN_AGE = 300;

    private OidcConnectionConfig $config;
    private OidcDiscovery $discovery;
    private JwksKeyStore $keys;
    private ClockInterface $clock;
    private StateStore $stateStore;
    private ReplayGuardInterface $replayGuard;
    private HttpClientInterface $http;

    public function __construct(
        OidcConnectionConfig $config,
        OidcDiscovery $discovery,
        JwksKeyStore $keys,
        ClockInterface $clock,
        StateStore $stateStore,
        ReplayGuardInterface $replayGuard,
        HttpClientInterface $http,
        RejectionDetail $rejectionDetail
    ) {
        $this->config = $config;
        $this->discovery = $discovery;
        $this->keys = $keys;
        $this->clock = $clock;
        $this->stateStore = $stateStore;
        $this->replayGuard = $replayGuard;
        $this->http = $http;
        $this->rejectionDetail = $rejectionDetail;
    }

    public function protocol(): string
    {
        return 'oidc';
    }

    /**
     * @param array<string, mixed> $request Callback query parameters.
     */
    public function read(array $request): IdentityPayload
    {
        $this->rejectionDetail->clear();

        $this->rejectErrorResponse($request);
        $code = $this->requireCode($request);

        // C11 first: no state, no exchange. The authorization code is only worth redeeming if
        // it came back to a login this site started, and burning the state before the network
        // call means a replayed callback cannot even reach the token endpoint.
        [$nonce, $verifier] = $this->consumeLoginState($request);

        $tokens = $this->exchange($code, $verifier);
        $idToken = $tokens['id_token'];
        $accessToken = $tokens['access_token'];

        $claims = $this->verifyIdToken($idToken, $nonce, $code, $accessToken);

        $subject = trim((string)$claims['sub']);
        $attributes = $claims;

        if ($this->config->fetchUserinfo) {
            $attributes = $this->mergeUserinfo($attributes, $subject, $accessToken);
        }

        return new IdentityPayload(
            $subject,
            $attributes,
            $this->config->issuer,
            isset($claims['sid']) && is_string($claims['sid']) && $claims['sid'] !== ''
                ? $claims['sid']
                : null
        );
    }

    // -----------------------------------------------------------------------------------
    // Callback
    // -----------------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $request
     */
    private function rejectErrorResponse(array $request): void
    {
        $error = $request['error'] ?? null;

        if ($error === null) {
            return;
        }

        // The SAML twin of this is B4: a failed login must never be mistaken for an identity.
        $this->reject(
            IdentityReaderException::STATUS_NOT_SUCCESS,
            sprintf('Identity provider returned the error "%s".', self::errorCode($error))
        );
    }

    /**
     * An OAuth 2.0 `error` value as it may be quoted in the diagnostics record, or `(unreadable)`.
     *
     * Since 1.0.2 the detail reaches the administrator's panel, and on the callback this value
     * is whatever the visitor put in the query string - the state it rides on is one they can
     * obtain by starting a login in their own browser. RFC 6749 error codes are short tokens
     * (`invalid_client`, `access_denied`), so anything else is not quoted at all: a free-text
     * "your licence expired, go to ..." has no business appearing in a trusted screen.
     */
    private static function errorCode(mixed $value): string
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $value) === 1
            ? $value
            : '(unreadable)';
    }

    /**
     * @param array<string, mixed> $request
     */
    private function requireCode(array $request): string
    {
        $code = $request['code'] ?? null;

        if (!is_string($code) || trim($code) === '') {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Callback carries no authorization code.'
            );
        }

        return trim($code);
    }

    /**
     * C11 plus the server-side halves of C7 and C8.
     *
     * @param array<string, mixed> $request
     * @return array{0: string, 1: string} [nonce, code verifier]
     */
    private function consumeLoginState(array $request): array
    {
        $state = $request['state'] ?? null;

        if (!is_string($state) || trim($state) === '') {
            $this->reject(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Callback carries no state value, so no login of ours can be matched to it.'
            );
        }

        $validation = $this->stateStore->consume($state);

        if (!$validation->valid) {
            $this->reject(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Login state rejected: ' . $validation->reasonCode . '.'
            );
        }

        $context = $validation->context();
        $nonce = $context['nonce'] ?? '';
        $verifier = $context['code_verifier'] ?? '';

        if ($nonce === '' || $verifier === '') {
            // Fail closed. A state record without these was not written by
            // OidcAuthorizationRequest, and continuing would mean running the flow with C7 and
            // C8 silently switched off.
            $this->reject(
                IdentityReaderException::UNSOLICITED_RESPONSE,
                'Login state carries no nonce or no PKCE verifier.'
            );
        }

        return [$nonce, $verifier];
    }

    // -----------------------------------------------------------------------------------
    // Token endpoint
    // -----------------------------------------------------------------------------------

    /**
     * @return array{id_token: string, access_token: ?string}
     */
    private function exchange(string $code, string $verifier): array
    {
        $endpoint = $this->discovery->metadata()->tokenEndpoint;

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->redirectUri,
            'client_id' => $this->config->clientId,
            // C8: the verifier goes here and only here - on the back channel, once, straight
            // from server-side state.
            'code_verifier' => $verifier,
        ];

        if ($this->config->clientSecret !== null) {
            $form['client_secret'] = $this->config->clientSecret;
        }

        try {
            $response = $this->http->postForm($endpoint, $form);
        } catch (HttpTransportException $error) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                'Token endpoint could not be reached: ' . $error->getMessage()
            );
        }

        $body = json_decode($response->body, true, 32, JSON_BIGINT_AS_STRING);

        if (json_last_error() !== JSON_ERROR_NONE || !is_array($body)) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('Token endpoint answered HTTP %d with a non-JSON body.', $response->statusCode)
            );
        }

        if (!$response->isSuccessful()) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf(
                    'Token endpoint answered HTTP %d: %s.',
                    $response->statusCode,
                    array_key_exists('error', $body) ? self::errorCode($body['error']) : 'no error code'
                )
            );
        }

        $idToken = $body['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            // No id token means the provider ran a plain OAuth 2.0 flow. An access token on its
            // own says nothing verifiable about who is logging in (C10).
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Token response carries no id_token.'
            );
        }

        $accessToken = $body['access_token'] ?? null;
        $tokenType = $body['token_type'] ?? null;

        if ($accessToken !== null && (!is_string($accessToken) || $accessToken === '')) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Token response carries an unusable access_token.'
            );
        }

        if (is_string($accessToken) && is_string($tokenType)
            && strtolower($tokenType) !== 'bearer'
        ) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('Token response uses the unsupported token type "%s".', $tokenType)
            );
        }

        return [
            'id_token' => $idToken,
            'access_token' => is_string($accessToken) ? $accessToken : null,
        ];
    }

    // -----------------------------------------------------------------------------------
    // C1-C3, C5, C6, C7, C9: the id token
    // -----------------------------------------------------------------------------------

    /**
     * @return array<string, mixed> The verified claims, exactly as they arrived (A7).
     */
    private function verifyIdToken(
        string $token,
        string $expectedNonce,
        string $code,
        ?string $accessToken
    ): array {
        $segments = $this->splitToken($token);
        $header = $this->decodeHeader($segments[0]);

        $algorithm = $this->requireAllowedAlgorithm($header);

        if ($segments[2] === '') {
            // C2: an unsecured JWT. Unreachable through the allow list above (no allowed
            // algorithm produces an empty signature), and checked anyway - this is the one
            // failure that must never depend on another check having fired first.
            $this->reject(
                IdentityReaderException::SIGNATURE_INVALID,
                'Id token carries an empty signature.'
            );
        }

        $kid = $header['kid'] ?? null;
        $key = $this->keys->keyFor(is_string($kid) && $kid !== '' ? $kid : null);

        if (!hash_equals($key->getAlgorithm(), $algorithm)) {
            // The key was published for a different algorithm than the token asks for. The
            // library makes the same comparison (JWT.php:154); making it here too means the
            // rejection carries our reason code instead of a generic decode failure.
            $this->reject(
                IdentityReaderException::ALGORITHM_NOT_ALLOWED,
                sprintf(
                    'Token asks for %s but the selected key is published for %s.',
                    $algorithm,
                    $key->getAlgorithm()
                )
            );
        }

        $claims = $this->decode($token, $key);

        $this->checkIssuer($claims);
        $this->checkAudience($claims);
        $expiry = $this->checkTimes($claims);
        $subject = $this->requireSubject($claims);
        $this->checkNonce($claims, $expectedNonce);
        $this->checkTokenHash($claims, 'at_hash', $accessToken, 'access token');
        $this->checkTokenHash($claims, 'c_hash', $code, 'authorization code');
        $this->rememberJti($claims, $expiry);

        $claims['sub'] = $subject;

        return $claims;
    }

    /**
     * Splits the compact serialisation and nothing more.
     *
     * A2 forbids hand-rolled JWT parsing, and this is the one place the rule has to bend a
     * little, so it bends as little as possible: C1 requires the `alg` header to be rejected
     * "before any signature work", which is impossible if JWT::decode() is the first thing that
     * touches the token. What happens here is structural only - three segments of the base64url
     * alphabet - and the decoding itself is still the library's
     * (JWT::urlsafeB64Decode + JWT::jsonDecode). The payload is NOT decoded here: nothing reads a
     * claim before the signature has been verified.
     *
     * The alphabet check is not decoration either: JWT::urlsafeB64Decode() calls base64_decode()
     * in non-strict mode (JWT.php:432-435), so invalid characters are silently dropped rather
     * than reported.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    private function splitToken(string $token): array
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Id token is not a three-segment JWS compact serialisation.'
            );
        }

        foreach ([0, 1] as $index) {
            if (preg_match('/^[A-Za-z0-9_-]+$/', $segments[$index]) !== 1) {
                $this->reject(
                    IdentityReaderException::MALFORMED_RESPONSE,
                    'Id token segments are not base64url.'
                );
            }
        }

        if ($segments[2] !== '' && preg_match('/^[A-Za-z0-9_-]+$/', $segments[2]) !== 1) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Id token signature segment is not base64url.'
            );
        }

        return [$segments[0], $segments[1], $segments[2]];
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeHeader(string $segment): array
    {
        try {
            $decoded = JWT::jsonDecode(JWT::urlsafeB64Decode($segment));
        } catch (Throwable) {
            $decoded = null;
        }

        if (!$decoded instanceof stdClass) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Id token header is not a JSON object.'
            );
        }

        return (array)$decoded;
    }

    /**
     * C1/C2/C3. The list is a constant; the header never selects the routine.
     *
     * @param array<string, mixed> $header
     */
    private function requireAllowedAlgorithm(array $header): string
    {
        $algorithm = $header['alg'] ?? null;

        if (!is_string($algorithm)
            || !in_array($algorithm, OidcConnectionConfig::ALLOWED_ALGORITHMS, true)
        ) {
            $this->reject(
                IdentityReaderException::ALGORITHM_NOT_ALLOWED,
                sprintf(
                    'Id token is signed with "%s"; only %s are accepted.',
                    is_string($algorithm) ? $algorithm : '(no alg header)',
                    implode(' and ', OidcConnectionConfig::ALLOWED_ALGORITHMS)
                )
            );
        }

        if (isset($header['crit'])) {
            // RFC 7515 section 4.1.11: a relying party that does not understand every extension
            // listed in `crit` must reject the token. We implement no extensions.
            $this->reject(
                IdentityReaderException::ALGORITHM_NOT_ALLOWED,
                'Id token header demands critical extensions this plugin does not implement.'
            );
        }

        return $algorithm;
    }

    /**
     * The only place cryptography happens, and it is the library's.
     *
     * JWT::$timestamp and JWT::$leeway are process-global public statics (JWT.php:43, 52). They
     * are pinned to our clock and our configured skew for the duration of the call so the
     * library's own time checks agree with ours instead of using \time(), and restored in a
     * finally so nothing else in the process inherits them. Our authoritative checks run
     * afterwards regardless of what these globals said.
     *
     * @return array<string, mixed>
     */
    private function decode(string $token, Key $key): array
    {
        $previousTimestamp = JWT::$timestamp;
        $previousLeeway = JWT::$leeway;

        JWT::$timestamp = $this->clock->now();
        JWT::$leeway = $this->config->clockSkew;

        try {
            $payload = JWT::decode($token, $key);
        } catch (SignatureInvalidException $error) {
            $this->reject(
                IdentityReaderException::SIGNATURE_INVALID,
                'Id token signature does not verify against the provider key.'
            );
        } catch (ExpiredException | BeforeValidException $error) {
            $this->reject(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Id token is outside its validity window: ' . $error->getMessage()
            );
        } catch (IdentityReaderException $already) {
            throw $already;
        } catch (Throwable $error) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Id token could not be decoded: ' . $error->getMessage()
            );
        } finally {
            JWT::$timestamp = $previousTimestamp;
            JWT::$leeway = $previousLeeway;
        }

        return self::toArray($payload);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function checkIssuer(array $claims): void
    {
        $issuer = $claims['iss'] ?? null;

        if (!is_string($issuer) || !hash_equals($this->config->issuer, $issuer)) {
            $this->reject(
                IdentityReaderException::ISSUER_MISMATCH,
                sprintf(
                    'Id token issuer "%s" is not the configured issuer.',
                    is_string($issuer) ? $issuer : '(absent)'
                )
            );
        }
    }

    /**
     * C6: `aud` contains our client id, and a multi-valued `aud` additionally requires `azp`.
     *
     * The `azp` rule is not bureaucracy: a token issued for a different client that merely lists
     * us as an extra audience is a token minted in someone else's login, and `azp` is the only
     * claim that says which client the user actually authenticated to.
     *
     * @param array<string, mixed> $claims
     */
    private function checkAudience(array $claims): void
    {
        $audience = $claims['aud'] ?? null;

        if (is_string($audience)) {
            $audience = [$audience];
        }

        if (!is_array($audience) || $audience === []) {
            $this->reject(
                IdentityReaderException::AUDIENCE_MISMATCH,
                'Id token carries no audience.'
            );
        }

        $values = [];
        foreach ($audience as $value) {
            if (!is_string($value)) {
                // Filtering non-strings out here instead of rejecting would shrink the audience
                // count and, with it, silently skip the azp requirement below: `aud = [us, 12345]`
                // would look single-valued. A token whose audience we cannot fully read is a
                // token we cannot say was meant for us alone.
                $this->reject(
                    IdentityReaderException::MALFORMED_RESPONSE,
                    'Id token audience contains a value that is not a string.'
                );
            }

            $values[] = $value;
        }

        if (!in_array($this->config->clientId, $values, true)) {
            $this->reject(
                IdentityReaderException::AUDIENCE_MISMATCH,
                'Id token audience does not name this client.'
            );
        }

        if (count($values) === 1) {
            return;
        }

        $authorizedParty = $claims['azp'] ?? null;

        if (!is_string($authorizedParty) || !hash_equals($this->config->clientId, $authorizedParty)) {
            $this->reject(
                IdentityReaderException::AUDIENCE_MISMATCH,
                'Id token has several audiences and no azp naming this client.'
            );
        }
    }

    /**
     * C6/A4. Every bound is checked against ClockInterface and the configured skew.
     *
     * @param array<string, mixed> $claims
     * @return int The expiry, used as the replay retention horizon.
     */
    private function checkTimes(array $claims): int
    {
        $now = $this->clock->now();
        $skew = $this->config->clockSkew;

        $expiry = self::timestamp($claims['exp'] ?? null);
        if ($expiry === null) {
            $this->reject(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Id token carries no usable exp claim.'
            );
        }

        if ($now - $skew >= $expiry) {
            $this->reject(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Id token has expired.'
            );
        }

        $issuedAt = self::timestamp($claims['iat'] ?? null);
        if ($issuedAt === null) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Id token carries no usable iat claim.'
            );
        }

        if ($issuedAt - $skew > $now) {
            $this->reject(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Id token was issued in the future.'
            );
        }

        if ($issuedAt + self::MAX_ID_TOKEN_AGE + $skew <= $now) {
            // "Not absurdly old" made checkable: a token older than a whole login window was
            // not minted for the login that is happening now.
            $this->reject(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Id token is older than the accepted login window.'
            );
        }

        // Defence in depth, today unreachable: decode() pins JWT::$timestamp and JWT::$leeway
        // to our clock and skew, which makes the library's own nbf test (JWT.php:168,
        // floor(nbf) > timestamp + leeway) algebraically identical to this one -- so the
        // library always rejects first, with the same ASSERTION_EXPIRED code. Kept on purpose:
        // unpinning those globals, or a vendor bump that reorders the checks, would leave this
        // as the only nbf guard. Measured 2026-09-13; see the note at the matching test case in
        // test/oidc_token_reader_test.php, which documents that removing this does NOT turn it red.
        $notBefore = self::timestamp($claims['nbf'] ?? null);
        if ($notBefore !== null && $notBefore - $skew > $now) {
            $this->reject(
                IdentityReaderException::ASSERTION_EXPIRED,
                'Id token is not valid yet.'
            );
        }

        return $expiry;
    }

    /**
     * C6, the OIDC twin of B9: an empty subject silently matching an account is how "log in as
     * nobody" becomes "log in as somebody".
     *
     * @param array<string, mixed> $claims
     */
    private function requireSubject(array $claims): string
    {
        $subject = $claims['sub'] ?? null;

        if (!is_string($subject) || trim($subject) === '') {
            $this->reject(
                IdentityReaderException::SUBJECT_MISSING,
                'Id token carries no non-empty sub claim.'
            );
        }

        return trim($subject);
    }

    /**
     * C7. No configuration switch, no "the IdP does not send one" branch.
     *
     * @param array<string, mixed> $claims
     */
    private function checkNonce(array $claims, string $expected): void
    {
        $nonce = $claims['nonce'] ?? null;

        if (!is_string($nonce) || $nonce === '') {
            $this->reject(
                IdentityReaderException::NONCE_MISMATCH,
                'Id token carries no nonce, so it cannot be tied to this browser session.'
            );
        }

        if (!hash_equals($expected, $nonce)) {
            $this->reject(
                IdentityReaderException::NONCE_MISMATCH,
                'Id token nonce belongs to a different login.'
            );
        }
    }

    /**
     * C9. Present-and-wrong is a rejection, and so is present-and-uncomputable.
     *
     * The hash is the left-most half of the digest of the ASCII value, base64url encoded
     * (OpenID Connect Core 1.0, section 3.1.3.6). Both allowed algorithms use SHA-256, so the
     * digest is fixed here rather than derived from the header - deriving it from the header
     * would let the header pick the hash, which is the same mistake as letting it pick the
     * signature routine.
     *
     * @param array<string, mixed> $claims
     */
    private function checkTokenHash(
        array $claims,
        string $claim,
        ?string $value,
        string $label
    ): void {
        $expected = $claims[$claim] ?? null;

        if ($expected === null) {
            return; // "when present" - absence is allowed by the spec for at_hash.
        }

        if (!is_string($expected) || $expected === '') {
            $this->reject(
                IdentityReaderException::TOKEN_HASH_MISMATCH,
                sprintf('Id token carries an unreadable %s claim.', $claim)
            );
        }

        if ($value === null || $value === '') {
            $this->reject(
                IdentityReaderException::TOKEN_HASH_MISMATCH,
                sprintf(
                    'Id token carries %s but no %s came back to check it against.',
                    $claim,
                    $label
                )
            );
        }

        $digest = hash('sha256', $value, true);
        $half = substr($digest, 0, intdiv(strlen($digest), 2));
        $computed = rtrim(strtr(base64_encode($half), '+/', '-_'), '=');

        if (!hash_equals($computed, $expected)) {
            $this->reject(
                IdentityReaderException::TOKEN_HASH_MISMATCH,
                sprintf('Id token %s does not match the %s.', $claim, $label)
            );
        }
    }

    /**
     * A5, the OIDC counterpart of the SAML assertion id.
     *
     * @param array<string, mixed> $claims
     */
    private function rememberJti(array $claims, int $expiry): void
    {
        $jti = $claims['jti'] ?? null;

        if (!is_string($jti) || $jti === '') {
            return; // "when present"; the state token still makes the login single-use (C11).
        }

        if (!$this->replayGuard->remember($jti, $expiry + $this->config->clockSkew)) {
            $this->reject(
                IdentityReaderException::REPLAYED_ASSERTION,
                'Id token jti has already been accepted once.'
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // C10 userinfo
    // -----------------------------------------------------------------------------------

    /**
     * Extra claims, never identity. Runs only after the id token verified, and its `sub` has to
     * agree with the id token's - an unsigned JSON document served over a bearer token is not
     * evidence of who anybody is.
     *
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    private function mergeUserinfo(array $claims, string $subject, ?string $accessToken): array
    {
        $endpoint = $this->discovery->metadata()->userinfoEndpoint;

        if ($endpoint === null) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                'Userinfo is enabled for this connection but the provider advertises no '
                . 'userinfo endpoint.'
            );
        }

        if ($accessToken === null) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Userinfo is enabled but the token response carried no access token.'
            );
        }

        try {
            $response = $this->http->get($endpoint, ['Authorization' => 'Bearer ' . $accessToken]);
        } catch (HttpTransportException $error) {
            $this->reject(
                IdentityReaderException::DISCOVERY_FAILED,
                'Userinfo endpoint could not be reached: ' . $error->getMessage()
            );
        }

        if (!$response->isSuccessful()) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                sprintf('Userinfo endpoint answered with HTTP %d.', $response->statusCode)
            );
        }

        if ($response->mediaType() === 'application/jwt') {
            // A signed userinfo response is a different verification path (its own signature,
            // its own issuer and audience checks). Until that path exists, refusing is the only
            // honest answer; parsing it unverified would be the exact shortcut C10 forbids.
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Signed userinfo responses (application/jwt) are not supported by this plugin.'
            );
        }

        $document = json_decode($response->body, true, 32, JSON_BIGINT_AS_STRING);

        if (json_last_error() !== JSON_ERROR_NONE || !is_array($document) || array_is_list($document)) {
            $this->reject(
                IdentityReaderException::MALFORMED_RESPONSE,
                'Userinfo response is not a JSON object.'
            );
        }

        $userinfoSubject = $document['sub'] ?? null;

        if (!is_string($userinfoSubject) || !hash_equals($subject, $userinfoSubject)) {
            $this->reject(
                IdentityReaderException::SUBJECT_MISMATCH,
                'Userinfo describes a different subject than the verified id token.'
            );
        }

        // Id token claims win on conflict: they are the signed ones.
        foreach ($document as $name => $value) {
            if (!array_key_exists($name, $claims)) {
                $claims[$name] = $value;
            }
        }

        return $claims;
    }

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    /**
     * A7: structure only. stdClass becomes array because that is what IdentityPayload takes;
     * no name is touched, no value is trimmed, nothing is case folded.
     *
     * @return array<string, mixed>
     */
    private static function toArray(mixed $value): array
    {
        $out = [];

        foreach ((array)$value as $name => $item) {
            $out[(string)$name] = $item instanceof stdClass || is_array($item)
                ? self::toArray($item)
                : $item;
        }

        return $out;
    }

    /**
     * JSON numbers can arrive as int, float or - with JSON_BIGINT_AS_STRING - as a numeric
     * string. A non-numeric value is not "zero", it is a malformed claim, so it returns null
     * and the caller rejects.
     */
    private static function timestamp(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) || (is_string($value) && preg_match('/^-?\d+(\.\d+)?$/', $value) === 1)) {
            return (int)floor((float)$value);
        }

        return null;
    }
}
