<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use Keyway\Sso\Core\Port\AuthenticationStarterInterface;
use Keyway\Sso\Core\Port\RandomSourceInterface;
use Keyway\Sso\Core\State\StateStore;

/**
 * The start of a login: builds the authorization URL and puts the two secrets that make C7 and
 * C8 work where they belong - server-side, next to the login state.
 *
 * This is the other half of OidcTokenReader and it is why the reader can insist on a nonce at
 * all: a reader that checks a nonce nobody sent rejects every login, and a reader that skips the
 * check because "the IdP does not send one" accepts tokens minted for another session. The two
 * classes are a pair, and neither is correct alone.
 *
 * Every value here is generated fresh per login from RandomSourceInterface:
 *  - `state` - StateStore's one-shot token (C11), the only thing that ties the callback to a
 *    login this site started;
 *  - `nonce` - 32 random bytes, kept in the state record, compared against the id token (C7);
 *  - `code_verifier` - 32 random bytes, kept in the state record, sent only on the back channel;
 *    the URL carries its SHA-256 (C8). `plain` is not implemented, not configurable and not
 *    reachable: the method is a constant on the config class.
 *
 * Nothing here is built from the incoming request. The redirect URI and the scopes come from
 * settings and the endpoint comes from the validated discovery document.
 */
final class OidcAuthorizationRequest implements AuthenticationStarterInterface
{
    /** 32 bytes -> 43 base64url characters, inside PKCE's 43..128 range (RFC 7636). */
    private const SECRET_BYTES = 32;

    private OidcConnectionConfig $config;
    private OidcDiscovery $discovery;
    private StateStore $stateStore;
    private RandomSourceInterface $random;

    public function __construct(
        OidcConnectionConfig $config,
        OidcDiscovery $discovery,
        StateStore $stateStore,
        RandomSourceInterface $random
    ) {
        $this->config = $config;
        $this->discovery = $discovery;
        $this->stateStore = $stateStore;
        $this->random = $random;
    }

    /**
     * The handle this connection is known by in the login state, and the string
     * OidcTokenReader::protocol() reports. The two have to be equal or the callback cannot find
     * the reader that matches the state.
     */
    public function connection(): string
    {
        return 'oidc';
    }

    /**
     * @param array<string, string> $context Extra bookkeeping for the state record (the
     *                                       connection handle and the browser-binding decision
     *                                       that LoginFlow needs back at the callback). It is
     *                                       merged, not replaced - and it cannot overwrite the
     *                                       nonce or the verifier.
     */
    public function start(?string $returnUrl = null, array $context = []): OidcAuthorizationRedirect
    {
        $metadata = $this->discovery->metadata();

        $nonce = $this->secret();
        $verifier = $this->secret();

        // Our keys are applied last on purpose: no caller, and no future refactor that passes
        // request data through $context, can substitute its own nonce or verifier.
        $state = $this->stateStore->issue($returnUrl, array_merge($context, [
            'protocol' => 'oidc',
            'nonce' => $nonce,
            'code_verifier' => $verifier,
        ]));

        $parameters = [
            'response_type' => 'code',
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
            'scope' => $this->config->scopeParameter(),
            'state' => $state->value,
            'nonce' => $nonce,
            'code_challenge' => self::challenge($verifier),
            'code_challenge_method' => OidcConnectionConfig::CODE_CHALLENGE_METHOD,
        ];

        $separator = str_contains($metadata->authorizationEndpoint, '?') ? '&' : '?';
        $url = $metadata->authorizationEndpoint
            . $separator
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        return new OidcAuthorizationRedirect($url, $state);
    }

    private function secret(): string
    {
        return self::base64Url($this->random->bytes(self::SECRET_BYTES));
    }

    /**
     * RFC 7636 section 4.2: BASE64URL(SHA256(ASCII(code_verifier))), unpadded.
     */
    public static function challenge(string $verifier): string
    {
        return self::base64Url(hash('sha256', $verifier, true));
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
