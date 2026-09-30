<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;

/**
 * Turns a protocol response into a validated IdentityPayload.
 *
 * This is the seam between the core (pure PHP, no XML, no HTTP) and the protocol layer.
 * Two implementations are planned:
 *
 *  - SamlResponseReader   - wraps onelogin/php-saml ^4.3.2 (ext-dom, ext-mbstring, ext-openssl).
 *  - OidcTokenReader      - wraps league/oauth2-client ^2.9 + firebase/php-jwt ^7.
 *
 * HARD CONTRACT for any implementation. The core assumes every item below has already
 * happened; it performs NO cryptographic verification of its own and cannot compensate for a
 * reader that skips a check. Everything an IdentityPayload carries is, from the core's point
 * of view, already proven.
 *
 * A check that is merely *configured in the library* does not count as done: the reader is
 * responsible for proving it is on (`strict = true` and friends), because every one of these
 * libraries ships a permissive default somewhere.
 *
 * ---------------------------------------------------------------------------------------
 * A. UNIVERSAL - both protocols
 * ---------------------------------------------------------------------------------------
 *
 *  A1. SIGNATURE COVERAGE, NOT "A SIGNATURE SOMEWHERE". The response is rejected unless a
 *      signature made with a configured IdP key is valid AND the data actually read out came
 *      from inside the region that signature covers. "The Response or the Assertion is signed"
 *      is NOT the contract - that phrasing is literally satisfied by XML Signature Wrapping
 *      (CVE-2017-11427 and its whole family), where the signature covers one assertion and the
 *      attributes are read from a second, injected one. See B1/B2 for how this is enforced.
 *  A2. NO HAND-WRITTEN PROTOCOL PARSING. Signature verification, canonicalisation, JWT
 *      decoding and base64 handling are delegated to the pinned, maintained libraries, because
 *      hand-rolled parsing of a signed message is the single largest source of authentication
 *      bypasses in software of this kind. No regex over XML, no string surgery on an assertion,
 *      no `explode('.')` on a JWT, no `json_decode` of a payload that has not been verified
 *      first.
 *  A3. KEY MATERIAL IS CONFIGURED, NOT DISCOVERED FROM THE MESSAGE. The verifying key comes
 *      from plugin settings (SAML: the IdP certificate - a certificate, never a fingerprint)
 *      or from the discovery document of the configured issuer (OIDC: JWKS URL). A key,
 *      certificate or JWKS URL carried inside the message itself is ignored.
 *  A4. CLOCK SKEW IS A NUMBER, NOT A FEELING. Time windows are checked against a single
 *      configured allowance of at most 120 seconds. Skew is applied symmetrically and is never
 *      "unlimited", and no implementation may disable the time checks to make a broken IdP work.
 *  A5. SINGLE USE. Every message identifier that the protocol guarantees to be unique
 *      (SAML `Assertion/@ID`, OIDC `jti` when present) is recorded for at least the length of
 *      the accepted time window, and a repeat is rejected. This is independent of, and additional
 *      to, the one-shot login state in Core\State\StateStore.
 *  A6. THE ISSUER MUST BE THE CONFIGURED ONE. Exact string comparison against the connection's
 *      configured issuer/entity id. No prefix, suffix or "starts with https://" matching.
 *  A7. ATTRIBUTES ARE RETURNED EXACTLY AS SENT - no renaming, case folding or trimming.
 *      Normalisation is the core's job (AttributeMapper) so the diagnostics panel can show what
 *      really arrived.
 *  A8. FAILURE IS AN EXCEPTION, NEVER A PARTIAL PAYLOAD. Any failed check throws
 *      IdentityReaderException with one of its stable reason codes. There is no "degraded"
 *      success, no returning a payload with a warning flag. The exception message is shown to
 *      the user; the raw response never is (it belongs in the masked diagnostics record).
 *
 * ---------------------------------------------------------------------------------------
 * B. SAML 2.0
 * ---------------------------------------------------------------------------------------
 *
 *  B1. EXACTLY ONE ASSERTION. A Response carrying more than one `saml:Assertion` element
 *      (signed, unsigned, encrypted or any mixture) is rejected outright. Do not "pick the
 *      signed one" - reject the message. This is the primary, cheapest defence against
 *      signature wrapping and it is the first thing the reader checks.
 *  B2. ATTRIBUTES COME FROM THE SIGNED ASSERTION. The assertion whose attributes, NameID and
 *      conditions are read MUST be the node the verified signature references. If the library
 *      cannot demonstrate that binding, the response is rejected. A response where the
 *      signature validates but the reference resolves to a different node than the one parsed
 *      is a wrapping attempt, not a quirk.
 *  B3. UNSIGNED IS ALWAYS REJECTED. An unsigned assertion is rejected even when the Response
 *      envelope is signed and even when the transport was HTTPS.
 *  B4. `samlp:Status` MUST BE `urn:oasis:names:tc:SAML:2.0:status:Success`. Any other status -
 *      including `Responder`, `AuthnFailed`, `NoPassive` - is a failed login, not an identity.
 *      A Response with a non-Success status and no assertion must never reach the core.
 *  B5. `Conditions`: `NotBefore` and `NotOnOrAfter` are both enforced (skew per A4), and
 *      `AudienceRestriction` must list our SP entity id exactly.
 *  B6. `Subject/SubjectConfirmation`: method MUST be
 *      `urn:oasis:names:tc:SAML:2.0:cm:bearer`, and its `SubjectConfirmationData` MUST carry a
 *      `Recipient` equal to our ACS URL and its OWN `NotOnOrAfter`, which is enforced separately
 *      from `Conditions/@NotOnOrAfter`. A confirmation with no `NotOnOrAfter` is rejected.
 *  B7. `InResponseTo` MUST equal the request id we issued, and the request id MUST be one this
 *      site created and has not yet consumed. A response with no `InResponseTo` is rejected
 *      unless IdP-initiated flow is explicitly enabled for the connection (out of MVP scope);
 *      when it is enabled, the whole flow still passes through StateStore.
 *  B8. `Destination`, when present, MUST equal our ACS URL.
 *  B9. NAMEID MUST BE PRESENT AND NON-EMPTY after trimming. An empty, whitespace-only or
 *      missing NameID is rejected rather than mapped to an empty subject; an empty subject
 *      silently matching an account is exactly how "log in as nobody" becomes "log in as
 *      somebody".
 * B10. XXE AND DTD ARE OFF. The parser runs with entity loading disabled and rejects any
 *      document containing a DOCTYPE. This is checked by the reader, not assumed from the
 *      library: an XML parser that resolves entities turns a login form into a file-read
 *      primitive and an SSRF primitive.
 * B11. ENCRYPTED ASSERTIONS are decrypted with our SP private key before any of the above runs,
 *      and every check then runs on the decrypted content. Decryption success is not validation.
 *
 * ---------------------------------------------------------------------------------------
 * C. OIDC / OAuth 2.0 - the second half of the contract, and just as binding
 * ---------------------------------------------------------------------------------------
 *
 *  C1. ALGORITHM ALLOW LIST, FIXED IN CODE. Only `RS256` and `ES256` are accepted. The `alg`
 *      header of the incoming token NEVER selects the verification routine on its own: a token
 *      whose `alg` is outside the list is rejected before any signature work.
 *  C2. `alg: none` IS REJECTED unconditionally, as is any unsecured JWT (empty signature part).
 *  C3. HMAC ALGORITHMS (`HS*`) ARE REJECTED for the id token on an asymmetric connection.
 *      Accepting `HS256` while holding the IdP's public key lets anyone who can read that public
 *      key - it is public - sign their own token. This is the JWT twin of A1 and must be
 *      enforced by the allow list from C1, not by a runtime `if`.
 *  C4. THE KEY COMES FROM JWKS FETCHED FROM THE DISCOVERY DOCUMENT of the configured issuer
 *      (`https://.../.well-known/openid-configuration`), over HTTPS with certificate
 *      verification on. `JWK::parseKeySet()` from firebase/php-jwt; no hand-rolled key parsing.
 *  C5. `kid` MUST MATCH. The header `kid` selects the key from the JWKS. When the token carries
 *      no `kid` and the set holds more than one key, the token is rejected - trying every key in
 *      turn is how a rotated-out or attacker-suggested key gets used. Cached JWKS may be
 *      refreshed at most once per rejected `kid`, rate-limited, to survive key rotation.
 *  C6. CLAIMS: `iss` equals the configured issuer exactly (A6); `aud` contains our client id;
 *      when `aud` has multiple values, `azp` MUST be present and equal our client id; `exp` is
 *      in the future and `iat` is not absurdly old (skew per A4); `sub` is present and non-empty
 *      (the OIDC twin of B9).
 *  C7. `nonce` IS MANDATORY. The reader sends a nonce with the authentication request, keeps it
 *      server-side next to the login state, and rejects any id token whose `nonce` claim is
 *      missing or different. This is the OIDC equivalent of `InResponseTo` (B7) and the only
 *      thing tying the token to the browser that started the login; without it a token minted
 *      for another session - or replayed from a log - is accepted. THE READER MUST NOT SHIP
 *      WITHOUT IT, and "the IdP does not send nonce" is a configuration error on their side,
 *      never a reason to skip the check.
 *  C8. PKCE IS MANDATORY: `code_challenge_method = S256` (never `plain`), a fresh verifier per
 *      login, stored server-side, never in a cookie or in the `state` value.
 *  C9. `at_hash` / `c_hash`, when present in the id token, are verified against the access token
 *      and the authorization code respectively. Present-and-wrong is a rejection; the reader
 *      does not treat "I could not compute it" as a pass.
 * C10. THE USERINFO ENDPOINT IS NOT A SHORTCUT. Its response is only used after the id token
 *      verified, over HTTPS with a bearer token, and its `sub` MUST equal the id token `sub`.
 *      An unsigned userinfo response never establishes identity on its own.
 * C11. THE `state` VALUE IS STILL CHECKED by Core\State\StateStore. `nonce` and `state` solve
 *      different problems (token binding vs request binding) and neither substitutes for the
 *      other.
 *
 * Implementation note for whoever writes the readers: every numbered item above should map to
 * a test with the corresponding malicious fixture - two assertions, wrapped signature, `alg:
 * none`, `HS256` signed with the public key, missing nonce, expired `NotOnOrAfter`, wrong
 * `Recipient`. A reader that only has happy-path tests has not been tested.
 *
 * @see IdentityPayload
 * @see IdentityReaderException for the stable reason codes each rejection must use.
 */
interface IdentityReaderInterface
{
    /**
     * Protocol identifier for diagnostics: 'saml2' or 'oidc'.
     */
    public function protocol(): string;

    /**
     * @param array<string, mixed> $request Raw transport input (POST fields, query string).
     * @throws IdentityReaderException When the response is missing, malformed or fails any
     *                                 of the validations listed in the class docblock.
     */
    public function read(array $request): IdentityPayload;
}
