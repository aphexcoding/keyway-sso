<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Saml;

/**
 * A verified IdP-initiated LogoutRequest: what the identity provider ASKED for.
 *
 * ------------------------------------------------------------------------------------------
 * THE SUBJECT IS INPUT, NOT AN ORDER - AND THE TYPE IS WHAT ENFORCES IT
 * ------------------------------------------------------------------------------------------
 *
 * `NameID` and `SessionIndex` arrived in a document written by somebody else. Everything in this
 * object survived signature verification, issuer pinning, the destination check, the time window
 * and the replay guard, so it is AUTHENTIC - it really came from the configured IdP. Authentic
 * is not the same as authorised.
 *
 * The only thing this object licenses is: "the IdP asks that the session belonging to THIS
 * subject be ended". The caller MUST resolve that subject against the identity that actually
 * signed in - the name id and session index recorded at login - and end only a session whose
 * recorded subject matches. It must never treat these fields as a selector handed straight to a
 * session store, and it must never fall back to "end the current session" when the subject does
 * not match: the browser making that request belongs to whoever clicked the link, and a
 * mismatched subject is exactly the case where those two are different people.
 *
 * Until 2026-09-17 that rule lived in this docblock and nowhere else, while the raw subject sat
 * on a public readonly property - which made `$sessions->endByNameId($request->nameId)` the path
 * of least resistance and left nothing in the code to object. The subject is now reachable only
 * through matches(), which compares, and through subjectForResponse(), which is documented for
 * one use. The same reasoning applies to the session index list: an empty list is the WIDER
 * request, and a bare `empty()` on a public array reads as "nothing to log out", so the list is
 * behind appliesToEverySession() and namedSessionIndexes() instead.
 *
 * When no session matches, that is not an error to hide. Answer the IdP with
 * SamlLogoutResponse::unknownPrincipal() and end nothing.
 *
 * Nothing here is trimmed, folded or normalised: the values are compared byte for byte against
 * what the IdP really sent.
 */
final class InboundLogoutRequest
{
    /** The IdP's own message id. Goes back as InResponseTo in our LogoutResponse. */
    public readonly string $id;

    /** Optional format of the NameID, kept for callers that pinned one at login. */
    public readonly ?string $nameIdFormat;

    /** Opaque state to echo back to the IdP, still percent-encoded as it arrived. */
    public readonly ?string $rawRelayState;

    /** The subject the IdP wants logged out. Private on purpose: see the class docblock. */
    private readonly string $nameId;

    /**
     * EVERY session the IdP named, in document order. Private for the same reason as $nameId.
     *
     * @var list<string>
     */
    private readonly array $sessionIndexes;

    /**
     * @param list<string> $sessionIndexes
     */
    public function __construct(
        string $id,
        string $nameId,
        ?string $nameIdFormat,
        array $sessionIndexes,
        ?string $rawRelayState
    ) {
        $this->id = $id;
        $this->nameId = $nameId;
        $this->nameIdFormat = $nameIdFormat;
        $this->sessionIndexes = array_values($sessionIndexes);
        $this->rawRelayState = $rawRelayState;
    }

    /**
     * Does this request name the session that was actually recorded at login?
     *
     * THE ONLY SANCTIONED WAY TO ACT ON THE SUBJECT. Both comparisons are exact - byte for byte,
     * through hash_equals, with no trimming, case folding or unicode normalisation. A name id is
     * an opaque identifier chosen by the IdP: `Alice@example.test` and `alice@example.test` are
     * two different subjects as far as SAML is concerned, and a comparison that folded them
     * would end one person's session on another person's say-so. hash_equals rather than `===`
     * because the value is attacker-supplied and compared against a stored secret-ish
     * identifier; the constant-time comparison costs nothing here and removes the question.
     *
     * @param string      $recordedNameId        The name id stored when THIS session signed in.
     * @param string|null $recordedSessionIndex  The session index stored with it, or null when
     *                                           the assertion carried none.
     */
    public function matches(string $recordedNameId, ?string $recordedSessionIndex): bool
    {
        if (!hash_equals($this->nameId, $recordedNameId)) {
            return false;
        }

        if ($this->sessionIndexes === []) {
            // The IdP named no session at all, which asks for EVERY session of this subject -
            // the wider request. The subject matched, so this session is one of them.
            return true;
        }

        if ($recordedSessionIndex === null) {
            // The IdP named specific sessions and we cannot tell whether ours is one of them.
            // Ending it anyway would be acting on a guess about which session was meant.
            return false;
        }

        foreach ($this->sessionIndexes as $sessionIndex) {
            if (hash_equals($sessionIndex, $recordedSessionIndex)) {
                return true;
            }
        }

        return false;
    }

    /**
     * True when the IdP named no SessionIndex at all - the WIDER request, "every session of this
     * subject", never "no session".
     */
    public function appliesToEverySession(): bool
    {
        return $this->sessionIndexes === [];
    }

    /**
     * How many sessions the IdP named explicitly. Zero means it named none; see
     * appliesToEverySession().
     *
     * Exists so that a caller which ended one session out of several named ones can tell that it
     * did, and answer SamlLogoutResponse::partialLogout() instead of reporting a logout that did
     * not happen.
     */
    public function namedSessionCount(): int
    {
        return count($this->sessionIndexes);
    }

    /**
     * The raw NameID, FOR BUILDING THE LogoutResponse AND FOR NOTHING ELSE.
     *
     * A LogoutResponse does not carry a subject, but a diagnostics line and any future
     * SP-initiated correlation do, and those are the reasons this accessor exists. It is NOT a
     * selector: resolving a session by this value is the exact mistake the class docblock
     * describes. Use matches().
     */
    public function subjectForResponse(): string
    {
        return $this->nameId;
    }
}
