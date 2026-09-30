<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Logout;

/**
 * Who a live session belongs to, in the identity provider's own words.
 *
 * Recorded at login and read back when a LogoutRequest arrives, because that request names its
 * target the way the IdP names people - a NameID and a SessionIndex - and nothing else in Craft
 * stores either. Without this, matching an inbound logout to a session is guesswork, and the
 * only guess available ("it is whoever is holding this browser") is the one that logs out the
 * wrong person.
 *
 * NOTHING IS NORMALISED HERE - which is a statement about this class, not about the value. What
 * arrives has ALREADY been through the reader's own normalisation (IdentityPayload trims the
 * NameID on construction, and LoginFlow hands over exactly that string, the same one the identity
 * link is written from). That is deliberate: both sides of the later hash_equals have to come out
 * of one normalisation step, and the way to guarantee that is for every step after the reader -
 * this one included - to touch nothing. The rest of the contract follows. The values go in byte for byte as
 * the assertion carried them so that InboundLogoutRequest::matches() compares against what the
 * IdP really sent. Trimming on the way in would make a subject whose name id legitimately ends
 * in a space unmatchable forever, and folding case would make two different subjects equal.
 */
final class SessionSubject
{
    /** The NameID from the assertion that started this session. Raw. */
    public readonly string $nameId;

    /** The SessionIndex from that assertion, or null when it carried none. Raw. */
    public readonly ?string $sessionIndex;

    public function __construct(string $nameId, ?string $sessionIndex)
    {
        $this->nameId = $nameId;
        $this->sessionIndex = $sessionIndex;
    }
}
