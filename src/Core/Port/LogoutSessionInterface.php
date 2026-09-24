<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\Logout\SessionSubject;

/**
 * The browser session, as much of it as single logout is allowed to touch.
 *
 * Three operations, deliberately no more. There is no "end the session belonging to name id X"
 * and there will not be one: a front-channel LogoutRequest arrives in ONE browser carrying ONE
 * session, and an implementation able to end somebody else's session by identifier would turn a
 * signed GET into a remote session kill for any subject the IdP can name.
 *
 * remember() is called at login, current() and endCurrentSession() when a LogoutRequest arrives.
 * The caller compares before it ends anything - see InboundLogoutFlow.
 */
interface LogoutSessionInterface
{
    /**
     * Store the subject of the session that has just started. Must not normalise the values.
     *
     * Never throws by contract: the person is already signed in when this runs, and failed
     * bookkeeping must not take their session away. An implementation that cannot store the
     * subject leaves current() returning null, which costs a later logout its match and is
     * reported honestly as unknownPrincipal.
     */
    public function remember(SessionSubject $subject): void;

    /** The subject of the session in this browser, or null when there is none to speak of. */
    public function current(): ?SessionSubject;

    /**
     * End the session in THIS browser. Returns whether it is actually gone.
     *
     * False is not an exception: the honest answer to the IdP in that case is a responder error,
     * not a Success for a session that is still alive.
     */
    public function endCurrentSession(): bool;
}
