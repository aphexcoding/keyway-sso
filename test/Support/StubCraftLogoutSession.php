<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\web\User as UserSession;
use yii\web\Session;

/**
 * Craft's user component with the session taken out: whether it thinks there is a guest, and
 * whether anybody asked it to log out.
 *
 * `$stayLoggedIn` is the switch that matters. A session Craft refuses to drop - an event handler
 * cancelling the logout - must not be reported to the identity provider as Success, and "did it
 * actually go" is not visible from `logout()`, which returns void.
 */
final class StubCraftLogoutSession extends UserSession
{
    public bool $guest;

    public int $logouts = 0;

    /** When true, logout() is called but the session survives it. */
    public bool $stayLoggedIn = false;

    public function __construct(bool $guest = false)
    {
        // Deliberately no parent::__construct(): no application, no session storage.
        $this->guest = $guest;
    }

    public function getIsGuest(): bool
    {
        return $this->guest;
    }

    public function logout($destroySession = true): void
    {
        $this->logouts++;

        if (!$this->stayLoggedIn) {
            $this->guest = true;
        }
    }
}
