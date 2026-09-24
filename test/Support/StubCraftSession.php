<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\web\User as UserSession;
use yii\web\IdentityInterface;

/**
 * craft\web\User with the session taken out, and a memory of whether it was ever asked to start
 * one.
 *
 * `$logins` is the assertion that matters. A refusal that returns the right reason code but
 * signs the person in anyway is the exact bug this stub exists to catch: the control-panel gate
 * is only worth anything if it runs BEFORE login(), and "before" is not visible from the return
 * value.
 */
final class StubCraftSession extends UserSession
{
    /** @var list<array{0: IdentityInterface, 1: int}> Every login() call, in order. */
    public array $logins = [];

    /** Whether Craft would accept the session; false exercises SESSION_NOT_STARTED. */
    public bool $accepts = true;

    public string $returnUrl = '/cp/dashboard';

    public int $returnUrlRemovals = 0;

    public function __construct()
    {
        // Deliberately does not call parent::__construct(): no application, no session storage.
    }

    public function login(IdentityInterface $identity, $duration = 0): bool
    {
        $this->logins[] = [$identity, (int)$duration];

        return $this->accepts;
    }

    public function getReturnUrl($defaultUrl = null): string
    {
        return $this->returnUrl;
    }

    public function removeReturnUrl(): void
    {
        $this->returnUrlRemovals++;
    }
}
