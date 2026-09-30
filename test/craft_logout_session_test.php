<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftLogoutSession;
use Keyway\Sso\Core\Logout\SessionSubject;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\StubCraftLogoutSession;
use Keyway\Sso\Test\Support\StubSessionStorage;

/**
 * The adapter between single logout and Craft's session.
 *
 * Thin, but not trivial: three of its lines are the difference between an honest answer and a
 * dangerous one, and none of them is visible from the flow's own tests, which run against a
 * stub of this class.
 */

// Same guard as every other file in this suite that touches Craft's own classes: the stub
// session extends `craft\web\User`, so without an installed vendor directory PHP fatals on
// the class rather than reporting a failure. Reported as a skip, so a fresh clone runs the
// suite green before `composer install`.
if (!class_exists(\craft\web\User::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_logout_session', 'skipped: vendor absent (run composer install)'));

    return [];
}

return [
    'the subject is stored verbatim and read back whole' => static function (): void {
        $user = new StubCraftLogoutSession(false);
        $storage = new StubSessionStorage();
        $session = new CraftLogoutSession($user, $storage);

        // A name id that a trimming implementation would quietly change.
        $session->remember(new SessionSubject(' Alice@example.test ', '_session_7'));

        $current = $session->current();
        Assert::same(' Alice@example.test ', $current?->nameId, 'byte for byte, or the later match fails');
        Assert::same('_session_7', $current?->sessionIndex);
    },

    'an assertion that carried no SessionIndex reads back as null, not as an empty string' =>
        static function (): void {
            $session = new CraftLogoutSession(new StubCraftLogoutSession(false), new StubSessionStorage());
            $session->remember(new SessionSubject('alice@example.test', null));

            Assert::null($session->current()?->sessionIndex);
        },

    // Craft expires sessions on its own schedule and the bag can outlive the login. A subject
    // read back after that would match a LogoutRequest and report the logout of a session that
    // no longer exists - and, worse, it would be the SECOND visitor to this browser whose
    // presence decided the answer.
    'a guest has no subject, whatever is left in the session bag' => static function (): void {
        $user = new StubCraftLogoutSession(false);
        $storage = new StubSessionStorage();
        $session = new CraftLogoutSession($user, $storage);
        $session->remember(new SessionSubject('alice@example.test', '_session_7'));

        $user->guest = true;

        Assert::null($session->current(), 'the guest check comes first');
    },

    'a password login has no subject either' => static function (): void {
        $session = new CraftLogoutSession(new StubCraftLogoutSession(false), new StubSessionStorage());

        Assert::null($session->current(), 'nothing recorded, nothing to match - and no guessing');
    },

    'ending the session asks Craft whether it really went' => static function (): void {
        $user = new StubCraftLogoutSession(false);
        $session = new CraftLogoutSession($user, new StubSessionStorage());

        Assert::true($session->endCurrentSession());
        Assert::same(1, $user->logouts);
    },

    // THE ONE ANSWER THIS ENDPOINT MUST NEVER GIVE. `logout()` returns void and an event handler
    // may cancel it; a hard `return true` here would report Success to the identity provider for
    // a session that is still open, and the IdP would stop asking anybody else about it.
    'a session that survives logout() is reported as NOT ended' => static function (): void {
        $user = new StubCraftLogoutSession(false);
        $user->stayLoggedIn = true;
        $session = new CraftLogoutSession($user, new StubSessionStorage());

        Assert::false($session->endCurrentSession(), 'asked, never assumed');
        Assert::same(1, $user->logouts, 'and we did try');
    },

    // Runs immediately after a successful login. Bookkeeping that can take away a session
    // somebody just legitimately obtained is worse than bookkeeping that is missing.
    'a failing write never throws into the login' => static function (): void {
        $storage = new StubSessionStorage();
        $storage->writesFail = true;
        $session = new CraftLogoutSession(new StubCraftLogoutSession(false), $storage);

        Assert::doesNotThrow(
            static fn () => $session->remember(new SessionSubject('alice@example.test', '_session_7')),
            'the port contract: remember() never throws'
        );

        Assert::null($session->current(), 'and the honest consequence is an unknownPrincipal later');
    },
];
