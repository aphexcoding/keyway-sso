<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use craft\web\User as UserSession;
use Keyway\Sso\Core\Logout\SessionSubject;
use Keyway\Sso\Core\Port\LogoutSessionInterface;
use Throwable;
use yii\web\Session;

/**
 * The browser session as Craft holds it, plus the two values Craft does not store: the NameID
 * and the SessionIndex the identity provider used when this session began.
 *
 * They go into the PHP session and nowhere else. Not into the users table - they describe one
 * sign-in, not the account, and a person signed in from two browsers has two of them. Not into a
 * cookie - a subject the browser can rewrite is a subject an attacker chooses, and matching an
 * inbound LogoutRequest against an attacker-chosen value would end sessions on demand. The PHP
 * session dies with the session it describes, which is exactly the lifetime wanted.
 *
 * remember() NEVER THROWS, by the port's contract. It runs immediately after a successful login,
 * and bookkeeping that can take away a session somebody just legitimately obtained is worse than
 * bookkeeping that is missing: when it fails, current() answers null, the next LogoutRequest is
 * answered with an honest unknownPrincipal, and the person stays signed in. Identical to the
 * rule CraftDbIdentityLinkStore follows for the same moment in the flow.
 */
final class CraftLogoutSession implements LogoutSessionInterface
{
    /** Namespaced so nothing else in Craft's session bag can collide with them. */
    private const KEY_NAME_ID = 'keyway-sso.logout.nameId';
    private const KEY_SESSION_INDEX = 'keyway-sso.logout.sessionIndex';

    private UserSession $user;
    private Session $storage;

    public function __construct(UserSession $user, Session $storage)
    {
        $this->user = $user;
        $this->storage = $storage;
    }

    public function remember(SessionSubject $subject): void
    {
        try {
            // Stored verbatim. The value arrives already settled by the reader (LoginFlow hands
            // over the same string the identity link is written from), and touching it here
            // would put the two sides of the later comparison on different normalisations.
            $this->storage->set(self::KEY_NAME_ID, $subject->nameId);
            $this->storage->set(self::KEY_SESSION_INDEX, $subject->sessionIndex);
        } catch (Throwable) {
            // See the class docblock: a failed write costs a later logout its match, nothing more.
        }
    }

    public function current(): ?SessionSubject
    {
        // The guest check comes FIRST and is not a formality: a stale subject left in the bag
        // after Craft expired the session would otherwise match a LogoutRequest and report a
        // logout of a session that no longer exists.
        if ($this->user->getIsGuest()) {
            return null;
        }

        $nameId = $this->storage->get(self::KEY_NAME_ID);

        if (!is_string($nameId) || $nameId === '') {
            // Signed in by password, or signed in before this plugin recorded subjects. Either
            // way there is nothing to match against, and guessing is what this returns null to
            // avoid.
            return null;
        }

        $sessionIndex = $this->storage->get(self::KEY_SESSION_INDEX);

        return new SessionSubject($nameId, is_string($sessionIndex) ? $sessionIndex : null);
    }

    public function endCurrentSession(): bool
    {
        $this->user->logout();

        // Asked, never assumed: `logout()` returns void and an event handler may keep the
        // session alive. Reporting Success to the identity provider for a session that is still
        // open is the one answer this endpoint must never give.
        return $this->user->getIsGuest();
    }
}
