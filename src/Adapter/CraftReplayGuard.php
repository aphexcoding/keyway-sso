<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\ReplayGuardInterface;

/**
 * ReplayGuardInterface on Craft's shared cache (contract A5).
 *
 * Burns the identifier the identity provider issued - SAML `Assertion/@ID`, OIDC `jti` - as
 * opposed to CraftStateStorage, which burns the token this site issued. Same atomic primitive,
 * different thing being protected; see SingleUseKeys for exactly how strong "atomic" is on each
 * cache backend, including the honest caveat about Craft's default FileCache.
 *
 * Two details the contract asks for and that are easy to get wrong:
 *
 *  - IT TAKES AN ABSOLUTE EXPIRY AND THE CACHE WANTS A DURATION. Converting between them needs
 *    the current time, hence the clock: the same ClockInterface the readers use, so a test can
 *    move time and a skewed server cannot silently shorten the window.
 *  - IT MUST NOT FORGET EARLY. "Retention: at least until `$expiresAt`" - forgetting sooner
 *    re-opens the replay window, forgetting later costs storage. So the TTL gets a grace margin
 *    on top, and never drops below MIN_TTL even for an assertion that is already expiring; a
 *    stale assertion is refused by the reader anyway, and a one-second entry would be a guard
 *    that stops guarding while the second request is still in flight.
 *
 * The identifier is hashed into the key. It comes from outside, it has no length limit in
 * either specification, and it is the kind of value that has no business appearing verbatim in
 * a cache directory listing.
 */
final class CraftReplayGuard implements ReplayGuardInterface
{
    private const KEY_PREFIX = 'keyway-sso.replay.';
    private const GRACE = 300;
    private const MIN_TTL = 300;

    private SingleUseKeys $singleUse;
    private ClockInterface $clock;

    public function __construct(SingleUseKeys $singleUse, ClockInterface $clock)
    {
        $this->singleUse = $singleUse;
        $this->clock = $clock;
    }

    public function remember(string $id, int $expiresAt): bool
    {
        $now = $this->clock->now();
        $ttl = max(self::MIN_TTL, $expiresAt - $now + self::GRACE);

        return $this->singleUse->claim(self::KEY_PREFIX . hash('sha256', $id), $now, $ttl);
    }
}
