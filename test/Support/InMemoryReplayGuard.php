<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\ReplayGuardInterface;

/**
 * Reference implementation of the replay registry. Single-process, so "atomic" is simply
 * "checks and writes without yielding".
 *
 * `$expiresAt` IS HONOURED, and that is the whole point of this class existing rather than an
 * array. The earlier version accepted the argument and remembered forever, which made every
 * replay test in this repository - login, OIDC and logout alike - weaker than it looked: a
 * reader that computes a horizon too short, or on the wrong axis entirely, still looked green,
 * because nothing here ever let an entry expire. A registry that never forgets cannot tell a
 * correct retention from a wrong one.
 *
 * The clock is injectable for the same reason it is everywhere else in this codebase: a test
 * that cannot move time cannot assert what happens after the entry is gone.
 *
 * IT IS ALSO MANDATORY, and that is a fix rather than a style preference. The constructor used
 * to fall back to SystemClock, so a guard built without an argument swept its entries against
 * the wall clock while the reader under test ran on a FixedClock. Nothing failed, because the
 * retention horizon (`exp` + skew) is 360 s ahead of a fixture dated "now" - measured: the suite
 * stays green up to +359 s of drift and goes red at +360 s. That is a margin, not a guarantee,
 * and it is the kind of margin that turns into a random red the day a fixture is dated closer to
 * its own expiry. A required clock removes the wall clock from the suite instead of relying on
 * the gap staying wide.
 */
final class InMemoryReplayGuard implements ReplayGuardInterface
{
    /** @var array<string, int> id => expiry */
    private array $seen = [];

    private ClockInterface $clock;

    public function __construct(ClockInterface $clock)
    {
        $this->clock = $clock;
    }

    public function remember(string $id, int $expiresAt): bool
    {
        $now = $this->clock->now();

        // Retention is "at least until $expiresAt" (see ReplayGuardInterface), so an entry is
        // live while now < expiry and dropped at or after it. Sweeping on write keeps count()
        // honest without a second code path.
        foreach ($this->seen as $key => $expiry) {
            if ($now >= $expiry) {
                unset($this->seen[$key]);
            }
        }

        if (isset($this->seen[$id])) {
            return false;
        }

        $this->seen[$id] = $expiresAt;

        return true;
    }

    public function count(): int
    {
        return count($this->seen);
    }
}
