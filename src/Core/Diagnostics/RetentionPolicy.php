<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

/**
 * How long diagnostics rows live, and how often the table is swept.
 *
 * Three separate problems, and the reason all three are here rather than in the sink is that
 * none of them needs a database to be decided - or tested.
 *
 * AGE. Rows describe logins. A login from six months ago tells an administrator nothing and
 * tells anyone who gets into the database something: issuers, masked subjects, group names and
 * the shape of the directory. Diagnostics that accumulate forever turn a support feature into a
 * liability, so the default horizon is 30 days.
 *
 * VOLUME. Age alone does not bound anything. A site with a bad IdP configuration and a
 * scheduled job hitting the login endpoint can write thousands of rows in an afternoon, all of
 * them younger than the cutoff. The row cap is what stops a support table from becoming the
 * largest table in the database.
 *
 * FREQUENCY. Sweeping on every login would put a DELETE in the critical path of signing in,
 * which is the one path in this plugin that must stay fast and must never fail. So the sweep is
 * time-boxed: at most one per interval, decided from a timestamp the sink keeps in the shared
 * cache. Missing the odd sweep is harmless; slowing down every login is not.
 *
 * The constructor clamps rather than validates. It is built from settings a site owner can type
 * (and from project config a previous administrator may have hand-edited), and the failure mode
 * of `days = 0` would be a policy that deletes every row the moment it is written - a plugin
 * that erases its own diagnostics is worse than one that keeps too many.
 */
final class RetentionPolicy
{
    public const DEFAULT_DAYS = 30;
    public const DEFAULT_MAX_ROWS = 2000;
    public const DEFAULT_PRUNE_INTERVAL = 3600;

    private const MIN_DAYS = 1;
    private const MAX_DAYS = 3650;
    private const MIN_ROWS = 10;
    private const MAX_ROWS = 1_000_000;
    private const MIN_INTERVAL = 60;
    private const MAX_INTERVAL = 86_400;

    private const SECONDS_PER_DAY = 86_400;

    private int $days;
    private int $maxRows;
    private int $pruneIntervalSeconds;

    public function __construct(int $days, int $maxRows, int $pruneIntervalSeconds = self::DEFAULT_PRUNE_INTERVAL)
    {
        $this->days = max(self::MIN_DAYS, min(self::MAX_DAYS, $days));
        $this->maxRows = max(self::MIN_ROWS, min(self::MAX_ROWS, $maxRows));
        $this->pruneIntervalSeconds = max(
            self::MIN_INTERVAL,
            min(self::MAX_INTERVAL, $pruneIntervalSeconds)
        );
    }

    public static function default(): self
    {
        return new self(self::DEFAULT_DAYS, self::DEFAULT_MAX_ROWS, self::DEFAULT_PRUNE_INTERVAL);
    }

    public function days(): int
    {
        return $this->days;
    }

    public function maxRows(): int
    {
        return $this->maxRows;
    }

    public function pruneIntervalSeconds(): int
    {
        return $this->pruneIntervalSeconds;
    }

    /**
     * The oldest `occurredAt` worth keeping: anything strictly older is deletable.
     */
    public function cutoff(int $now): int
    {
        return $now - ($this->days * self::SECONDS_PER_DAY);
    }

    /**
     * @param int|null $lastPruneAt Null when the table has never been swept (fresh install, or
     *                              a cache that was flushed - both mean "sweep now").
     */
    public function shouldPrune(?int $lastPruneAt, int $now): bool
    {
        if ($lastPruneAt === null) {
            return true;
        }

        // A stamp in the future comes from a clock change or a cache written by another host;
        // trusting it would suspend pruning until that future arrives, which on a bad clock can
        // be never. Treat it as unusable and sweep.
        if ($lastPruneAt > $now) {
            return true;
        }

        return ($now - $lastPruneAt) >= $this->pruneIntervalSeconds;
    }
}
