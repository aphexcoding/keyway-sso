<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\ClockInterface;

final class FixedClock implements ClockInterface
{
    private int $now;

    public function __construct(int $now = 1_700_000_000)
    {
        $this->now = $now;
    }

    public function now(): int
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }

    public function set(int $now): void
    {
        $this->now = $now;
    }
}
