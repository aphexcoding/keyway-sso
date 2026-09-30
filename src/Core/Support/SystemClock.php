<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Support;

use Keyway\Sso\Core\Port\ClockInterface;

final class SystemClock implements ClockInterface
{
    public function now(): int
    {
        return time();
    }
}
