<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Support;

use InvalidArgumentException;
use Keyway\Sso\Core\Port\RandomSourceInterface;

final class RandomSource implements RandomSourceInterface
{
    public function bytes(int $length): string
    {
        if ($length < 1) {
            throw new InvalidArgumentException('Random length must be positive.');
        }

        return random_bytes($length);
    }
}
