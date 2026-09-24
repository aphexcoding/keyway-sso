<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * Source of cryptographically secure random bytes.
 *
 * Implementations MUST be CSPRNG-backed (`random_bytes`). The interface exists for
 * deterministic tests only; never wire a predictable implementation into a running site.
 */
interface RandomSourceInterface
{
    /**
     * @param int<1, max> $length
     * @return string Raw bytes, exactly $length long.
     */
    public function bytes(int $length): string;
}
