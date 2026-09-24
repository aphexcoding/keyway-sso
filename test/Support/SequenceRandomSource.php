<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\RandomSourceInterface;

/**
 * Deterministic, predictable byte source. Test double only - never wire this into a site.
 */
final class SequenceRandomSource implements RandomSourceInterface
{
    private int $counter = 0;

    public function bytes(int $length): string
    {
        $out = '';
        while (strlen($out) < $length) {
            $out .= hash('sha256', 'keyway-test-' . $this->counter++, true);
        }

        return substr($out, 0, $length);
    }
}
