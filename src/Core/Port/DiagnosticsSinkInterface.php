<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;

/**
 * Destination for login diagnostics (Craft database table behind the diagnostics panel).
 *
 * Implementations MUST NOT re-read the raw protocol message: everything the support panel is
 * allowed to show is already masked inside the event.
 */
interface DiagnosticsSinkInterface
{
    public function record(DiagnosticEvent $event): void;
}
