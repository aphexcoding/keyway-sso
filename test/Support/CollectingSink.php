<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Port\DiagnosticsSinkInterface;

final class CollectingSink implements DiagnosticsSinkInterface
{
    /** @var list<DiagnosticEvent> */
    public array $events = [];

    public function record(DiagnosticEvent $event): void
    {
        $this->events[] = $event;
    }

    public function last(): ?DiagnosticEvent
    {
        return $this->events === [] ? null : $this->events[count($this->events) - 1];
    }
}
