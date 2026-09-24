<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Craft;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Port\DiagnosticsSinkInterface;

/**
 * Diagnostics into Craft's log, until the panel has a table of its own.
 *
 * HONEST SCOPE: this is not the diagnostics panel. The product's support model is "the
 * administrator reads a screen instead of e-mailing us", and that needs a database table, a
 * retention policy and a control-panel view - none of which exist yet. What exists today is the
 * decision to never lose an event, so they go to the log with a category of their own and the
 * panel reads them from a real table when it is built.
 *
 * Writing them is safe because the event is already masked: DiagnosticEvent masks in its
 * constructor, so there is no path by which an unmasked assertion reaches this class. The log
 * level follows the outcome, so a successful login does not shout and a refusal is findable.
 */
final class CraftLogDiagnosticsSink implements DiagnosticsSinkInterface
{
    public const CATEGORY = 'keyway-sso';

    public function record(DiagnosticEvent $event): void
    {
        $line = $event->toJson();

        if ($event->isSuccess()) {
            Craft::info($line, self::CATEGORY);

            return;
        }

        Craft::warning($line, self::CATEGORY);
    }
}
