<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\Diagnostics\DiagnosticRow;
use Keyway\Sso\Core\Diagnostics\DiagnosticsQuery;

/**
 * The read side of diagnostics: what the control-panel screen asks for.
 *
 * Separate from DiagnosticsSinkInterface even though one class implements both, because the two
 * have opposite obligations. The sink runs inside a login and must never make it fail. The
 * reader runs inside a control-panel request where nothing is at stake but the screen itself.
 * Keeping them apart means the panel can be built against a fixture with no database, and means
 * nothing that only writes (the log sink) is ever mistaken for something the panel can read.
 *
 * Implementations MUST NOT throw. An unreachable table, a missing migration or a malformed row
 * is a screen that says so, not a 500 on the page an administrator opened BECAUSE something is
 * already broken. Rows that cannot be parsed come back as placeholder DiagnosticRow instances.
 */
interface DiagnosticsReaderInterface
{
    /**
     * @return list<DiagnosticRow> Newest first, honouring the query's limit and offset.
     */
    public function recent(DiagnosticsQuery $query): array;

    /**
     * How many rows match the query's filters, ignoring limit and offset - the pager's total.
     */
    public function total(DiagnosticsQuery $query): int;

    /**
     * Whether this store can be read at all - i.e. whether the migration that creates it has run.
     *
     * ON THE CONTRACT BECAUSE THE PANEL CANNOT WORK IT OUT ANY OTHER WAY, and the review that
     * added this method found the gap the hard way. The clause above says implementations must
     * never throw; the panel was nevertheless deciding "this store is unusable" from a `catch`
     * block. Both halves were internally consistent and together they were wrong: an install
     * that ran `composer update` without `craft up` has no table, so `recent()` correctly
     * answers `[]` and nothing is thrown - and the screen then said "no sign-in attempts have
     * been recorded yet". The administrator waits for rows that can never arrive and writes to
     * support, which is the exact cost this module exists to remove.
     *
     * Distinguishing "empty" from "not there" is therefore a question only the store can answer,
     * which makes it part of the contract rather than an accident of error handling.
     *
     * Implementations MUST NOT throw here either: false is the answer for every kind of "no".
     */
    public function isReady(): bool;
}
