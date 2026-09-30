<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\db\Connection;
use Throwable;
use yii\db\QueryBuilder;

/**
 * A `craft\db\Connection` that builds REAL SQL but never opens a socket.
 *
 * The point of the exercise is that the statements under test are genuinely built by Yii's
 * query builder - table prefix expanded, conditions turned into bound parameters, LIKE
 * wildcards escaped by the same code that will run in production - while the execution step is
 * replaced. A hand-written double asserting "the sink called andWhere() twice" would agree with
 * whatever the sink believes; this one can be asked what SQL came out.
 *
 * Two overrides make that possible:
 *
 *  - createCommand() returns FakeCraftDbCommand, so nothing is executed;
 *  - getQueryBuilder() returns the BASE builder rather than the MySQL one, because
 *    `yii\db\mysql\QueryBuilder::init()` asks the server whether it supports fractional seconds
 *    (QueryBuilder.php:401 -> Connection::getSlavePdo()) and therefore connects before it can
 *    build anything. The base builder emits the same clauses for everything this plugin uses.
 *
 * What it cannot prove is stated plainly: that MySQL and Postgres accept the SQL, that the
 * indexes are used, that DELETE and INSERT behave under concurrency, that the column widths in
 * the migration hold. Those need a server, and they belong to the acceptance test.
 */
final class FakeCraftDbConnection extends Connection
{
    /** @var list<array{table: string, columns: array<string, mixed>}> */
    public array $inserts = [];

    /** @var list<array{table: string, condition: array<mixed>|string, params: array<string, mixed>}> */
    public array $deletes = [];

    /** @var list<array{sql: string, params: array<string, mixed>}> */
    public array $statements = [];

    /** @var list<array<string, mixed>> Rows handed back to queryAll(). */
    public array $rows = [];

    /** Value handed back to queryScalar() - counts and the retention cut-off row id. */
    public mixed $scalar = null;

    public bool $tableThere = true;

    public ?Throwable $failTableCheck = null;
    public ?Throwable $failCommands = null;
    public ?Throwable $failInserts = null;
    public ?Throwable $failDeletes = null;

    public static function make(): self
    {
        // A DSN is needed only so getDriverName() can answer without connecting.
        return new self(['dsn' => 'mysql:host=127.0.0.1;port=1;dbname=keyway_test']);
    }

    /**
     * @inheritdoc
     */
    public function createCommand($sql = null, $params = []): FakeCraftDbCommand
    {
        if ($this->failCommands !== null) {
            throw $this->failCommands;
        }

        /** @var array<string, mixed> $params */
        return new FakeCraftDbCommand($this, $sql === null ? null : (string)$sql, $params);
    }

    /**
     * @inheritdoc
     */
    public function getQueryBuilder(): QueryBuilder
    {
        return new QueryBuilder($this);
    }

    /**
     * @inheritdoc
     */
    public function tableExists(string $table, ?bool $refresh = null): bool
    {
        if ($this->failTableCheck !== null) {
            throw $this->failTableCheck;
        }

        return $this->tableThere;
    }

    /** The last statement built, or null when nothing was queried. */
    public function lastSql(): ?string
    {
        return $this->statements === [] ? null : $this->statements[count($this->statements) - 1]['sql'];
    }

    /** @return array<string, mixed> */
    public function lastParams(): array
    {
        return $this->statements === [] ? [] : $this->statements[count($this->statements) - 1]['params'];
    }
}
