<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Throwable;

/**
 * The command object FakeCraftDbConnection hands out: records what it was asked to do and
 * answers with canned data instead of talking to a server.
 *
 * Not a subclass of `yii\db\Command` on purpose - `Connection::createCommand()` declares no
 * return type, and extending the real command would drag in a constructor that wants a live
 * PDO. What matters here is the four methods Db::insert(), Db::delete() and Query::all() /
 * ::scalar() / ::count() actually call.
 */
final class FakeCraftDbCommand
{
    private FakeCraftDbConnection $connection;
    private ?string $sql;

    /** @var array<string, mixed> */
    private array $params;

    /**
     * @param array<string, mixed> $params
     */
    public function __construct(FakeCraftDbConnection $connection, ?string $sql, array $params)
    {
        $this->connection = $connection;
        $this->sql = $sql;
        $this->params = $params;
    }

    /**
     * @param array<string, mixed> $columns
     */
    public function insert(string $table, array $columns): self
    {
        $this->throwIf($this->connection->failInserts);
        $this->connection->inserts[] = ['table' => $table, 'columns' => $columns];

        return $this;
    }

    /**
     * @param array<mixed>|string $condition
     * @param array<string, mixed> $params
     */
    public function delete(string $table, array|string $condition = '', array $params = []): self
    {
        $this->throwIf($this->connection->failDeletes);
        $this->connection->deletes[] = ['table' => $table, 'condition' => $condition, 'params' => $params];

        return $this;
    }

    public function execute(): int
    {
        return 1;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function queryAll(): array
    {
        $this->remember();

        return $this->connection->rows;
    }

    public function queryScalar(): mixed
    {
        $this->remember();

        return $this->connection->scalar;
    }

    private function remember(): void
    {
        $this->connection->statements[] = ['sql' => (string)$this->sql, 'params' => $this->params];
    }

    private function throwIf(?Throwable $error): void
    {
        if ($error !== null) {
            throw $error;
        }
    }
}
