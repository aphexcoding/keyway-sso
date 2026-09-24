<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\StateStorageInterface;
use Keyway\Sso\Core\State\StateRecord;

/**
 * Reference implementation of the storage contract, including the atomic markConsumed().
 * Single-process, so "atomic" here is simply "checks and writes without yielding".
 */
final class InMemoryStateStorage implements StateStorageInterface
{
    /** @var array<string, StateRecord> */
    private array $records = [];

    public function save(StateRecord $record): void
    {
        $this->records[$record->id] = $record;
    }

    public function find(string $id): ?StateRecord
    {
        return $this->records[$id] ?? null;
    }

    public function markConsumed(string $id, int $consumedAt): bool
    {
        $record = $this->records[$id] ?? null;

        if ($record === null || $record->isConsumed()) {
            return false;
        }

        $this->records[$id] = $record->withConsumedAt($consumedAt);

        return true;
    }

    public function purgeExpired(int $now): void
    {
        foreach ($this->records as $id => $record) {
            if ($record->isExpired($now)) {
                unset($this->records[$id]);
            }
        }
    }

    public function count(): int
    {
        return count($this->records);
    }
}
