<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\StateStorageInterface;
use Keyway\Sso\Core\State\StateRecord;

/**
 * A deliberately broken storage: markConsumed() always reports success, the way a naive cache
 * adapter or a legacy implementation would. Used to prove StateStore does not depend on the
 * storage alone for replay protection.
 *
 * Note what this double does NOT cover, because it was read as covering it once already: it lies
 * about enforcement but still writes the consumption, so the flag check catches the replay. The
 * storage that reports success and writes nothing is AmnesiacStateStorage, and it needs a
 * different defence (the read-back in StateStore::consume()).
 */
final class PermissiveStateStorage implements StateStorageInterface
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
        if ($record !== null) {
            $this->records[$id] = $record->withConsumedAt($consumedAt);
        }

        return true;
    }

    public function purgeExpired(int $now): void
    {
    }
}
