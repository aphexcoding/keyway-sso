<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\StateStorageInterface;
use Keyway\Sso\Core\State\StateRecord;

/**
 * The dangerous kind of broken storage: markConsumed() reports success and writes nothing.
 *
 * This is not a strawman. It is what a plugin gets from a cache adapter whose write silently
 * fails (full memcached, read-only Redis replica, APCu in a second FPM worker), from a TTL-only
 * adapter that cannot update an entry in place, and from any implementation whose author read
 * "return bool" as "return true unless I threw". PermissiveStateStorage does not cover this
 * case: it lies about enforcement but still records the consumption, so the flag check on the
 * next request saves us. Here nothing is recorded, so nothing saves us but the read-back in
 * StateStore::consume().
 */
final class AmnesiacStateStorage implements StateStorageInterface
{
    /** @var array<string, StateRecord> */
    private array $records = [];

    private int $markConsumedCalls = 0;

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
        $this->markConsumedCalls++;

        // Deliberately no write: "it worked, trust me".
        return true;
    }

    public function purgeExpired(int $now): void
    {
    }

    public function markConsumedCalls(): int
    {
        return $this->markConsumedCalls;
    }
}
