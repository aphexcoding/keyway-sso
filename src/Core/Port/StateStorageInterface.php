<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\State\StateRecord;

/**
 * Persistence for in-flight login state (SAML RelayState / OIDC `state`).
 *
 * Contract for implementers (Craft cache, database table, session):
 *  - `save()` MUST store the record verbatim, including the secret hash.
 *  - `markConsumed()` MUST be atomic. It is the single-use guarantee of the whole flow:
 *    it returns true for the first caller only, and false for every replay, even when two
 *    requests race. An implementation that reads, checks and writes without a transaction
 *    or an atomic compare-and-set breaks replay protection.
 *  - `find()` MUST return null for unknown ids rather than throwing.
 */
interface StateStorageInterface
{
    public function save(StateRecord $record): void;

    public function find(string $id): ?StateRecord;

    /**
     * @return bool True when this call flipped the record from unused to used.
     */
    public function markConsumed(string $id, int $consumedAt): bool;

    /**
     * Housekeeping; implementations backed by a TTL cache may no-op.
     */
    public function purgeExpired(int $now): void;
}
