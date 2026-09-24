<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use yii\caching\ArrayCache;

/**
 * A REAL yii\caching\ArrayCache that also remembers the durations it was handed.
 *
 * Not a stand-in for the cache: every read and write goes through Yii's own implementation, so
 * the adapters are exercised against the same `add()` / `set()` / `get()` semantics they will
 * meet in production (ArrayCache::addValue() is the one backend in the tree whose "store only
 * if absent" really is atomic, because a single process cannot race itself).
 *
 * The recording exists because two clauses of the port contracts are about the TTL and are
 * otherwise unobservable without sleeping: "never longer than asked" (a zero duration means
 * FOREVER in Yii, which would freeze a rotated JWKS in place) and "do not forget before the
 * expiry" in ReplayGuardInterface.
 */
final class RecordingArrayCache extends ArrayCache
{
    /** @var list<array{key: string, duration: int, added: bool|null}> */
    private array $writes = [];

    /**
     * @param string $key
     * @param mixed $value
     * @param int $duration
     */
    protected function setValue($key, $value, $duration): bool
    {
        $this->writes[] = ['key' => (string)$key, 'duration' => (int)$duration, 'added' => null];

        return parent::setValue($key, $value, $duration);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @param int $duration
     */
    protected function addValue($key, $value, $duration): bool
    {
        $added = parent::addValue($key, $value, $duration);
        $this->writes[] = ['key' => (string)$key, 'duration' => (int)$duration, 'added' => $added];

        return $added;
    }

    /**
     * @return list<int> Durations handed to the backend, oldest first.
     */
    public function durations(): array
    {
        return array_map(static fn(array $write): int => $write['duration'], $this->writes);
    }

    /**
     * The key as Yii built it (buildKey() hashes anything long or non-alphanumeric).
     *
     * Comparing two of these is how a test pins the key LAYOUT without reimplementing
     * buildKey(): write through the adapter, write the expected raw key through the cache, and
     * the two recorded keys must be the same string.
     */
    public function lastKey(): ?string
    {
        $last = end($this->writes);

        return $last === false ? null : $last['key'];
    }

    public function lastDuration(): ?int
    {
        $last = end($this->writes);

        return $last === false ? null : $last['duration'];
    }

    public function writeCount(): int
    {
        return count($this->writes);
    }

    /**
     * How many writes went through `add()` (store only if absent) rather than `set()`.
     *
     * The only structural check available for the atomicity clause: a single-process suite
     * cannot tell a compare-and-set apart from a read-then-write by behaviour alone, because
     * nothing races. It can tell them apart by which cache primitive was used.
     */
    public function addCount(): int
    {
        return count(array_filter($this->writes, static fn(array $write): bool => $write['added'] !== null));
    }

    public function plainSetCount(): int
    {
        return count(array_filter($this->writes, static fn(array $write): bool => $write['added'] === null));
    }
}
