<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Support;

use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\KeyValueCacheInterface;

/**
 * Request-scoped fallback cache.
 *
 * Correct but weak: it lives and dies with the PHP process, so the C5 rate limit it backs is
 * only exact within one request. It exists so the protocol layer can be constructed without a
 * cache at all; the Craft adapter passes the site cache instead, and that is the configuration
 * the contract assumes.
 */
final class InMemoryKeyValueCache implements KeyValueCacheInterface
{
    /** @var array<string, array{expires: int, value: array<mixed>}> */
    private array $entries = [];

    private ClockInterface $clock;

    public function __construct(ClockInterface $clock)
    {
        $this->clock = $clock;
    }

    public function get(string $key): ?array
    {
        $entry = $this->entries[$key] ?? null;

        if ($entry === null) {
            return null;
        }

        if ($this->clock->now() >= $entry['expires']) {
            unset($this->entries[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function set(string $key, array $value, int $ttl): void
    {
        $this->entries[$key] = [
            'expires' => $this->clock->now() + max(1, $ttl),
            'value' => $value,
        ];
    }
}
