<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * Small shared cache for documents fetched from the IdP (discovery, JWKS) and for the
 * bookkeeping that makes contract C5's rate limit real.
 *
 * Why a port and not a static array: C5 asks for "at most one refresh per rejected `kid`,
 * rate-limited". Kept in the object, that promise only holds within a single PHP request, and a
 * flood of tokens carrying random `kid`s would still turn into one JWKS fetch per request
 * against the IdP. Kept here, the Craft adapter hands over the site cache and the limit holds
 * across requests.
 *
 * Values are plain arrays on purpose - nothing serialises an object into a shared cache, so a
 * poisoned cache entry cannot become a poisoned object graph.
 */
interface KeyValueCacheInterface
{
    /**
     * @return array<mixed>|null Null when absent or expired.
     */
    public function get(string $key): ?array;

    /**
     * @param array<mixed> $value
     * @param int          $ttl Seconds; implementations may store shorter, never longer.
     */
    public function set(string $key, array $value, int $ttl): void;
}
