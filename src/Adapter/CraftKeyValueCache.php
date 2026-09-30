<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Keyway\Sso\Core\Port\KeyValueCacheInterface;
use yii\caching\CacheInterface;

/**
 * KeyValueCacheInterface on Craft's shared cache: OIDC discovery documents, JWKS, and the
 * bookkeeping that makes contract C5's "at most one JWKS refresh per rejected kid" hold across
 * requests instead of only within one.
 *
 * Three things this thin class actually does, none of them decorative:
 *
 *  - NEVER PASSES A ZERO DURATION. `yii\caching\Cache::set()` reads 0 as "keep forever"
 *    (vendor/yiisoft/yii2/caching/Cache.php:239-256, FileCache turns 0 into a year), and a JWKS
 *    cached forever is a key rotation that never takes effect. The port says implementations
 *    may store shorter, never longer, so the duration is floored at one second and passed
 *    explicitly - passing null would instead pick up Craft's global `cacheDuration`.
 *  - RETURNS NULL FOR ANYTHING THAT IS NOT AN ARRAY. Yii answers `false` for a miss; the port
 *    answers null, and the callers use `?? null` semantics. A cache entry that came back as a
 *    string or an object is treated as a miss rather than handed on.
 *  - NAMESPACES ITS KEYS. The cache is shared with Craft and every other plugin.
 */
final class CraftKeyValueCache implements KeyValueCacheInterface
{
    private const KEY_PREFIX = 'keyway-sso.kv.';

    private CacheInterface $cache;

    public function __construct(CacheInterface $cache)
    {
        $this->cache = $cache;
    }

    public function get(string $key): ?array
    {
        $value = $this->cache->get(self::KEY_PREFIX . $key);

        return is_array($value) ? $value : null;
    }

    public function set(string $key, array $value, int $ttl): void
    {
        $this->cache->set(self::KEY_PREFIX . $key, $value, max(1, $ttl));
    }
}
