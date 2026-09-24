<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use yii\caching\CacheInterface;
use yii\mutex\Mutex;

/**
 * "Claim this key, and tell me truthfully whether I was first."
 *
 * Both single-use guarantees in the plugin reduce to this one question:
 * StateStorageInterface::markConsumed() burns the state token this site issued, and
 * ReplayGuardInterface::remember() burns the identifier the identity provider issued. Neither
 * contract is satisfied by "read, check, write" - two requests racing there both see an unused
 * key and both win, which is precisely the replay the contracts exist to stop. So the primitive
 * lives in one class, with one honest account of how strong it actually is.
 *
 * HOW STRONG IT ACTUALLY IS, measured in this vendor tree rather than assumed:
 *
 *  - `yii\caching\Cache::add()` (vendor/yiisoft/yii2/caching/Cache.php:379) forwards to the
 *    backend's `addValue()`, whose documented job is "store only if the key is absent".
 *  - On Memcached that is the server-side `add` command and on Redis a `SET ... NX`: a real
 *    compare-and-set, atomic across processes and across machines.
 *  - ON CRAFT'S DEFAULT BACKEND IT IS NOT. Craft configures `yii\caching\FileCache`
 *    (vendor/craftcms/cms/src/helpers/App.php:1018-1030), and FileCache::addValue()
 *    (vendor/yiisoft/yii2/caching/FileCache.php:187-195) is `@filemtime($file) > time()`
 *    followed by setValue() - a read, a check and a write, with a window between them. Two
 *    concurrent requests can both find no file and both be told they were first.
 *
 * That window is why this class takes a mutex. Craft ships one: the `mutex` component
 * (vendor/craftcms/cms/src/config/app.php:87) whose default driver is App::dbMutexConfig()
 * (App.php:1141-1155) - MysqlMutex, i.e. `GET_LOCK` (vendor/yiisoft/yii2/mutex/MysqlMutex.php:68-81),
 * or PgsqlMutex advisory locks. Those ARE mutual exclusion across processes, so wrapping the
 * add() in one closes the FileCache window on a normal install.
 *
 * Two behaviours that are deliberate, not oversights:
 *
 *  - NO LOCK, NO CLAIM. When the mutex cannot be acquired within the timeout, claim() returns
 *    false. It does not fall through to a bare add(). "I could not prove I was first" must read
 *    as "I was not first", because the caller turns a true into a signed-in session.
 *  - A FAILED WRITE ALSO READS AS FALSE. `add()` returns false both for "somebody already has
 *    it" and for "the disk is full". They are indistinguishable here and both deny the login,
 *    which is the safe direction; StateStore's read-back (Core\State\StateStore::consume())
 *    turns the second case into STORAGE_UNCONFIRMED rather than a silent accept.
 *
 * The mutex is nullable but NOT optional: there is no default. A forgotten argument on the one
 * security primitive in the product would silently drop the compare-and-set to a read-then-write
 * on Craft's default FileCache, and it would look exactly like working code. Passing null has to
 * be a decision somebody typed - which, in the suite, it is, because a single process cannot
 * race itself and the lock would only measure itself.
 */
final class SingleUseKeys
{
    /**
     * Seconds to wait for the lock. Long enough to outlast a competing request that is doing
     * the same short cache write, short enough that a wedged lock fails the login instead of
     * holding a PHP worker open.
     */
    private const LOCK_TIMEOUT = 3;

    private CacheInterface $cache;
    private ?Mutex $mutex;

    public function __construct(CacheInterface $cache, ?Mutex $mutex)
    {
        $this->cache = $cache;
        $this->mutex = $mutex;
    }

    /**
     * @param string $key   Full cache key; callers namespace and hash it themselves.
     * @param int    $value Stored so that a later read can say WHEN the key was claimed.
     * @param int    $ttl   Seconds. Never 0 - Yii reads 0 as "keep forever".
     * @return bool True only for the caller that claimed the key.
     */
    public function claim(string $key, int $value, int $ttl): bool
    {
        $ttl = max(1, $ttl);

        if ($this->mutex === null) {
            return $this->cache->add($key, $value, $ttl);
        }

        if (!$this->mutex->acquire($key, self::LOCK_TIMEOUT)) {
            return false;
        }

        try {
            return $this->cache->add($key, $value, $ttl);
        } finally {
            // craft\mutex\MutexTrait::release() defers the release to the end of an open DB
            // transaction; that is Craft's business and harmless here, because the deferred
            // lock is re-acquired for free by the same request and released at request end.
            $this->mutex->release($key);
        }
    }

    /**
     * The value a previous claim() stored, or null when the key was never claimed (or expired).
     */
    public function read(string $key): ?int
    {
        $value = $this->cache->get($key);

        return is_int($value) ? $value : null;
    }
}
