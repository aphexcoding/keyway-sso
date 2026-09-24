<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Keyway\Sso\Core\Port\StateStorageInterface;
use Keyway\Sso\Core\State\StateRecord;
use yii\caching\CacheInterface;
use yii\mutex\Mutex;

/**
 * StateStorageInterface on Craft's shared cache.
 *
 * WHY THE CACHE AND NOT THE SESSION, which is where the previous turn's note expected this to
 * land. The SAML HTTP-POST binding sends the identity provider's response as a form POST from
 * the IdP's origin to our ACS URL - a cross-site POST. Whether the session cookie rides along
 * is decided by its SameSite attribute, and in Craft that attribute is:
 *
 *   vendor/craftcms/cms/src/helpers/App.php:1209  'cookieParams' => Craft::cookieConfig()
 *   vendor/craftcms/cms/src/Craft.php:188         'sameSite' => $generalConfig->sameSiteCookieValue
 *   vendor/craftcms/cms/src/config/GeneralConfig.php:2725  public ?string $sameSiteCookieValue = null;
 *
 * Null means Craft emits no SameSite attribute, and a cookie with no attribute is treated as
 * Lax by current Chromium and Edge - so the cookie is withheld from a cross-site POST, and the
 * state we carefully saved is simply not there when the assertion comes back. Chromium's
 * "Lax+POST" grace period hides this for the first two minutes after the cookie is written,
 * which is worse than failing outright: it turns into a login that works while you are testing
 * and fails for the customer whose IdP made them re-authenticate. And `sameSiteCookieValue` is
 * a documented knob (the config file's own example sets it to 'Strict'), so on any site that
 * hardens it, session-backed state never works at all.
 *
 * The cache has no such problem: it is server-side and indifferent to cookies, which also makes
 * the IdP-initiated flow - where there is no prior request from this browser at all - work by
 * construction rather than by luck.
 *
 * WHAT THE CACHE COSTS US, and it is a real cost, not a technicality: the state is no longer
 * bound to the user agent that started the login. StateStore issues 32 random bytes, hands them
 * out inside RelayState / `state` and keeps only their SHA-256 (Core\State\StateStore), so the
 * token is unguessable - and unguessable is NOT what the specifications ask for here. RFC 6749
 * s10.12, RFC 6819 s5.3.5 and OpenID Connect Core s15.5.2 all require `state` to be bound to
 * the user agent's authenticated state, typically a hash of the session cookie, and they
 * require it precisely against login-CSRF, where the attacker HOLDS a perfectly valid token by
 * construction because the attacker is the one who started the flow. Unguessability does not
 * touch that attack.
 *
 * So this is an accepted risk, not compliance: SameSite makes a cookie unavailable at the SAML
 * ACS endpoint (above), and the choice is between a login that cannot be bound and a login that
 * does not work. The residual exposure is login-CSRF - an attacker splicing their own identity
 * into somebody else's browser - and the way to close it is a dedicated nonce cookie sent
 * `SameSite=None; Secure`, which belongs with the login controller and is deliberately not
 * invented here. Whoever builds that controller: this paragraph is the reason it is on the list.
 *
 * SINGLE USE. The record itself is written once and never rewritten. Consumption is recorded in
 * a separate key claimed through SingleUseKeys, which is the only atomic operation available;
 * find() overlays that marker onto the record. So the burnt flag cannot be lost by a lost
 * update, and markConsumed()'s answer comes from the atomic claim rather than from a read.
 * The find() call at the top of markConsumed() only NARROWS the field - it rejects unknown ids
 * cheaply - and is deliberately not where the race is decided.
 *
 * NOTHING IS SERIALISED AS AN OBJECT. The record goes in as an array of scalars and is rebuilt
 * field by field, with every type checked. A tampered cache entry therefore cannot become an
 * arbitrary object graph on unserialize(); the worst it can do is fail to rebuild, and then the
 * login is refused as if the state had expired.
 */
final class CraftStateStorage implements StateStorageInterface
{
    private const RECORD_PREFIX = 'keyway-sso.state.';
    private const CONSUMED_PREFIX = 'keyway-sso.state-burnt.';

    /**
     * The burnt marker must outlive the record it burns; if it expired first, a replay arriving
     * in the gap would find an unconsumed state. Outliving it only costs a few bytes.
     */
    private const CONSUMED_GRACE = 300;

    private CacheInterface $cache;
    private SingleUseKeys $singleUse;

    /**
     * ONE cache handle, and the claim primitive is built from it here rather than injected.
     *
     * Taking both separately reads as harmless dependency injection and is a fail-open hole: wire
     * SingleUseKeys to a request-scoped cache and $cache to the file cache, and markConsumed()
     * answers true, StateStore's read-back inside the same request agrees - and on the next
     * request the burnt marker is simply gone, so the replay is accepted. The record and the
     * marker that burns it have to live in the same store, so there is no way to ask for two.
     */
    public function __construct(CacheInterface $cache, ?Mutex $mutex)
    {
        $this->cache = $cache;
        $this->singleUse = new SingleUseKeys($cache, $mutex);
    }

    public function save(StateRecord $record): void
    {
        $ttl = max(1, $record->expiresAt - $record->createdAt);

        $this->cache->set(self::recordKey($record->id), [
            'id' => $record->id,
            'secretHash' => $record->secretHash,
            'returnUrl' => $record->returnUrl,
            'createdAt' => $record->createdAt,
            'expiresAt' => $record->expiresAt,
            'context' => $record->context(),
            'consumedAt' => $record->consumedAt,
        ], $ttl);
    }

    public function find(string $id): ?StateRecord
    {
        $stored = $this->cache->get(self::recordKey($id));
        $record = is_array($stored) ? self::hydrate($stored) : null;

        if ($record === null || $record->isConsumed()) {
            return $record;
        }

        $consumedAt = $this->singleUse->read(self::consumedKey($id));

        return $consumedAt === null ? $record : $record->withConsumedAt($consumedAt);
    }

    public function markConsumed(string $id, int $consumedAt): bool
    {
        $record = $this->find($id);

        // Cheap rejections only. The decision that matters is the claim below, because it is
        // the one that survives two requests arriving at the same millisecond.
        if ($record === null || $record->isConsumed()) {
            return false;
        }

        $ttl = max(1, $record->expiresAt - $consumedAt) + self::CONSUMED_GRACE;

        return $this->singleUse->claim(self::consumedKey($id), $consumedAt, $ttl);
    }

    /**
     * No-op by design: every entry carries a TTL, so the cache evicts expired state itself.
     * StateStorageInterface allows this explicitly for TTL-backed implementations.
     */
    public function purgeExpired(int $now): void
    {
    }

    /**
     * Keys are hashed rather than concatenated. The id is short and well-formed when it comes
     * from StateStore, but an adapter that trusts its caller to have validated the input is an
     * adapter that can be made to address another plugin's cache entry.
     */
    private static function recordKey(string $id): string
    {
        return self::RECORD_PREFIX . hash('sha256', $id);
    }

    private static function consumedKey(string $id): string
    {
        return self::CONSUMED_PREFIX . hash('sha256', $id);
    }

    /**
     * @param array<mixed> $stored
     */
    private static function hydrate(array $stored): ?StateRecord
    {
        foreach (['id', 'secretHash', 'returnUrl'] as $key) {
            if (!isset($stored[$key]) || !is_string($stored[$key])) {
                return null;
            }
        }

        foreach (['createdAt', 'expiresAt'] as $key) {
            if (!isset($stored[$key]) || !is_int($stored[$key])) {
                return null;
            }
        }

        $consumedAt = $stored['consumedAt'] ?? null;
        if ($consumedAt !== null && !is_int($consumedAt)) {
            return null;
        }

        $context = [];
        foreach (is_array($stored['context'] ?? null) ? $stored['context'] : [] as $key => $value) {
            if (is_string($key) && is_string($value)) {
                $context[$key] = $value;
            }
        }

        return new StateRecord(
            $stored['id'],
            $stored['secretHash'],
            $stored['returnUrl'],
            $stored['createdAt'],
            $stored['expiresAt'],
            $context,
            $consumedAt
        );
    }
}
