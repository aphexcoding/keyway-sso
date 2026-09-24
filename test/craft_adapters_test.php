<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftKeyValueCache;
use Keyway\Sso\Adapter\CraftReplayGuard;
use Keyway\Sso\Adapter\CraftStateStorage;
use Keyway\Sso\Adapter\SingleUseKeys;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateRecord;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Core\State\StateValidation;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\RecordingArrayCache;
use Keyway\Sso\Test\Support\RecordingMutex;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * The Craft-side implementations of four core ports, run against a REAL Yii cache.
 *
 * `yii\caching\ArrayCache` rather than a hand-written double on purpose: the whole point of
 * these adapters is that they lean on `Cache::add()` meaning "store only if absent", and a
 * double would simply agree with whatever the adapter believes. ArrayCache is the one backend
 * in the tree whose add() genuinely cannot race (one process, no yielding), so it is the right
 * place to pin the behaviour; SingleUseKeys documents, with file and line numbers, how much
 * weaker the guarantee is on Craft's default FileCache and why the mutex is there.
 *
 * What this suite cannot do is prove atomicity, because proving it needs two processes. It
 * proves the things that are provable in one: that the claim is won once, that the loser is
 * told so, that a lock which cannot be taken ends the attempt rather than bypassing it, and
 * that the TTLs satisfy the clauses the ports actually spell out.
 *
 * Skipped loudly when `vendor/` is absent, like craft_layer: a suite that returns [] in silence
 * reads as "all green" in the runner.
 */
if (!class_exists(\yii\caching\ArrayCache::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_adapters', 'skipped: vendor absent (run composer install)'));

    return [];
}

$record = static function (string $id = 'state-id-0001', int $createdAt = 1_000_000, int $ttl = 300): StateRecord {
    return new StateRecord(
        $id,
        hash('sha256', 'secret-' . $id),
        '/admin/entries',
        $createdAt,
        $createdAt + $ttl,
        ['connection' => 'okta', 'protocol' => 'saml']
    );
};

/**
 * Writes $payload into the cache under the key CraftStateStorage reads for $id, and returns
 * whatever find() then makes of it.
 *
 * The sanity write first is the point, not ceremony. The key layout is duplicated here because
 * there is no other way to plant a poisoned entry - and a duplicate that silently drifts away
 * from production would make every one of these cases pass for the WRONG reason: the adapter
 * would look at a key nobody wrote to, find nothing, and return the null the test expected.
 * So the helper proves the hand-built key really does address the adapter, and only then
 * overwrites it with the malformed payload.
 *
 * @param array<mixed> $payload
 */
$poison = static function (CraftStateStorage $storage, RecordingArrayCache $cache, array $payload): ?StateRecord {
    $key = 'keyway-sso.state.' . hash('sha256', 'poison-id');
    $sane = [
        'id' => 'poison-id',
        'secretHash' => hash('sha256', 'secret'),
        'returnUrl' => '/admin',
        'createdAt' => 1_000_000,
        'expiresAt' => 1_000_300,
        'context' => ['protocol' => 'saml'],
        'consumedAt' => null,
    ];

    $cache->set($key, $sane, 60);
    Assert::notNull(
        $storage->find('poison-id'),
        'the hand-built key must address the adapter, or this case proves nothing'
    );

    $cache->set($key, $payload, 60);

    return $storage->find('poison-id');
};

return [
    // -- SingleUseKeys: the primitive both single-use guarantees are built on -----------------

    'a key is claimed by exactly one caller' => static function (): void {
        $keys = new SingleUseKeys(new RecordingArrayCache(), null);

        Assert::true($keys->claim('k', 11, 60), 'first caller wins');
        Assert::false($keys->claim('k', 22, 60), 'second caller loses');
        Assert::false($keys->claim('k', 33, 60), 'and stays losing');
    },

    'the claim records when it happened, so a reader can say when' => static function (): void {
        $keys = new SingleUseKeys(new RecordingArrayCache(), null);

        Assert::null($keys->read('k'), 'an unclaimed key reads as null');
        $keys->claim('k', 1_234, 60);
        Assert::same(1_234, $keys->read('k'));
        Assert::null($keys->read('other'));
    },

    'the loser does not overwrite the winner\'s value' => static function (): void {
        $keys = new SingleUseKeys(new RecordingArrayCache(), null);

        $keys->claim('k', 1_000, 60);
        $keys->claim('k', 2_000, 60);

        Assert::same(1_000, $keys->read('k'));
    },

    'a zero duration never reaches the cache, because Yii reads it as forever' => static function (): void {
        $cache = new RecordingArrayCache();
        $keys = new SingleUseKeys($cache, null);

        $keys->claim('k', 1, 0);
        Assert::same(1, $cache->lastDuration());

        $keys->claim('k2', 1, -50);
        Assert::same(1, $cache->lastDuration());
    },

    // The clause that cannot be tested by behaviour in one process: nothing races here, so a
    // read-then-write implementation would pass every case above. What CAN be pinned is which
    // primitive is used - `add()` is the compare-and-set the ports demand, `get()` + `set()` is
    // the implementation they forbid - and that is what this case guards against a future edit.
    'the claim goes through Cache::add() on both branches, never through get() and set()' => static function (): void {
        // BOTH branches, and the one with the mutex is the one that matters: it is the branch a
        // customer actually runs, and testing only the mutex-less branch left the production
        // path free to be rewritten as read-then-write with the whole suite still green.
        foreach (['no mutex' => null, 'with mutex' => new RecordingMutex()] as $label => $mutex) {
            $cache = new RecordingArrayCache();
            $keys = new SingleUseKeys($cache, $mutex);

            Assert::true($keys->claim('k', 1, 60), $label . ': first caller wins');
            Assert::false($keys->claim('k', 2, 60), $label . ': second caller loses');

            Assert::same(2, $cache->addCount(), $label . ': both attempts used add()');
            Assert::same(0, $cache->plainSetCount(), $label . ': nothing fell back to a plain set()');
        }
    },

    'the lock is taken around the write and given back' => static function (): void {
        $mutex = new RecordingMutex();
        $keys = new SingleUseKeys(new RecordingArrayCache(), $mutex);

        Assert::true($keys->claim('k', 1, 60));
        Assert::sameList(['k'], $mutex->acquired);
        Assert::sameList(['k'], $mutex->released);
    },

    // Fail closed. "I could not prove I was first" has to read as "I was not first", because the
    // caller turns a true into a signed-in session - and the unprotected add() underneath is
    // exactly the read-then-write the port forbids.
    'a lock that cannot be taken ends the claim instead of bypassing it' => static function (): void {
        $cache = new RecordingArrayCache();
        $mutex = new RecordingMutex();
        $keys = new SingleUseKeys($cache, $mutex);

        $mutex->grant = false;

        Assert::false($keys->claim('k', 1, 60));
        Assert::same(0, $cache->writeCount(), 'nothing was written behind the lock\'s back');

        // Proof that the key really is untouched: the next caller that does get the lock wins it.
        $mutex->grant = true;
        Assert::true($keys->claim('k', 1, 60));
    },

    // Guards the two constructor shapes that are security decisions, not style:
    //  - a defaulted mutex would let a caller drop the compare-and-set to a read-then-write by
    //    forgetting an argument;
    //  - two cache handles on CraftStateStorage would let the record and the marker that burns
    //    it live in different stores, which fails OPEN: the marker vanishes next request and
    //    the replay is accepted.
    'the constructors do not offer a way to weaken the guarantee' => static function (): void {
        $mutex = (new ReflectionMethod(SingleUseKeys::class, '__construct'))->getParameters()[1];

        Assert::same('mutex', $mutex->name);
        Assert::false($mutex->isDefaultValueAvailable(), 'the mutex must be passed, even as null');

        $storage = (new ReflectionMethod(CraftStateStorage::class, '__construct'))->getParameters();

        Assert::same(2, count($storage));
        Assert::same('yii\\caching\\CacheInterface', (string)$storage[0]->getType());
        Assert::same('?yii\\mutex\\Mutex', (string)$storage[1]->getType());
    },

    // -- CraftKeyValueCache: discovery, JWKS, the C5 refresh limit ----------------------------

    'a document round-trips through the shared cache' => static function (): void {
        $kv = new CraftKeyValueCache(new RecordingArrayCache());

        Assert::null($kv->get('jwks'), 'a miss is null, not false');

        $kv->set('jwks', ['keys' => [['kid' => 'a']]], 600);

        Assert::same(['keys' => [['kid' => 'a']]], $kv->get('jwks'));
    },

    // A rotated key set that never expires is a rotation that never takes effect.
    'a zero ttl does not cache a document forever' => static function (): void {
        $cache = new RecordingArrayCache();
        $kv = new CraftKeyValueCache($cache);

        $kv->set('discovery', ['issuer' => 'https://idp.example.com'], 0);

        Assert::same(1, $cache->lastDuration());
        Assert::notSame(0, $cache->lastDuration(), 'Yii reads 0 as "keep forever"');
    },

    'an entry that is not an array is treated as a miss' => static function (): void {
        $cache = new RecordingArrayCache();
        $kv = new CraftKeyValueCache($cache);

        // The key layout is duplicated here knowingly - there is no other way to plant an entry
        // we did not write. The sanity read comes first so that a layout drift shows up as a
        // failure: without it, a renamed prefix would make this case pass for the wrong reason,
        // the adapter looking at a key nobody touched and correctly finding nothing.
        $cache->set('keyway-sso.kv.jwks', ['keys' => []], 60);
        Assert::same(['keys' => []], $kv->get('jwks'), 'the hand-built key must address the adapter');

        // Written the way a different plugin, or an older build, might have left it there.
        $cache->set('keyway-sso.kv.jwks', 'not-an-array', 60);

        Assert::null($kv->get('jwks'));
    },

    // -- CraftStateStorage --------------------------------------------------------------------

    'a state record round-trips verbatim, secret hash included' => static function () use ($record): void {
        $storage = new CraftStateStorage($cache = new RecordingArrayCache(), null);
        $original = $record();

        $storage->save($original);
        $found = $storage->find($original->id);

        Assert::notNull($found);
        Assert::same($original->id, $found->id);
        Assert::same($original->secretHash, $found->secretHash);
        Assert::same('/admin/entries', $found->returnUrl);
        Assert::same($original->createdAt, $found->createdAt);
        Assert::same($original->expiresAt, $found->expiresAt);
        Assert::same(['connection' => 'okta', 'protocol' => 'saml'], $found->context());
        Assert::false($found->isConsumed());
    },

    'an unknown id is null rather than an exception' => static function (): void {
        $storage = new CraftStateStorage($cache = new RecordingArrayCache(), null);

        Assert::null($storage->find('never-saved'));
    },

    'the state lifetime is the cache lifetime' => static function () use ($record): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        $storage->save($record('abc', 1_000_000, 420));

        Assert::same(420, $cache->lastDuration());
    },

    'exactly one caller burns the state' => static function () use ($record): void {
        $storage = new CraftStateStorage($cache = new RecordingArrayCache(), null);
        $storage->save($record());

        Assert::true($storage->markConsumed('state-id-0001', 1_000_100));
        Assert::false($storage->markConsumed('state-id-0001', 1_000_101));
        Assert::false($storage->markConsumed('state-id-0001', 1_000_102));
    },

    // StateStore reads the record back after markConsumed() and refuses the login with
    // STORAGE_UNCONFIRMED unless it can SEE the flag. An adapter that returns true without
    // leaving a visible mark is the failure that check exists for.
    'a burnt state reads as burnt, which is what StateStore verifies' => static function () use ($record): void {
        $storage = new CraftStateStorage($cache = new RecordingArrayCache(), null);
        $storage->save($record());

        $storage->markConsumed('state-id-0001', 1_000_123);
        $found = $storage->find('state-id-0001');

        Assert::notNull($found);
        Assert::true($found->isConsumed());
        Assert::same(1_000_123, $found->consumedAt);
    },

    'a state that was never saved cannot be burnt' => static function (): void {
        $storage = new CraftStateStorage($cache = new RecordingArrayCache(), null);

        Assert::false($storage->markConsumed('never-saved', 1_000_000));
    },

    // If the marker expired first, a replay arriving in the gap would find an unconsumed state.
    'the burnt marker outlives the record it burns' => static function () use ($record): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        $storage->save($record('abc', 1_000_000, 300));
        $recordTtl = $cache->lastDuration();

        $storage->markConsumed('abc', 1_000_000);
        $markerTtl = $cache->lastDuration();

        Assert::same(300, $recordTtl);
        Assert::true($markerTtl > $recordTtl, 'marker ttl ' . $markerTtl . ' > record ttl ' . $recordTtl);
    },

    // -- hydrate(): one case per guard ---------------------------------------------------------
    //
    // The docblock promises "every type checked". Until now a single fixture stood for all four
    // guards, and since ANY of them rejected it, removing any ONE of them killed nothing - the
    // promise had no cover at all. One malformed field per case, so each guard is the only thing
    // standing between the cache and a StateRecord.

    'a record whose string fields are not strings is refused' => static function () use ($poison): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        Assert::null($poison($storage, $cache, [
            'id' => 12_345,
            'secretHash' => hash('sha256', 'secret'),
            'returnUrl' => '/admin',
            'createdAt' => 1_000_000,
            'expiresAt' => 1_000_300,
            'context' => ['protocol' => 'saml'],
            'consumedAt' => null,
        ]), 'a numeric id is not a string id');
    },

    'a record whose timestamps are not integers is refused' => static function () use ($poison): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        Assert::null($poison($storage, $cache, [
            'id' => 'poison-id',
            'secretHash' => hash('sha256', 'secret'),
            'returnUrl' => '/admin',
            'createdAt' => '1000000',
            'expiresAt' => 1_000_300,
            'context' => ['protocol' => 'saml'],
            'consumedAt' => null,
        ]), 'a numeric string is not an int timestamp');
    },

    // Its own guard because it is the only nullable field: `null` is legitimate here and must
    // not be confused with "wrong type", which is how a lazy check ends up accepting a string.
    'a record whose consumed marker is not an integer is refused' => static function () use ($poison): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        Assert::null($poison($storage, $cache, [
            'id' => 'poison-id',
            'secretHash' => hash('sha256', 'secret'),
            'returnUrl' => '/admin',
            'createdAt' => 1_000_000,
            'expiresAt' => 1_000_300,
            'context' => ['protocol' => 'saml'],
            'consumedAt' => 'yesterday',
        ]), 'a consumed marker that is not a timestamp is not a timestamp');
    },

    // The fourth guard does not reject the record - it filters the context, because a bad pair
    // in there is not a reason to fail a login. The record survives; the bad pair does not.
    'a context entry that is not a string pair is dropped, not carried' => static function () use ($poison): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        $found = $poison($storage, $cache, [
            'id' => 'poison-id',
            'secretHash' => hash('sha256', 'secret'),
            'returnUrl' => '/admin',
            'createdAt' => 1_000_000,
            'expiresAt' => 1_000_300,
            'context' => [5 => 'okta', 'protocol' => 'saml', 'depth' => 3],
            'consumedAt' => null,
        ]);

        Assert::notNull($found, 'a bad context pair does not fail the login');
        Assert::same(['protocol' => 'saml'], $found->context());
    },

    // -- key layout -----------------------------------------------------------------------------

    // Pins the hashing itself. Without this, `hash('sha256', $id)` could be dropped from the
    // adapter and every behavioural case would still pass, because they all write and read
    // through the same (mutated) key function.
    'the state key is the prefix plus the hash of the id' => static function () use ($record): void {
        $cache = new RecordingArrayCache();
        $storage = new CraftStateStorage($cache, null);

        $storage->save($record('abc'));
        $written = $cache->lastKey();

        // Built through a real cache so Yii's own buildKey() is applied to both sides; the test
        // pins the layout, not Yii's internal hashing of it.
        $expected = new RecordingArrayCache();
        $expected->set('keyway-sso.state.' . hash('sha256', 'abc'), 'x', 60);

        Assert::same($expected->lastKey(), $written);
    },

    // The port exists for one consumer. This is that consumer, wired to this adapter.
    'StateStore on this adapter issues a token and refuses its replay' => static function (): void {
        $cache = new RecordingArrayCache();
        $store = new StateStore(
            new CraftStateStorage($cache, new RecordingMutex()),
            new FixedClock(1_000_000),
            new SequenceRandomSource(),
            new RedirectGuard([], '/'),
            300
        );

        $token = $store->issue('/admin/entries', ['connection' => 'okta']);

        $first = $store->consume($token->value);
        Assert::true($first->valid, 'reason: ' . $first->reasonCode);
        Assert::same('/admin/entries', $first->returnUrl);
        Assert::same('okta', $first->context()['connection']);

        $replay = $store->consume($token->value);
        Assert::false($replay->valid);
        Assert::same(StateValidation::ALREADY_USED, $replay->reasonCode);
    },

    'StateStore on this adapter refuses a token whose window has passed' => static function (): void {
        $cache = new RecordingArrayCache();
        $clock = new FixedClock(1_000_000);
        $store = new StateStore(
            new CraftStateStorage($cache, null),
            $clock,
            new SequenceRandomSource(),
            new RedirectGuard([], '/'),
            300
        );

        $token = $store->issue('/admin');
        $clock->advance(301);

        $result = $store->consume($token->value);

        Assert::false($result->valid);
        Assert::same(StateValidation::EXPIRED, $result->reasonCode);
    },

    // -- CraftReplayGuard: the identifier the IdP issued, not the one we issued ----------------

    'an assertion id is accepted once' => static function (): void {
        $cache = new RecordingArrayCache();
        $clock = new FixedClock(1_000_000);
        $guard = new CraftReplayGuard(new SingleUseKeys($cache, null), $clock);

        Assert::true($guard->remember('_assertion-1', 1_000_300));
        Assert::false($guard->remember('_assertion-1', 1_000_300));
    },

    'the replay key is the prefix plus the hash of the identifier' => static function (): void {
        $cache = new RecordingArrayCache();
        $guard = new CraftReplayGuard(new SingleUseKeys($cache, null), new FixedClock(1_000_000));

        $guard->remember('_assertion-1', 1_000_300);
        $written = $cache->lastKey();

        $expected = new RecordingArrayCache();
        $expected->set('keyway-sso.replay.' . hash('sha256', '_assertion-1'), 'x', 60);

        Assert::same($expected->lastKey(), $written);
    },

    'two different identifiers do not collide' => static function (): void {
        $cache = new RecordingArrayCache();
        $guard = new CraftReplayGuard(new SingleUseKeys($cache, null), new FixedClock(1_000_000));

        Assert::true($guard->remember('_assertion-1', 1_000_300));
        Assert::true($guard->remember('_assertion-2', 1_000_300));
        Assert::true($guard->remember('jti-abc', 1_000_300));
        Assert::false($guard->remember('_assertion-2', 1_000_300));
    },

    // "Retention: at least until $expiresAt." Forgetting early re-opens the window; forgetting
    // late only costs storage, so the TTL is allowed to be generous and never allowed to be short.
    'the guard does not forget before the window closes' => static function (): void {
        $cache = new RecordingArrayCache();
        $guard = new CraftReplayGuard(new SingleUseKeys($cache, null), new FixedClock(1_000_000));

        $guard->remember('_assertion-1', 1_000_900);

        Assert::true(
            $cache->lastDuration() >= 900,
            'ttl ' . $cache->lastDuration() . ' must cover the 900s left in the window'
        );
    },

    'an identifier that is already expiring is still held for a usable minimum' => static function (): void {
        $cache = new RecordingArrayCache();
        $guard = new CraftReplayGuard(new SingleUseKeys($cache, null), new FixedClock(1_000_000));

        Assert::true($guard->remember('_stale', 999_000), 'a stale id is still recorded');
        Assert::true($cache->lastDuration() >= 60, 'a one-second guard stops guarding mid-flight');
        Assert::false($guard->remember('_stale', 999_000));
    },
];
