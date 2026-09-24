<?php

declare(strict_types=1);

use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateRecord;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Core\State\StateValidation;
use Keyway\Sso\Test\Support\AmnesiacStateStorage;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\InMemoryStateStorage;
use Keyway\Sso\Test\Support\PermissiveStateStorage;
use Keyway\Sso\Test\Support\SequenceRandomSource;

/**
 * @return array{0: StateStore, 1: InMemoryStateStorage, 2: FixedClock}
 */
$build = static function (int $ttl = 300, array $origins = [], string $default = '/'): array {
    $storage = new InMemoryStateStorage();
    $clock = new FixedClock(1_000_000);
    $store = new StateStore(
        $storage,
        $clock,
        new SequenceRandomSource(),
        new RedirectGuard($origins, $default),
        $ttl
    );

    return [$store, $storage, $clock];
};

return [
    'a fresh token round-trips' => static function () use ($build): void {
        [$store, , $clock] = $build();

        $token = $store->issue('/admin/entries', ['connection' => 'okta']);
        $result = $store->consume($token->value);

        Assert::true($result->valid);
        Assert::same(StateValidation::OK, $result->reasonCode);
        Assert::same('/admin/entries', $result->returnUrl);
        Assert::same('okta', $result->context()['connection']);
        Assert::same($token->id, $result->id);
        Assert::same($clock->now() + 300, $token->expiresAt);
    },

    'a token is single use' => static function () use ($build): void {
        [$store] = $build();

        $token = $store->issue('/admin');

        Assert::true($store->consume($token->value)->valid);

        $replay = $store->consume($token->value);
        Assert::false($replay->valid);
        Assert::same(StateValidation::ALREADY_USED, $replay->reasonCode);
        Assert::null($replay->returnUrl);
    },

    'a token expires exactly at the TTL boundary' => static function () use ($build): void {
        [$store, , $clock] = $build(60);

        $token = $store->issue('/admin');
        $clock->advance(59);
        Assert::true($store->consume($token->value)->valid, 'still inside the window');

        $second = $store->issue('/admin');
        $clock->advance(60);
        $result = $store->consume($second->value);

        Assert::false($result->valid);
        Assert::same(StateValidation::EXPIRED, $result->reasonCode);
    },

    'a tampered secret is rejected and does not burn the state' => static function () use ($build): void {
        [$store] = $build();

        $token = $store->issue('/admin');
        $forged = $token->id . '.' . str_repeat('A', 43);

        $rejected = $store->consume($forged);
        Assert::false($rejected->valid);
        Assert::same(StateValidation::SECRET_MISMATCH, $rejected->reasonCode);

        Assert::true(
            $store->consume($token->value)->valid,
            'knowing only the id must not let an attacker cancel a login in flight'
        );
    },

    'an unknown id is reported as unknown' => static function () use ($build): void {
        [$store] = $build();

        $result = $store->consume(str_repeat('a', 22) . '.' . str_repeat('b', 43));

        Assert::false($result->valid);
        Assert::same(StateValidation::UNKNOWN, $result->reasonCode);
    },

    'malformed tokens never reach storage' => static function () use ($build): void {
        [$store] = $build();

        foreach ([
            '',
            'nodot',
            'a.b',
            'aaaaaaaaaaaaaaaaaaaaaa',
            'aaaaaaaaaaaaaaaaaaaaaa.bbb.ccc',
            'aaaaaaaaaaaaaaaaaaaaaa.',
            '.bbbbbbbbbbbbbbbbbbbbbb',
            'aaaaaaaaaaaaaaaaaaaa$$.bbbbbbbbbbbbbbbbbbbbbb',
            'aaaaaaaaaaaaaaaaaaaaaa.' . str_repeat('b', 500),
        ] as $token) {
            $result = $store->consume($token);
            Assert::false($result->valid, $token);
            Assert::same(StateValidation::MALFORMED, $result->reasonCode, $token);
        }
    },

    'the secret is never stored in clear' => static function () use ($build): void {
        [$store, $storage] = $build();

        $token = $store->issue('/admin');
        [$id, $secret] = explode('.', $token->value);
        $record = $storage->find($id);

        Assert::notNull($record);
        Assert::same(hash('sha256', $secret), $record->secretHash);
        Assert::notSame($secret, $record->secretHash);
        Assert::notContains($secret, json_encode([
            'id' => $record->id,
            'hash' => $record->secretHash,
            'url' => $record->returnUrl,
            'ctx' => $record->context(),
        ]) ?: '');
    },

    'two tokens issued in a row are different' => static function () use ($build): void {
        [$store] = $build();

        $a = $store->issue('/admin');
        $b = $store->issue('/admin');

        Assert::notSame($a->id, $b->id);
        Assert::notSame($a->value, $b->value);
        Assert::true(strlen($a->value) > 50);
    },

    'an off-site return URL is dropped at issue time' => static function () use ($build): void {
        [$store] = $build(300, [], '/admin');

        $token = $store->issue('https://evil.com/phish');

        Assert::same('/admin', $token->returnUrl);
        Assert::same('/admin', $store->consume($token->value)->returnUrl);
    },

    'a poisoned stored return URL is dropped at consume time' => static function () use ($build): void {
        [$store, $storage, $clock] = $build(300, [], '/admin');

        $secret = str_repeat('z', 43);
        $storage->save(new StateRecord(
            str_repeat('q', 22),
            hash('sha256', $secret),
            'https://evil.com/phish',
            $clock->now(),
            $clock->now() + 300
        ));

        $result = $store->consume(str_repeat('q', 22) . '.' . $secret);

        Assert::true($result->valid);
        Assert::same('/admin', $result->returnUrl, 'defence in depth against an older writer');
    },

    'an absolute return URL survives when its origin is allowed' => static function () use ($build): void {
        [$store] = $build(300, ['https://intranet.example.com'], '/admin');

        $token = $store->issue('https://intranet.example.com/admin/entries');

        Assert::same('https://intranet.example.com/admin/entries', $token->returnUrl);
    },

    'TTL bounds are enforced' => static function (): void {
        $make = static fn (int $ttl): StateStore => new StateStore(
            new InMemoryStateStorage(),
            new FixedClock(),
            new SequenceRandomSource(),
            new RedirectGuard(),
            $ttl
        );

        Assert::throws(InvalidArgumentException::class, static fn () => $make(29));
        Assert::throws(InvalidArgumentException::class, static fn () => $make(3601));
        Assert::doesNotThrow(static fn () => $make(30));
        Assert::doesNotThrow(static fn () => $make(3600));
        Assert::same(300, StateStore::DEFAULT_TTL);
    },

    'expired records are purged' => static function () use ($build): void {
        [$store, $storage, $clock] = $build(60);

        $store->issue('/admin');
        $store->issue('/admin');
        Assert::same(2, $storage->count());

        $clock->advance(59);
        $store->purgeExpired();
        Assert::same(2, $storage->count());

        $clock->advance(1);
        $store->purgeExpired();
        Assert::same(0, $storage->count());
    },

    'context values are trimmed and capped' => static function () use ($build): void {
        [$store, $storage] = $build();

        $token = $store->issue('/admin', [
            ' connection ' => 'okta',
            '' => 'dropped',
            'long' => str_repeat('x', 400),
        ]);
        $record = $storage->find($token->id);

        Assert::notNull($record);
        Assert::sameList(['connection', 'long'], array_keys($record->context()));
        Assert::same(255, strlen($record->context()['long']));
    },

    'a consumed record reports itself as consumed' => static function () use ($build): void {
        [$store, $storage, $clock] = $build();

        $token = $store->issue('/admin');
        $store->consume($token->value);
        $record = $storage->find($token->id);

        Assert::notNull($record);
        Assert::true($record->isConsumed());
        Assert::same($clock->now(), $record->consumedAt);
        Assert::false($storage->markConsumed($token->id, $clock->now()), 'atomic flip happens once');
    },

    'every failure reason has an administrator-facing message' => static function (): void {
        foreach ([
            StateValidation::MALFORMED,
            StateValidation::UNKNOWN,
            StateValidation::EXPIRED,
            StateValidation::ALREADY_USED,
            StateValidation::SECRET_MISMATCH,
            StateValidation::STORAGE_UNCONFIRMED,
        ] as $reason) {
            $message = StateValidation::fail($reason)->message();
            Assert::true(strlen($message) > 20, $reason);
            Assert::notSame('Login state rejected.', $message, $reason);
        }
    },

    'replay is refused even when the storage fails to enforce single use' => static function (): void {
        $store = new StateStore(
            new PermissiveStateStorage(),
            new FixedClock(1_000_000),
            new SequenceRandomSource(),
            new RedirectGuard(),
            300
        );

        $token = $store->issue('/admin');
        Assert::true($store->consume($token->value)->valid);

        $replay = $store->consume($token->value);
        Assert::false($replay->valid, 'StateStore must not outsource replay protection entirely');
        Assert::same(StateValidation::ALREADY_USED, $replay->reasonCode);
    },

    'a storage that confirms without storing cannot hand out replays' => static function (): void {
        $storage = new AmnesiacStateStorage();
        $store = new StateStore(
            $storage,
            new FixedClock(1_000_000),
            new SequenceRandomSource(),
            new RedirectGuard(),
            300
        );

        $token = $store->issue('/admin');

        // Five attempts, the way the reviewer replayed one token five times. Not one of them
        // may sign anybody in: we could not observe the state being burnt, so we refuse.
        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $result = $store->consume($token->value);

            Assert::false($result->valid, 'attempt ' . $attempt);
            Assert::same(StateValidation::STORAGE_UNCONFIRMED, $result->reasonCode, 'attempt ' . $attempt);
            Assert::null($result->returnUrl, 'attempt ' . $attempt);
        }

        Assert::same(5, $storage->markConsumedCalls(), 'the store did try to burn it every time');
    },

    'the unconfirmed-storage failure explains itself to the administrator' => static function (): void {
        $message = StateValidation::fail(StateValidation::STORAGE_UNCONFIRMED)->message();

        Assert::true(strlen($message) > 20);
        Assert::contains('cache', $message, 'the admin needs to know where to look');
        Assert::notSame('Login state rejected.', $message);
    },

    'a record already marked consumed is refused on arrival' => static function () use ($build): void {
        [$store, $storage, $clock] = $build();

        $secret = str_repeat('m', 43);
        $storage->save(new StateRecord(
            str_repeat('n', 22),
            hash('sha256', $secret),
            '/admin',
            $clock->now(),
            $clock->now() + 300,
            [],
            $clock->now()
        ));

        $result = $store->consume(str_repeat('n', 22) . '.' . $secret);

        Assert::false($result->valid);
        Assert::same(StateValidation::ALREADY_USED, $result->reasonCode);
    },

    // -----------------------------------------------------------------------------------
    // inspect() - reading a state without burning it. See StateInspection for why it exists.
    // -----------------------------------------------------------------------------------

    'inspect reads the context and the return URL without consuming' => static function () use ($build): void {
        [$store, $storage] = $build();

        $token = $store->issue('/admin/entries', ['connection' => 'okta']);
        $first = $store->inspect($token->value);
        $second = $store->inspect($token->value);

        Assert::true($first->valid);
        Assert::same('/admin/entries', $first->returnUrl);
        Assert::same('okta', $first->context()['connection']);
        Assert::same($token->id, $first->id);

        Assert::true($second->valid, 'inspecting twice is allowed; that is the whole point');
        Assert::false($storage->find($token->id)?->isConsumed() ?? true, 'nothing was burnt');
        Assert::true($store->consume($token->value)->valid, 'the one real use is still available');
    },

    // The gate in front of the protocol reader must not accept what the reader would refuse.
    'inspect refuses everything consume refuses, with the same reason' => static function () use ($build): void {
        [$store, $storage, $clock] = $build();

        $cases = [];

        $cases['malformed'] = 'not-a-token';
        $cases['unknown'] = str_repeat('q', 22) . '.' . str_repeat('r', 43);

        $expired = $store->issue('/admin');
        $cases['expired'] = $expired->value;

        $wrongSecret = $store->issue('/admin');
        $cases['secret'] = $wrongSecret->id . '.' . str_repeat('z', 43);

        $burnt = $store->issue('/admin');
        $store->consume($burnt->value);
        $cases['burnt'] = $burnt->value;

        $clock->advance(301);

        foreach ($cases as $label => $token) {
            $inspected = $store->inspect($token);
            $consumed = $store->consume($token);

            Assert::false($inspected->valid, $label . ' is refused by inspect');
            Assert::same($consumed->reasonCode, $inspected->reasonCode, $label . ' agrees with consume');
        }

        Assert::same(3, $storage->count(), 'no state was created or destroyed by inspecting');
    },

    'inspect sanitises the return URL exactly as consume does' => static function () use ($build): void {
        [$store] = $build(300, [], '/admin');

        // RedirectGuard refuses an absolute URL that is not on the allow list, and the fallback
        // must be the same on both paths - an inspection that returned the raw value would put
        // an open redirect one refactor away.
        $token = $store->issue('https://evil.example.com/phish');

        Assert::same('/admin', $store->inspect($token->value)->returnUrl);
        Assert::same('/admin', $store->consume($token->value)->returnUrl);
    },

    'wasConsumed answers for a burnt state and for one that never existed' => static function () use ($build): void {
        [$store] = $build();

        $token = $store->issue('/admin');

        Assert::false($store->wasConsumed($token->id), 'issued is not consumed');
        Assert::true($store->consume($token->value)->valid);
        Assert::true($store->wasConsumed($token->id));
        Assert::false($store->wasConsumed('never-existed-0000'), 'an unknown id is not "consumed"');
    },

    'the inspection carries the same wording as the validation it mirrors' => static function () use ($build): void {
        [$store] = $build();

        $inspected = $store->inspect(str_repeat('q', 22) . '.' . str_repeat('r', 43));

        Assert::same(StateValidation::UNKNOWN, $inspected->reasonCode);
        Assert::same(StateValidation::fail(StateValidation::UNKNOWN)->message(), $inspected->message());
    },
];
