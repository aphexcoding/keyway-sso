<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\State;

use InvalidArgumentException;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\RandomSourceInterface;
use Keyway\Sso\Core\Port\StateStorageInterface;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Issues and verifies one-shot login state (SAML RelayState, OIDC `state`).
 *
 * Three properties this class exists to guarantee:
 *  - unguessable: 32 random bytes, hashed at rest, compared with hash_equals();
 *  - single use: a replayed response is rejected even if it is otherwise perfectly valid;
 *  - bounded: a state that is not used within the TTL is worthless.
 *
 * The return URL rides along server-side rather than inside the token, and is validated both
 * when issued and when consumed. Validating twice is not redundancy theatre: the storage layer
 * is a shared cache, and an entry that was written by an older, looser build of the plugin must
 * not be trusted at redirect time.
 *
 * How far the single-use guarantee really goes - stated precisely, because the earlier version
 * of this docblock promised more than the class delivered:
 *
 *  - a storage that forgets to flip the flag but keeps the record (a naive adapter that returns
 *    true from markConsumed() and stores the result) is caught by the consumed check on the way
 *    in, so the replay is refused;
 *  - a storage that reports success and persists NOTHING is caught by the read-back after
 *    markConsumed(): the login is refused with STORAGE_UNCONFIRMED rather than accepted. It is
 *    a broken installation either way, but it is a broken installation that cannot be replayed;
 *  - what this class still cannot do is make a non-atomic storage atomic. Two requests racing
 *    against a read-modify-write adapter can both observe an unconsumed record; only the
 *    adapter can close that window, which is why StateStorageInterface demands atomicity.
 */
final class StateStore
{
    public const DEFAULT_TTL = 300;
    private const MIN_TTL = 30;
    private const MAX_TTL = 3600;

    private const ID_BYTES = 16;
    private const SECRET_BYTES = 32;

    private StateStorageInterface $storage;
    private ClockInterface $clock;
    private RandomSourceInterface $random;
    private RedirectGuard $redirectGuard;
    private int $ttl;

    public function __construct(
        StateStorageInterface $storage,
        ClockInterface $clock,
        RandomSourceInterface $random,
        RedirectGuard $redirectGuard,
        int $ttl = self::DEFAULT_TTL
    ) {
        if ($ttl < self::MIN_TTL || $ttl > self::MAX_TTL) {
            throw new InvalidArgumentException(sprintf(
                'Login state TTL must be between %d and %d seconds.',
                self::MIN_TTL,
                self::MAX_TTL
            ));
        }

        $this->storage = $storage;
        $this->clock = $clock;
        $this->random = $random;
        $this->redirectGuard = $redirectGuard;
        $this->ttl = $ttl;
    }

    public function ttl(): int
    {
        return $this->ttl;
    }

    /**
     * @param array<string, string> $context
     */
    public function issue(?string $returnUrl = null, array $context = []): StateToken
    {
        $now = $this->clock->now();
        $id = self::encode($this->random->bytes(self::ID_BYTES));
        $secret = self::encode($this->random->bytes(self::SECRET_BYTES));
        $safeReturnUrl = $this->redirectGuard->sanitize($returnUrl);

        $record = new StateRecord(
            $id,
            hash('sha256', $secret),
            $safeReturnUrl,
            $now,
            $now + $this->ttl,
            self::normaliseContext($context)
        );

        $this->storage->save($record);

        return new StateToken($id, $id . '.' . $secret, $safeReturnUrl, $record->expiresAt);
    }

    /**
     * Reads a state without burning it: same checks as consume(), no write, no single-use claim.
     *
     * NOT AN AUTHORISATION. See StateInspection - the whole contract, including why this method
     * has to exist and what stops it becoming a replay hole, is written down there.
     */
    public function inspect(string $token): StateInspection
    {
        $found = $this->verify($token);

        if (is_string($found)) {
            return StateInspection::fail($found, self::idOf($token));
        }

        return StateInspection::ok(
            $found->id,
            $this->redirectGuard->sanitize($found->returnUrl),
            $found->context()
        );
    }

    /**
     * True when the state with this id exists and has already been burnt.
     *
     * The check LoginFlow runs after a protocol reader returns, so that "the reader forgot to
     * consume the state" cannot become "a login that can be replayed". It takes an id, not a
     * token: by then the secret has been verified and the id is what the caller has left.
     */
    public function wasConsumed(string $id): bool
    {
        $record = $this->storage->find($id);

        return $record !== null && $record->isConsumed();
    }

    /**
     * Verifies the token and burns it. Every failure path leaves the state unusable or untouched;
     * none of them signs anybody in.
     */
    public function consume(string $token): StateValidation
    {
        $found = $this->verify($token);

        if (is_string($found)) {
            return StateValidation::fail($found, self::idOf($token));
        }

        $record = $found;
        $now = $this->clock->now();

        // Authoritative single-use check; the storage implementation makes it atomic, so two
        // concurrent replays cannot both win.
        if (!$this->storage->markConsumed($record->id, $now)) {
            return StateValidation::fail(StateValidation::ALREADY_USED, $record->id);
        }

        // Read back before trusting the "true" above. A storage that reports success without
        // persisting anything - a failed cache write, a read replica, a TTL-only adapter -
        // would otherwise hand out unlimited replays of one token, and the caller would never
        // learn about it. We cannot accept a login whose single-use guarantee we could not
        // observe, so this is fail-closed by design: the burnt-state check happens here, not
        // in the adapter's return value.
        $burnt = $this->storage->find($record->id);
        if ($burnt === null || !$burnt->isConsumed()) {
            return StateValidation::fail(StateValidation::STORAGE_UNCONFIRMED, $record->id);
        }

        return StateValidation::ok(
            $record->id,
            $this->redirectGuard->sanitize($record->returnUrl),
            $record->context()
        );
    }

    /**
     * Everything both readers of a state have to agree on, in one place.
     *
     * Returns the record when the token checks out, or the reason code that refused it. Shared
     * so that inspect() cannot drift into being more permissive than consume(): a gate that runs
     * before the protocol reader and accepts tokens the reader would have rejected is a gate
     * that widens the flow instead of narrowing it.
     *
     * @return StateRecord|string The record, or a StateValidation reason code.
     */
    private function verify(string $token): StateRecord|string
    {
        $parts = explode('.', Ascii::trim($token));

        if (count($parts) !== 2) {
            return StateValidation::MALFORMED;
        }

        [$id, $secret] = $parts;

        if (!self::isHandle($id) || !self::isHandle($secret)) {
            return StateValidation::MALFORMED;
        }

        $record = $this->storage->find($id);
        if ($record === null) {
            return StateValidation::UNKNOWN;
        }

        if ($record->isExpired($this->clock->now())) {
            return StateValidation::EXPIRED;
        }

        // Secret first, replay second: without this order, knowing only the (shorter, more
        // exposed) id would be enough to burn someone else's in-flight login.
        if (!hash_equals($record->secretHash, hash('sha256', $secret))) {
            return StateValidation::SECRET_MISMATCH;
        }

        if ($record->isConsumed()) {
            return StateValidation::ALREADY_USED;
        }

        return $record;
    }

    /**
     * The id half of a token, for failure reporting only.
     *
     * Reported even when the token was refused, because the diagnostics panel needs something to
     * correlate a failed callback with the login that started it. Null for anything that is not
     * shaped like one of our tokens, so a malformed value cannot put arbitrary text in a log.
     */
    private static function idOf(string $token): ?string
    {
        $parts = explode('.', Ascii::trim($token));

        if (count($parts) !== 2 || !self::isHandle($parts[0])) {
            return null;
        }

        return $parts[0];
    }

    public function purgeExpired(): void
    {
        $this->storage->purgeExpired($this->clock->now());
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function isHandle(string $value): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{16,128}$/', $value) === 1;
    }

    /**
     * @param array<string, string> $context
     * @return array<string, string>
     */
    private static function normaliseContext(array $context): array
    {
        $out = [];

        foreach ($context as $key => $value) {
            $key = Ascii::trim((string)$key);
            if ($key === '' || !is_scalar($value)) {
                continue;
            }

            $out[$key] = Ascii::truncateBytes((string)$value, 255);
        }

        return $out;
    }
}
