<?php

declare(strict_types=1);

use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\InMemoryReplayGuard;
use Keyway\Sso\Test\Support\OidcFixtures;
use Keyway\Sso\Test\Support\SamlFixtures;
use Keyway\Sso\Test\Support\SamlLogoutFixtures;

/**
 * The suite's own determinism, asserted rather than hoped for.
 *
 * This file exists because of a red that appeared once in roughly seventeen runs and then
 * refused to come back. Two separate defects were in play and only one of them was ever the
 * one written down:
 *
 *  1. THE REAL CAUSE - OidcFixtures built the P-256 JWK straight out of openssl_pkey_get_details()
 *     without left-padding the coordinates to 32 octets (RFC 7518 section 6.2.1.2). OpenSSL drops
 *     leading zero bytes, so about one generated key in a hundred produced a JWK that could not
 *     verify its own token, and the failure read exactly like a signature bug in the reader.
 *     Fixed separately; pinned here, because a guard that only fires when the coordinate happens
 *     to be short is the same lottery with extra steps.
 *  2. THE STANDING HAZARD - fixtures that reach for time() on their own while every reader under
 *     test runs on a FixedClock. Measured: this one could NOT have produced the observed red
 *     (offsetting the fixture clock by +/- 10^6 s leaves the suite green, because the single
 *     call site that relied on the default fed a token into an HTTP 400 body that is rejected
 *     on status before anything parses it). It is still a second, unsynchronised clock in the
 *     suite, and it is removed rather than narrowed.
 *
 * The cases below assert the invariants that keep both shut: no fixture invents a timestamp, no
 * test helper reads the wall clock, and a curve coordinate is always the full width.
 */

/**
 * Every helper source under test/Support, subdirectories included.
 *
 * Deliberately recursive: `Support/` is flat today, but a glob that stops at the top level would
 * skip the first subdirectory anyone adds WITHOUT failing, and a guard that silently covers less
 * than it claims is worse than no guard at all.
 *
 * @return list<string>
 */
$supportSources = static function (): array {
    $root = __DIR__ . '/Support';
    if (!is_dir($root)) {
        return [];
    }

    $found = [];
    $walk = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($walk as $entry) {
        if ($entry instanceof SplFileInfo
            && $entry->isFile()
            && strtolower($entry->getExtension()) === 'php'
        ) {
            $found[] = $entry->getPathname();
        }
    }

    sort($found); // stable order, so a failure names the same file on every machine

    return $found;
};

/** Token classes that carry no meaning for the walk below. */
$ignorable = [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT];

/**
 * Index of the nearest meaningful token before $index, or null at the start of the stream.
 *
 * @param list<array{0:int,1:string,2:int}|string> $tokens
 */
$previousSignificantIndex = static function (array $tokens, int $index) use ($ignorable): ?int {
    for ($back = $index - 1; $back >= 0; $back--) {
        $candidate = $tokens[$back];
        if (is_array($candidate) && in_array($candidate[0], $ignorable, true)) {
            continue;
        }

        return $back;
    }

    return null;
};

/**
 * How many arguments the name at $index is being called with, or null when it is not a call.
 *
 * Counts top-level commas only, so a nested call, an array literal or an interpolated string
 * cannot inflate the total, and a trailing comma cannot either. The distinction matters because
 * `gmdate($fmt, $ts)` is a pure function of its arguments while `gmdate($fmt)` is a clock read.
 *
 * @param list<array{0:int,1:string,2:int}|string> $tokens
 */
$callArgumentCount = static function (array $tokens, int $index) use ($ignorable): ?int {
    $total = count($tokens);

    $cursor = $index + 1;
    while ($cursor < $total
        && is_array($tokens[$cursor])
        && in_array($tokens[$cursor][0], $ignorable, true)
    ) {
        $cursor++;
    }

    if ($cursor >= $total || $tokens[$cursor] !== '(') {
        return null; // a mention (string key, named argument, `use function`), not a call
    }

    $depth = 0;
    $arguments = 0;
    $sawArgument = false;

    for (; $cursor < $total; $cursor++) {
        $token = $tokens[$cursor];

        if (is_array($token)) {
            // `{$x}` / `${x}` inside a string and `#[...]` all open a bracket that closes as a
            // plain `}` or `]`, so they have to be counted in or the depth drifts negative.
            if (in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES, T_ATTRIBUTE], true)) {
                $depth++;
            } elseif ($depth === 1 && !in_array($token[0], $ignorable, true)) {
                $sawArgument = true;
            }

            continue;
        }

        if ($token === '(' || $token === '[' || $token === '{') {
            $depth++;
            if ($depth > 1) {
                $sawArgument = true;
            }

            continue;
        }

        if ($token === ')' || $token === ']' || $token === '}') {
            $depth--;
            if ($depth === 0) {
                return $sawArgument ? $arguments + 1 : $arguments;
            }

            continue;
        }

        if ($token === ',' && $depth === 1) {
            $arguments++;
            $sawArgument = false;

            continue;
        }

        if ($depth === 1) {
            $sawArgument = true;
        }
    }

    return null; // unbalanced source would not have parsed in the first place
};

return [
    // ------------------------------------------------------- no fixture invents a timestamp

    'the OIDC claim fixture refuses to invent a timestamp' =>
        static function (): void {
            $error = Assert::throws(
                RuntimeException::class,
                static fn (): array => OidcFixtures::claims(['nonce' => 'n'])
            );
            Assert::contains('__now', $error->getMessage(), 'the message names the missing input');

            // idToken() funnels through claims(), so the same guard has to hold one level up -
            // that is the level nearly every case actually calls.
            Assert::throws(
                RuntimeException::class,
                static fn (): string => OidcFixtures::idToken(['nonce' => 'n'])
            );
        },

    'the SAML fixtures refuse to invent a timestamp' =>
        static function (): void {
            Assert::contains(
                'now',
                Assert::throws(
                    RuntimeException::class,
                    static fn (): string => SamlFixtures::response(['nameId' => 'a@b.test'])
                )->getMessage()
            );

            Assert::throws(
                RuntimeException::class,
                static fn (): string => SamlLogoutFixtures::requestQuery(['relayState' => 'x'])
            );

            Assert::throws(
                RuntimeException::class,
                static fn (): string => SamlLogoutFixtures::responseQuery(['relayState' => 'x'])
            );
        },

    'the same timestamp always builds the same claim set' =>
        static function (): void {
            // Determinism stated positively: identical input, byte-identical output, including
            // the derived fields (`exp`, `iat`, `auth_time`, `jti`) that used to follow the wall
            // clock. Two builds a second apart must not differ.
            $first = OidcFixtures::claims(['__now' => 1_700_000_000]);
            $second = OidcFixtures::claims(['__now' => 1_700_000_000]);

            Assert::same(json_encode($first), json_encode($second));
            Assert::same(1_700_000_000, $first['iat']);
            Assert::same(1_700_000_300, $first['exp']);

            // And a different timestamp really is a different claim set, so the assertion above
            // is not satisfied by a fixture that ignores its argument.
            Assert::notSame(
                json_encode($first),
                json_encode(OidcFixtures::claims(['__now' => 1_700_000_001]))
            );
        },

    'no test helper reads the wall clock' =>
        static function () use ($supportSources, $previousSignificantIndex, $callArgumentCount): void {
            // The structural half of the fix: the rule is asserted against the source of every
            // helper, not against the four call sites that happened to break it. A comment
            // mentioning time() is fine; a token that calls it is not, which is why this walks
            // the token stream instead of grepping.
            Assert::notSame([], $supportSources(), 'the support directory was found');

            // Reads the clock however it is called: banned outright.
            $forbidden = ['time', 'microtime', 'hrtime', 'systemclock'];

            // Reads the clock only when the caller leaves the moment out. `gmdate($fmt, $ts)`
            // formats a timestamp it was handed; `gmdate($fmt)` formats the wall clock, and the
            // two are one keystroke apart. The rule used to be a comment saying every call site
            // passes the timestamp - true at the time, enforced nowhere, which is precisely the
            // drift this file exists to catch. The number is the lowest arity at which the call
            // is a pure function of its arguments.
            $needsExplicitMoment = [
                'gmdate' => 2,    // gmdate($format, $timestamp)
                'date' => 2,      // date($format, $timestamp)
                'strtotime' => 2, // strtotime($text, $baseTimestamp)
                'mktime' => 6,    // mktime($h, $m, $s, $month, $day, $year) - any gap is today
                'gmmktime' => 6,
            ];

            foreach ($supportSources() as $path) {
                $tokens = token_get_all((string)file_get_contents($path));
                $where = basename($path);

                foreach ($tokens as $index => $token) {
                    if (!is_array($token)) {
                        continue;
                    }

                    // PHP 8 folds `\time` and `A\B\SystemClock` into one name token, so the
                    // last segment is what has to be compared - a check on T_STRING alone would
                    // walk straight past a fully qualified `\time()`.
                    if (!in_array(
                        $token[0],
                        [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED],
                        true
                    )) {
                        continue;
                    }

                    $segments = explode('\\', $token[1]);
                    $name = strtolower((string)end($segments));
                    $minimumArguments = $needsExplicitMoment[$name] ?? null;

                    if ($minimumArguments === null && !in_array($name, $forbidden, true)) {
                        continue;
                    }

                    $previousIndex = $previousSignificantIndex($tokens, $index);
                    $previous = $previousIndex === null ? null : $tokens[$previousIndex];

                    // `$x->time()` and `private static function time()` are a member access and a
                    // declaration, never a call into the clock.
                    $qualified = is_array($previous) && in_array(
                        $previous[0],
                        [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_FUNCTION],
                        true
                    );

                    // `self::time()` is the fixtures' own XML formatter, which takes the timestamp
                    // as an argument. A bare `T_DOUBLE_COLON` used to wave through ANY `X::time()`,
                    // including a real clock class, so the owner has to be the helper itself.
                    if (!$qualified && is_array($previous) && $previous[0] === T_DOUBLE_COLON) {
                        $ownerIndex = $previousSignificantIndex($tokens, $previousIndex);
                        $owner = $ownerIndex === null ? null : $tokens[$ownerIndex];

                        $qualified = is_array($owner)
                            && ($owner[0] === T_STATIC
                                || ($owner[0] === T_STRING && strtolower($owner[1]) === 'self'));
                    }

                    if ($qualified) {
                        continue;
                    }

                    if ($minimumArguments !== null) {
                        $arguments = $callArgumentCount($tokens, $index);
                        if ($arguments === null || $arguments >= $minimumArguments) {
                            continue;
                        }

                        Assert::true(
                            false,
                            $where . ':' . $token[2] . ' calls ' . $token[1] . '() with '
                            . $arguments . ' argument(s), so it formats the wall clock instead of '
                            . 'a timestamp it was given (needs ' . $minimumArguments . ')'
                        );

                        continue;
                    }

                    Assert::true(
                        false,
                        $where . ':' . $token[2] . ' reaches for the wall clock (' . $token[1] . ')'
                    );
                }
            }

            Assert::true(true, 'every helper takes its time from the caller');
        },

    'the replay guard cannot be built without a clock' =>
        static function (): void {
            // It used to default to SystemClock, which swept the registry against a different
            // clock than the one that set the retention horizon. Green only by a 360 s margin
            // (`exp` + skew) - measured: red from +360 s of drift. The margin is now gone
            // because the argument is required.
            $constructor = (new ReflectionClass(InMemoryReplayGuard::class))->getConstructor();

            Assert::notNull($constructor);
            Assert::same(1, $constructor?->getNumberOfRequiredParameters());

            $clock = new FixedClock(1_700_000_000);
            $guard = new InMemoryReplayGuard($clock);

            Assert::true($guard->remember('jti-1', 1_700_000_300), 'first use is accepted');
            Assert::false($guard->remember('jti-1', 1_700_000_300), 'and never again');

            // The entry is swept on the injected clock, not on the wall clock.
            $clock->advance(300);
            Assert::true(
                $guard->remember('jti-1', 1_700_000_600),
                'expired, so the id is free again'
            );
        },

    // -------------------------------------------- the defect that actually produced the red

    'a P-256 coordinate is always the full curve width' =>
        static function (): void {
            // Fed a short coordinate directly, which is the point: OpenSSL only hands one back
            // about 1% of the time, so the live key below cannot be the guard on its own.
            $short = OidcFixtures::ecCoordinate(str_repeat("\x7f", 31));
            $decoded = (string)base64_decode(strtr($short, '-_', '+/'), true);

            Assert::same(
                32,
                strlen($decoded),
                'a 31-byte coordinate is padded, not published short'
            );
            Assert::same("\x00", $decoded[0], 'and padded on the LEFT, big-endian');

            $full = str_repeat("\x7f", 32);
            Assert::same(
                $full,
                (string)base64_decode(strtr(OidcFixtures::ecCoordinate($full), '-_', '+/'), true),
                'a full-width coordinate passes through untouched'
            );

            Assert::same(
                43,
                strlen(OidcFixtures::ecCoordinate(str_repeat("\x01", 30))),
                'every coordinate encodes to the same length, whatever OpenSSL trimmed'
            );
        },
];
