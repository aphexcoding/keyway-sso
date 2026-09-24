<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Throwable;

/**
 * Assertions for the built-in runner.
 *
 * Exceptions rather than assert(): this host runs with zend.assertions=-1, so assert() is
 * compiled out entirely and a suite built on it would report green no matter what.
 */
final class Assert
{
    private static int $count = 0;

    private function __construct()
    {
    }

    public static function count(): int
    {
        return self::$count;
    }

    public static function resetCount(): void
    {
        self::$count = 0;
    }

    public static function same(mixed $expected, mixed $actual, string $message = ''): void
    {
        self::$count++;
        if ($expected !== $actual) {
            throw new AssertionFailed(sprintf(
                '%sexpected %s, got %s',
                $message === '' ? '' : $message . ': ',
                self::describe($expected),
                self::describe($actual)
            ));
        }
    }

    public static function notSame(mixed $unexpected, mixed $actual, string $message = ''): void
    {
        self::$count++;
        if ($unexpected === $actual) {
            throw new AssertionFailed(sprintf(
                '%sexpected a value other than %s',
                $message === '' ? '' : $message . ': ',
                self::describe($unexpected)
            ));
        }
    }

    public static function true(bool $actual, string $message = ''): void
    {
        self::same(true, $actual, $message);
    }

    public static function false(bool $actual, string $message = ''): void
    {
        self::same(false, $actual, $message);
    }

    public static function null(mixed $actual, string $message = ''): void
    {
        self::same(null, $actual, $message);
    }

    public static function notNull(mixed $actual, string $message = ''): void
    {
        self::notSame(null, $actual, $message);
    }

    /**
     * @param array<mixed> $expected
     * @param array<mixed> $actual
     */
    public static function sameList(array $expected, array $actual, string $message = ''): void
    {
        self::same(array_values($expected), array_values($actual), $message);
    }

    public static function contains(string $needle, string $haystack, string $message = ''): void
    {
        self::$count++;
        if (!str_contains($haystack, $needle)) {
            throw new AssertionFailed(sprintf(
                '%sexpected to find %s in %s',
                $message === '' ? '' : $message . ': ',
                self::describe($needle),
                self::describe($haystack)
            ));
        }
    }

    public static function notContains(string $needle, string $haystack, string $message = ''): void
    {
        self::$count++;
        if (str_contains($haystack, $needle)) {
            throw new AssertionFailed(sprintf(
                '%sdid not expect to find %s in %s',
                $message === '' ? '' : $message . ': ',
                self::describe($needle),
                self::describe($haystack)
            ));
        }
    }

    /**
     * @param class-string<Throwable> $expectedClass
     * @return Throwable The caught exception, for further assertions.
     */
    public static function throws(
        string $expectedClass,
        callable $callback,
        string $message = ''
    ): Throwable {
        self::$count++;

        try {
            $callback();
        } catch (Throwable $caught) {
            if ($caught instanceof $expectedClass) {
                return $caught;
            }

            throw new AssertionFailed(sprintf(
                '%sexpected %s, got %s (%s)',
                $message === '' ? '' : $message . ': ',
                $expectedClass,
                $caught::class,
                $caught->getMessage()
            ));
        }

        throw new AssertionFailed(sprintf(
            '%sexpected %s, nothing was thrown',
            $message === '' ? '' : $message . ': ',
            $expectedClass
        ));
    }

    public static function doesNotThrow(callable $callback, string $message = ''): void
    {
        self::$count++;

        try {
            $callback();
        } catch (Throwable $caught) {
            throw new AssertionFailed(sprintf(
                '%sunexpected %s: %s',
                $message === '' ? '' : $message . ': ',
                $caught::class,
                $caught->getMessage()
            ));
        }
    }

    private static function describe(mixed $value): string
    {
        if (is_string($value)) {
            return '"' . (strlen($value) > 200 ? substr($value, 0, 200) . '...' : $value) . '"';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if ($value === null) {
            return 'null';
        }

        if (is_array($value)) {
            $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            return $encoded === false ? 'array(unencodable)' : $encoded;
        }

        if (is_object($value)) {
            return $value::class;
        }

        return (string)$value;
    }
}
