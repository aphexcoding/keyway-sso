<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Support;

/**
 * Byte-level string helpers.
 *
 * Deliberately ASCII-only: the plugin must run on hosts without ext-mbstring, so there is no
 * `mb_*` call anywhere in the core. Every helper below is byte-wise and leaves multi-byte
 * UTF-8 sequences untouched (their bytes all have the high bit set and never collide with the
 * ASCII ranges we translate).
 *
 * Consequence to keep in mind: `lower()` does NOT case-fold non-ASCII letters. For identifiers
 * that matters only in theory - IdP-issued usernames, e-mail domains and group names that
 * differ solely by the case of a non-ASCII letter are treated as distinct values. Folding them
 * would require ext-mbstring/ext-intl and would let two different directory entries collapse
 * into one account, which is the worse failure mode for an authentication plugin.
 */
final class Ascii
{
    private const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWER = 'abcdefghijklmnopqrstuvwxyz';

    private function __construct()
    {
    }

    public static function lower(string $value): string
    {
        return strtr($value, self::UPPER, self::LOWER);
    }

    public static function upper(string $value): string
    {
        return strtr($value, self::LOWER, self::UPPER);
    }

    /**
     * Case-insensitive comparison over ASCII letters only.
     */
    public static function equalsIgnoreCase(string $a, string $b): bool
    {
        return self::lower($a) === self::lower($b);
    }

    /**
     * Trims ASCII whitespace and control characters from both ends.
     */
    public static function trim(string $value): string
    {
        return trim($value, " \t\n\r\0\x0B");
    }

    /**
     * Truncates to at most $maxBytes, never cutting a UTF-8 sequence in half.
     *
     * Keeping the result valid UTF-8 matters: diagnostics rows are json_encode()d, and
     * json_encode() fails on malformed UTF-8 - a half-cut character would silently drop the
     * whole diagnostic entry.
     */
    public static function truncateBytes(string $value, int $maxBytes): string
    {
        if ($maxBytes <= 0) {
            return '';
        }

        if (strlen($value) <= $maxBytes) {
            return $value;
        }

        $cut = substr($value, 0, $maxBytes);
        $length = strlen($cut);

        // Walk back over continuation bytes (10xxxxxx) to the lead byte of the last sequence.
        $index = $length - 1;
        $steps = 0;
        while ($index >= 0 && (ord($cut[$index]) & 0xC0) === 0x80 && $steps < 3) {
            $index--;
            $steps++;
        }

        if ($index < 0) {
            return '';
        }

        $lead = ord($cut[$index]);

        if ($lead < 0x80) {
            return $cut;
        }

        if (($lead & 0xE0) === 0xC0) {
            $expected = 2;
        } elseif (($lead & 0xF0) === 0xE0) {
            $expected = 3;
        } elseif (($lead & 0xF8) === 0xF0) {
            $expected = 4;
        } else {
            return substr($cut, 0, $index);
        }

        return $index + $expected <= $length ? $cut : substr($cut, 0, $index);
    }

    /**
     * Splits a UTF-8 string into characters, without ext-mbstring.
     *
     * Needed because masking cuts values down to "first n / last n characters"; doing that with
     * substr() would slice a multi-byte character in half and make the whole diagnostics row
     * fail json_encode().
     *
     * @return list<string>
     */
    public static function characters(string $value): array
    {
        $characters = [];
        $length = strlen($value);
        $index = 0;

        while ($index < $length) {
            $lead = ord($value[$index]);

            if ($lead < 0x80) {
                $size = 1;
            } elseif (($lead & 0xE0) === 0xC0) {
                $size = 2;
            } elseif (($lead & 0xF0) === 0xE0) {
                $size = 3;
            } elseif (($lead & 0xF8) === 0xF0) {
                $size = 4;
            } else {
                $size = 1;
            }

            $characters[] = substr($value, $index, $size);
            $index += $size;
        }

        return $characters;
    }

    public static function characterCount(string $value): int
    {
        return count(self::characters($value));
    }

    public static function firstCharacters(string $value, int $count): string
    {
        if ($count <= 0) {
            return '';
        }

        return implode('', array_slice(self::characters($value), 0, $count));
    }

    public static function lastCharacters(string $value, int $count): string
    {
        if ($count <= 0) {
            return '';
        }

        return implode('', array_slice(self::characters($value), -$count));
    }

    /**
     * Reduces somebody else's text to printable ASCII, at most $maxBytes long.
     *
     * For text that is quoted into a diagnostics message and a log line but was written by an
     * identity provider or by whoever reached the login endpoint. Every byte outside 0x20-0x7E
     * becomes "?": that removes line breaks (a forged second log line), terminal escapes, and
     * malformed UTF-8 - which json_encode() refuses, so one bad byte would otherwise drop the
     * whole diagnostic entry. It does NOT make the text HTML; the template's autoescaping does.
     */
    public static function printable(string $value, int $maxBytes): string
    {
        if ($maxBytes <= 0) {
            return '';
        }

        $clean = preg_replace('/[^\x20-\x7E]/', '?', $value);

        return substr(is_string($clean) ? $clean : '', 0, $maxBytes);
    }

    /**
     * True when the string contains no C0/C1 control characters (including CR, LF, NUL).
     */
    public static function hasControlCharacters(string $value): bool
    {
        return preg_match('/[\x00-\x1F\x7F]/', $value) === 1;
    }
}
