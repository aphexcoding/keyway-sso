<?php

declare(strict_types=1);

use Keyway\Sso\Core\Support\Ascii;
use Keyway\Sso\Test\Support\Assert;

return [
    'lower folds ASCII only and leaves UTF-8 bytes intact' => static function (): void {
        Assert::same('abc', Ascii::lower('ABC'));
        Assert::same('ąb', Ascii::lower('ąB'));
        Assert::same('ĄB', Ascii::upper('Ąb'));
    },

    'trim removes control characters at both ends' => static function (): void {
        Assert::same('value', Ascii::trim("  value\t\n"));
        Assert::same('value', Ascii::trim("\0value\r"));
        Assert::same('', Ascii::trim("   "));
    },

    'equalsIgnoreCase compares ASCII case-insensitively' => static function (): void {
        Assert::true(Ascii::equalsIgnoreCase('Editors', 'editors'));
        Assert::false(Ascii::equalsIgnoreCase('Editors', 'editor'));
    },

    'truncateBytes never cuts a UTF-8 sequence in half' => static function (): void {
        Assert::same('ą', Ascii::truncateBytes('ąb', 2));
        Assert::same('', Ascii::truncateBytes('ąb', 1));
        Assert::same('a', Ascii::truncateBytes('aąc', 2));
        Assert::same('abc', Ascii::truncateBytes('abc', 10));
        Assert::same('', Ascii::truncateBytes('abc', 0));
    },

    'truncateBytes output stays json-encodable' => static function (): void {
        $value = str_repeat('ż', 40);
        for ($limit = 1; $limit <= 80; $limit++) {
            $cut = Ascii::truncateBytes($value, $limit);
            Assert::notSame(false, json_encode($cut), 'limit ' . $limit);
        }
    },

    'hasControlCharacters detects CR, LF, TAB and NUL' => static function (): void {
        Assert::true(Ascii::hasControlCharacters("a\r\nb"));
        Assert::true(Ascii::hasControlCharacters("a\tb"));
        Assert::true(Ascii::hasControlCharacters("a\0b"));
        Assert::false(Ascii::hasControlCharacters('/admin/entries?x=1'));
        Assert::false(Ascii::hasControlCharacters('zażółć'));
    },

    'printable reduces foreign text to bounded, printable ASCII' => static function (): void {
        Assert::same('HTTP 401: invalid_client.', Ascii::printable('HTTP 401: invalid_client.', 400));
        Assert::same('a??b?c', Ascii::printable("a\r\nb\tc", 400), 'no line break survives');
        Assert::same('a?b', Ascii::printable("a\0b", 400));
        Assert::same('a?[31mb', Ascii::printable("a\x1b[31mb", 400), 'no terminal escape survives');
        Assert::same('za????', Ascii::printable('zażó', 400), 'one "?" per byte, never half a sequence');
        Assert::same('?(', Ascii::printable("\xC3\x28", 400), 'malformed UTF-8 is neutralised');
        Assert::notSame(false, json_encode(Ascii::printable("\xC3\x28\xFF", 400)), 'and what is left encodes');
        Assert::same('abc', Ascii::printable('abcdef', 3));
        Assert::same('', Ascii::printable('abc', 0));
        Assert::same('', Ascii::printable('', 10));
    },

    'characters splits UTF-8 without ext-mbstring' => static function (): void {
        Assert::sameList(['a', 'ż', 'ó', 'b'], Ascii::characters('ażób'));
        Assert::same(4, Ascii::characterCount('ażób'));
        Assert::same(0, Ascii::characterCount(''));
        Assert::same(1, Ascii::characterCount('€'));
        Assert::same(1, Ascii::characterCount("\xF0\x9F\x94\x91"));
    },

    'first/last characters never split a sequence' => static function (): void {
        Assert::same('aż', Ascii::firstCharacters('ażób', 2));
        Assert::same('ób', Ascii::lastCharacters('ażób', 2));
        Assert::same('ażób', Ascii::firstCharacters('ażób', 99));
        Assert::same('', Ascii::firstCharacters('ażób', 0));
        Assert::same('', Ascii::lastCharacters('ażób', -1));
        Assert::notSame(false, json_encode(Ascii::firstCharacters('żółw', 1)));
        Assert::same('ż', Ascii::firstCharacters('żółw', 1));
        Assert::same('w', Ascii::lastCharacters('żółw', 1));
    },
];
