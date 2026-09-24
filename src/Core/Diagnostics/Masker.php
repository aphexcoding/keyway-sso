<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

use Keyway\Sso\Core\Support\Ascii;

/**
 * Makes diagnostics readable without making them dangerous.
 *
 * The diagnostics panel is the support mechanism of this plugin, which means agency staff and,
 * during a support ticket, we ourselves will look at these rows. So the rule is: enough to
 * recognise a value, never enough to reuse it. Names of claims are shown in full
 * (that is what the administrator is debugging); values are masked; anything whose name smells
 * of a credential is dropped entirely rather than partially revealed.
 */
final class Masker
{
    public const REDACTED = '[redacted]';
    public const TRUNCATED = '[truncated]';

    private const MAX_VALUE_BYTES = 96;

    /**
     * Substring match, lower-cased. Over-masking is the intended bias: a postal code shown as
     * [redacted] costs one support question, a leaked bearer token costs a CVE.
     *
     * @var list<string>
     */
    private const SENSITIVE_NAME_PARTS = [
        'password',
        'passwd',
        'secret',
        'token',
        'assertion',
        'samlresponse',
        'saml_response',
        'authnrequest',
        'signature',
        'certificate',
        'credential',
        'privatekey',
        'private_key',
        'authorization',
        'cookie',
        'code',
        'otp',
        'pin',
        'apikey',
        'api_key',
    ];

    private function __construct()
    {
    }

    public static function isSensitiveName(string $name): bool
    {
        $name = Ascii::lower($name);

        foreach (self::SENSITIVE_NAME_PARTS as $part) {
            if (str_contains($name, $part)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Partial mask: enough to tell two values apart, not enough to replay one.
     */
    public static function maskValue(string $value): string
    {
        $value = Ascii::trim($value);

        if ($value === '') {
            return '';
        }

        if (str_contains($value, '@')) {
            return self::maskEmail($value);
        }

        $value = Ascii::truncateBytes($value, self::MAX_VALUE_BYTES);

        if (Ascii::characterCount($value) <= 4) {
            return '***';
        }

        return Ascii::firstCharacters($value, 2) . '***' . Ascii::lastCharacters($value, 2);
    }

    /**
     * Keeps the domain - it is not a secret and it is the first thing an administrator checks
     * when a login lands on the wrong tenant.
     */
    public static function maskEmail(string $email): string
    {
        $at = strrpos($email, '@');
        if ($at === false || $at === 0) {
            return '***';
        }

        $local = substr($email, 0, $at);
        $domain = substr($email, $at + 1);

        $maskedLocal = Ascii::characterCount($local) <= 2
            ? '***'
            : Ascii::firstCharacters($local, 1) . '***' . Ascii::lastCharacters($local, 1);

        return $maskedLocal . '@' . Ascii::truncateBytes($domain, 64);
    }

    /**
     * @param array<string, list<string>> $attributes
     * @return array<string, list<string>>
     */
    public static function maskAttributes(
        array $attributes,
        int $maxAttributes = 30,
        int $maxValues = 5
    ): array {
        $out = [];
        $count = 0;

        foreach ($attributes as $name => $values) {
            if ($count >= $maxAttributes) {
                $out[self::TRUNCATED] = [sprintf('%d more attribute(s)', count($attributes) - $count)];
                break;
            }

            $count++;
            $name = Ascii::truncateBytes((string)$name, 128);

            if (self::isSensitiveName($name)) {
                $out[$name] = [self::REDACTED];
                continue;
            }

            $masked = [];
            $index = 0;
            foreach ((array)$values as $value) {
                if ($index >= $maxValues) {
                    $masked[] = sprintf('[+%d more]', count((array)$values) - $index);
                    break;
                }
                $index++;
                $masked[] = self::maskValue((string)$value);
            }

            $out[$name] = $masked;
        }

        return $out;
    }

    /**
     * Last-resort scrub for the free-form structures an event carries (mapping, decision).
     *
     * The recorder already masks what it puts there; this exists because DiagnosticEvent is a
     * public constructor and the Craft layer, a migration or a future contributor can build one
     * without going through the recorder. Values under a credential-sounding key are dropped,
     * long strings are cut, and the structure is bounded so a whole assertion cannot be smuggled
     * in as "context".
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    public static function scrubStructure(array $data, int $maxDepth = 4, int $maxKeys = 40): array
    {
        $out = [];
        $count = 0;

        foreach ($data as $key => $value) {
            if ($count >= $maxKeys) {
                $out[self::TRUNCATED] = sprintf('%d more key(s)', count($data) - $count);
                break;
            }

            $count++;
            $key = is_string($key) ? Ascii::truncateBytes($key, 128) : $key;

            if (is_string($key) && self::isSensitiveName($key)) {
                $out[$key] = self::REDACTED;
                continue;
            }

            if (is_array($value)) {
                $out[$key] = $maxDepth <= 1
                    ? self::TRUNCATED
                    : self::scrubStructure($value, $maxDepth - 1, $maxKeys);
                continue;
            }

            if (is_string($value)) {
                $out[$key] = Ascii::truncateBytes($value, 256);
                continue;
            }

            if (is_scalar($value) || $value === null) {
                $out[$key] = $value;
                continue;
            }

            // Objects and resources have no place in a stored diagnostics row.
            $out[$key] = self::REDACTED;
        }

        return $out;
    }

    /**
     * Group names are shown in full: they are the thing being debugged, they are not secret,
     * and a masked group name makes the panel useless.
     *
     * @param list<string> $groups
     * @return list<string>
     */
    public static function groupList(array $groups, int $max = 50): array
    {
        $out = [];

        foreach ($groups as $index => $group) {
            if ($index >= $max) {
                $out[] = sprintf('[+%d more]', count($groups) - $max);
                break;
            }

            $out[] = Ascii::truncateBytes((string)$group, 128);
        }

        return $out;
    }
}
