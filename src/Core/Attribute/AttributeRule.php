<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * One "IdP attribute -> user field" rule. Immutable; built once from plugin settings.
 *
 * `source` is an attribute name as sent by the IdP (`mail`, `http://schemas.../emailaddress`),
 * or one of the pseudo-sources: `@nameId`, `@issuer`.
 */
final class AttributeRule
{
    public const SOURCE_NAME_ID = '@nameId';
    public const SOURCE_ISSUER = '@issuer';

    /** @var list<string> */
    private const PSEUDO_SOURCES = [self::SOURCE_NAME_ID, self::SOURCE_ISSUER];

    public readonly string $source;
    public readonly string $target;
    public readonly MultiValueStrategy $strategy;
    public readonly string $separator;
    public readonly bool $required;
    public readonly ?string $defaultValue;
    public readonly AttributeTransform $transform;

    public function __construct(
        string $source,
        string $target,
        MultiValueStrategy $strategy = MultiValueStrategy::First,
        bool $required = false,
        ?string $defaultValue = null,
        AttributeTransform $transform = AttributeTransform::None,
        string $separator = ' '
    ) {
        $source = Ascii::trim($source);
        $target = Ascii::trim($target);

        if ($source === '') {
            throw new InvalidArgumentException('Mapping source must not be empty.');
        }

        if (str_starts_with($source, '@') && !in_array($source, self::PSEUDO_SOURCES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown pseudo-source "%s". Supported: %s.',
                $source,
                implode(', ', self::PSEUDO_SOURCES)
            ));
        }

        // Throws for anything outside the allow list, and normalises the spelling so that a
        // rule written as "Email" writes the field the rest of the core reads.
        $target = UserField::canonical($target);

        if ($required && $defaultValue !== null) {
            throw new InvalidArgumentException(
                'A rule cannot be required and have a default value at the same time: the '
                . 'default would silently hide a misconfigured identity provider.'
            );
        }

        if ($strategy === MultiValueStrategy::Join && $separator === '') {
            throw new InvalidArgumentException('Join strategy needs a non-empty separator.');
        }

        $this->source = $source;
        $this->target = $target;
        $this->strategy = $strategy;
        $this->separator = $separator;
        $this->required = $required;
        $this->defaultValue = $defaultValue;
        $this->transform = $transform;
    }

    public static function required(
        string $source,
        string $target,
        MultiValueStrategy $strategy = MultiValueStrategy::First
    ): self {
        return new self($source, $target, $strategy, true);
    }

    public static function optional(
        string $source,
        string $target,
        ?string $defaultValue = null,
        MultiValueStrategy $strategy = MultiValueStrategy::First
    ): self {
        return new self($source, $target, $strategy, false, $defaultValue);
    }

    public function isPseudoSource(): bool
    {
        return in_array($this->source, self::PSEUDO_SOURCES, true);
    }
}
