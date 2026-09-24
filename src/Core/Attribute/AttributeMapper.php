<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Applies an AttributeMap to an IdentityPayload.
 *
 * Pure: no side effects, no I/O, no knowledge of Craft. Given the same payload and map it
 * always returns the same result, which is what makes the diagnostics panel trustworthy -
 * the administrator sees exactly the transformation that ran during the failed login.
 */
final class AttributeMapper
{
    private AttributeMap $map;

    public function __construct(AttributeMap $map)
    {
        $this->map = $map;
    }

    /**
     * @throws AttributeMappingException when a required attribute is missing or an address
     *                                   mapped to `email` is not a valid e-mail.
     */
    public function map(IdentityPayload $payload): MappedAttributes
    {
        $values = [];
        $skipped = [];
        $missing = [];

        foreach ($this->map->rules() as $rule) {
            $raw = $this->readSource($rule, $payload);
            $value = $this->collapse($rule, $raw);

            if ($value === null) {
                if ($rule->required) {
                    $missing[] = $rule->source;
                    continue;
                }

                if ($rule->defaultValue !== null) {
                    $value = $rule->defaultValue;
                } else {
                    $skipped[] = $rule->source;
                    continue;
                }
            }

            $value = $this->transform($rule, $value);

            if (Ascii::lower($rule->target) === Ascii::lower(UserField::EMAIL)) {
                $value = EmailNormalizer::normalize($value);
                if (!EmailNormalizer::isValid($value)) {
                    throw AttributeMappingException::invalidEmail($rule->source, $rule->target);
                }
            }

            $values[$rule->target] = $value;
        }

        if ($missing !== []) {
            throw AttributeMappingException::missingRequired($missing);
        }

        return new MappedAttributes($values, $skipped);
    }

    /**
     * @return list<string>
     */
    private function readSource(AttributeRule $rule, IdentityPayload $payload): array
    {
        if ($rule->source === AttributeRule::SOURCE_NAME_ID) {
            return $payload->nameId() === '' ? [] : [$payload->nameId()];
        }

        if ($rule->source === AttributeRule::SOURCE_ISSUER) {
            return $payload->issuer() === '' ? [] : [$payload->issuer()];
        }

        return $payload->values($rule->source);
    }

    /**
     * Collapses a multi-valued attribute to one value, or null when nothing usable is left.
     *
     * Values are trimmed first and blanks are dropped, so an IdP that sends an empty
     * `<AttributeValue/>` is treated as "did not send it" rather than as an empty username.
     *
     * @param list<string> $raw
     */
    private function collapse(AttributeRule $rule, array $raw): ?string
    {
        $clean = [];
        foreach ($raw as $value) {
            $value = Ascii::trim($value);
            if ($value !== '') {
                $clean[] = $value;
            }
        }

        if ($clean === []) {
            return null;
        }

        return match ($rule->strategy) {
            MultiValueStrategy::First => $clean[0],
            MultiValueStrategy::Last => $clean[count($clean) - 1],
            MultiValueStrategy::Join => implode($rule->separator, $clean),
        };
    }

    private function transform(AttributeRule $rule, string $value): string
    {
        return match ($rule->transform) {
            AttributeTransform::None => $value,
            AttributeTransform::Lowercase => Ascii::lower($value),
            AttributeTransform::Uppercase => Ascii::upper($value),
        };
    }
}
