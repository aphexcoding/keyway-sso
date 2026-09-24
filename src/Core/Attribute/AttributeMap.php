<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * The ordered set of attribute rules configured for one connection.
 */
final class AttributeMap
{
    /** @var list<AttributeRule> */
    private array $rules;

    /**
     * @param list<AttributeRule> $rules
     */
    public function __construct(array $rules)
    {
        $seen = [];
        foreach ($rules as $rule) {
            if (!$rule instanceof AttributeRule) {
                throw new InvalidArgumentException('AttributeMap accepts AttributeRule only.');
            }

            $key = Ascii::lower($rule->target);
            if (isset($seen[$key])) {
                throw new InvalidArgumentException(sprintf(
                    'Duplicate mapping for target "%s": two rules writing the same field make '
                    . 'the result depend on rule order.',
                    $rule->target
                ));
            }
            $seen[$key] = true;
        }

        $this->rules = array_values($rules);
    }

    /**
     * Sensible starting point: the claim names Okta, Keycloak, Entra ID and Google all
     * understand. Shipped as the default so a first-time install logs someone in.
     */
    public static function defaults(): self
    {
        return new self([
            new AttributeRule('email', UserField::EMAIL, MultiValueStrategy::First, true),
            AttributeRule::optional('firstName', UserField::FIRST_NAME),
            AttributeRule::optional('lastName', UserField::LAST_NAME),
        ]);
    }

    /**
     * @return list<AttributeRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    public function isEmpty(): bool
    {
        return $this->rules === [];
    }
}
