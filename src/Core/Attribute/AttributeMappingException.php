<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use RuntimeException;

/**
 * A login-time mapping failure: the assertion was valid, but it does not carry what this site
 * needs. The message is written for the administrator reading the diagnostics panel, because
 * that is who has to fix it in the IdP.
 */
final class AttributeMappingException extends RuntimeException
{
    public const MISSING_REQUIRED = 'missing_required_attribute';
    public const INVALID_EMAIL = 'invalid_email';

    private string $reasonCode;

    /** @var list<string> */
    private array $attributes;

    /**
     * @param list<string> $attributes
     */
    private function __construct(string $reasonCode, string $message, array $attributes)
    {
        parent::__construct($message);
        $this->reasonCode = $reasonCode;
        $this->attributes = $attributes;
    }

    /**
     * @param list<string> $sources
     */
    public static function missingRequired(array $sources): self
    {
        return new self(
            self::MISSING_REQUIRED,
            sprintf(
                'The identity provider did not send the required attribute(s): %s. '
                . 'Add them to the SAML/OIDC claim configuration, or clear the "required" flag '
                . 'on the matching mapping rule.',
                implode(', ', $sources)
            ),
            $sources
        );
    }

    public static function invalidEmail(string $source, string $target): self
    {
        return new self(
            self::INVALID_EMAIL,
            sprintf(
                'The value mapped from "%s" to "%s" is not a valid e-mail address.',
                $source,
                $target
            ),
            [$source]
        );
    }

    public function reasonCode(): string
    {
        return $this->reasonCode;
    }

    /**
     * @return list<string>
     */
    public function attributes(): array
    {
        return $this->attributes;
    }
}
