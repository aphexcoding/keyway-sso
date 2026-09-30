<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Identity;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * What the IdP said about the person logging in, after the protocol layer has verified it.
 *
 * Immutable and protocol-agnostic: a SAML assertion and an OIDC id_token both end up here.
 * Every attribute is stored as a list of strings, because SAML attributes are multi-valued by
 * definition and single-valued handling is a mapping decision, not a transport decision.
 */
final class IdentityPayload
{
    /** @var array<string, list<string>> */
    private array $attributes;

    /** @var array<string, string> lowercased name => original name */
    private array $index;

    private string $nameId;
    private string $issuer;
    private ?string $sessionIndex;

    /**
     * @param array<string, string|int|float|bool|array<mixed>> $attributes
     */
    public function __construct(
        string $nameId,
        array $attributes = [],
        string $issuer = '',
        ?string $sessionIndex = null
    ) {
        $this->nameId = Ascii::trim($nameId);
        $this->issuer = Ascii::trim($issuer);
        $this->sessionIndex = $sessionIndex;

        $normalised = [];
        $index = [];

        foreach ($attributes as $name => $value) {
            $name = (string)$name;
            if (Ascii::trim($name) === '') {
                throw new InvalidArgumentException('Attribute name must not be empty.');
            }

            $normalised[$name] = self::normaliseValues($value);

            $key = Ascii::lower($name);
            // First declaration wins, so a case-variant duplicate cannot shadow the original.
            if (!isset($index[$key])) {
                $index[$key] = $name;
            }
        }

        $this->attributes = $normalised;
        $this->index = $index;
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private static function normaliseValues(mixed $value): array
    {
        if (!is_array($value)) {
            $value = [$value];
        }

        $out = [];
        foreach ($value as $item) {
            if ($item === null) {
                continue;
            }
            if (is_bool($item)) {
                $item = $item ? 'true' : 'false';
            }
            if (is_array($item) || is_object($item)) {
                // Nested structures are not something an IdP attribute may carry; dropping is
                // safer than a lossy cast that could smuggle "Array" into a username.
                continue;
            }
            $out[] = (string)$item;
        }

        return $out;
    }

    public function nameId(): string
    {
        return $this->nameId;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function sessionIndex(): ?string
    {
        return $this->sessionIndex;
    }

    /**
     * Exact name first, then a case-insensitive fallback.
     *
     * IdPs are inconsistent about attribute casing (`emailAddress` vs `emailaddress` in AD FS),
     * and forcing an administrator to guess the casing is the single most common support ticket
     * in this category of plugin.
     *
     * @return list<string>
     */
    public function values(string $name): array
    {
        if (isset($this->attributes[$name])) {
            return $this->attributes[$name];
        }

        $key = Ascii::lower($name);
        if (isset($this->index[$key])) {
            return $this->attributes[$this->index[$key]];
        }

        return [];
    }

    public function has(string $name): bool
    {
        if (isset($this->attributes[$name])) {
            return true;
        }

        return isset($this->index[Ascii::lower($name)]);
    }

    /**
     * @return array<string, list<string>>
     */
    public function all(): array
    {
        return $this->attributes;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->attributes);
    }
}
