<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

use Keyway\Sso\Core\Support\Ascii;

/**
 * Result of mapping: user field => single scalar value, ready for the Craft layer to apply.
 *
 * A field is absent when the IdP sent nothing and no default was configured. Absent is not the
 * same as empty string: overwriting an existing first name with "" on every login would be a
 * data-loss bug, so the Craft layer only touches fields present here.
 */
final class MappedAttributes
{
    /** @var array<string, string> */
    private array $values;

    /** @var list<string> Sources that carried no usable value and had no default. */
    private array $skipped;

    /**
     * @param array<string, string> $values
     * @param list<string> $skipped
     */
    public function __construct(array $values, array $skipped = [])
    {
        $this->values = $values;
        $this->skipped = array_values($skipped);
    }

    public function has(string $target): bool
    {
        return isset($this->values[$target]);
    }

    public function get(string $target, ?string $fallback = null): ?string
    {
        return $this->values[$target] ?? $fallback;
    }

    public function email(): ?string
    {
        return $this->values[UserField::EMAIL] ?? null;
    }

    public function username(): ?string
    {
        return $this->values[UserField::USERNAME] ?? null;
    }

    /**
     * Username to use when creating an account: the mapped username, or the e-mail address.
     *
     * Craft accepts an e-mail as a username and most Craft installs run with
     * `useEmailAsUsername`, so this keeps JIT provisioning working on a mapping that only
     * carries an e-mail address.
     */
    public function usernameOrEmail(): ?string
    {
        $username = $this->username();
        if ($username !== null && Ascii::trim($username) !== '') {
            return $username;
        }

        return $this->email();
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return $this->values;
    }

    /**
     * @return list<string>
     */
    public function skipped(): array
    {
        return $this->skipped;
    }
}
