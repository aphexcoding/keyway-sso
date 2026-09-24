<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Access;

/**
 * May this login form submission be processed with a password at all?
 */
final class PasswordLoginDecision
{
    public const PASSWORD_LOGIN_ENABLED = 'password_login_enabled';
    public const BREAK_GLASS = 'break_glass';
    public const EMERGENCY_ACCOUNT = 'emergency_account';
    public const ADMIN_FALLBACK = 'admin_fallback';
    public const SSO_REQUIRED = 'sso_required';

    public readonly bool $allowed;
    public readonly string $reasonCode;
    public readonly string $message;

    public function __construct(bool $allowed, string $reasonCode, string $message)
    {
        $this->allowed = $allowed;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
    }

    public static function allow(string $reasonCode, string $message): self
    {
        return new self(true, $reasonCode, $message);
    }

    public static function deny(string $reasonCode, string $message): self
    {
        return new self(false, $reasonCode, $message);
    }
}
