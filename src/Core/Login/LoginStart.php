<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;

/**
 * "Send the browser here, and set this cookie first" - or "do not start a login at all".
 *
 * A value, like ProvisioningDecision: the core decides, the Craft controller performs. The
 * controller's whole job for a start is three lines - set the cookie if there is one, redirect
 * to the URL, or show the refusal - and there is nothing in it worth a test that boots a CMS.
 *
 * ORDER MATTERS AND IT IS THE CONTROLLER'S RESPONSIBILITY: the cookie has to be on the same
 * response as the redirect. A redirect sent first, cookie second, is a login that starts
 * unbound and fails at the callback.
 */
final class LoginStart
{
    public readonly bool $started;
    public readonly string $reasonCode;
    public readonly string $message;
    public readonly ?string $redirectUrl;
    public readonly ?CookieDirective $cookie;
    public readonly ?DiagnosticEvent $event;

    private function __construct(
        bool $started,
        string $reasonCode,
        string $message,
        ?string $redirectUrl,
        ?CookieDirective $cookie,
        ?DiagnosticEvent $event
    ) {
        $this->started = $started;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
        $this->redirectUrl = $redirectUrl;
        $this->cookie = $cookie;
        $this->event = $event;
    }

    public static function go(string $redirectUrl, ?CookieDirective $cookie): self
    {
        return new self(true, 'ok', 'Redirecting to the identity provider.', $redirectUrl, $cookie, null);
    }

    public static function refused(string $reasonCode, string $message, ?DiagnosticEvent $event = null): self
    {
        return new self(false, $reasonCode, $message, null, null, $event);
    }

    /**
     * True when this login is going out WITHOUT a browser binding.
     *
     * Not an error and not a silent state: the callback will accept it, the settings screen
     * warns about it and a diagnostics row records it.
     */
    public function isUnbound(): bool
    {
        return $this->started && $this->cookie === null;
    }

    /**
     * Safe to show on the login screen.
     */
    public function publicMessage(): string
    {
        return $this->started ? 'Redirecting to the identity provider.' : LoginRefusal::PUBLIC_MESSAGE;
    }
}
