<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

/**
 * What issuing a browser binding produced: the cookie to set (or nothing), and the bookkeeping
 * that has to travel inside the login state.
 *
 * `context()` always carries a decision. When no binding could be issued it carries the WORD
 * "unbound", not an absence - the absence is what makes a fail-closed check impossible.
 */
final class IssuedBinding
{
    public readonly bool $bound;
    public readonly ?CookieDirective $cookie;
    private string $hash;

    private function __construct(bool $bound, ?CookieDirective $cookie, string $hash)
    {
        $this->bound = $bound;
        $this->cookie = $cookie;
        $this->hash = $hash;
    }

    public static function bound(CookieDirective $cookie, string $hash): self
    {
        return new self(true, $cookie, $hash);
    }

    public static function unbound(): self
    {
        return new self(false, null, '');
    }

    /**
     * Keys to merge into the login state context. Never contains the secret itself.
     *
     * @return array<string, string>
     */
    public function context(): array
    {
        if (!$this->bound) {
            return [BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND];
        }

        return [
            BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_BOUND,
            BrowserBinding::CONTEXT_HASH => $this->hash,
        ];
    }
}
