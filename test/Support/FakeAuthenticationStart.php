<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\AuthenticationStartInterface;
use Keyway\Sso\Core\State\StateToken;

final class FakeAuthenticationStart implements AuthenticationStartInterface
{
    private string $url;
    private StateToken $state;

    public function __construct(string $url, StateToken $state)
    {
        $this->url = $url;
        $this->state = $state;
    }

    public function url(): string
    {
        return $this->url;
    }

    public function state(): StateToken
    {
        return $this->state;
    }
}
