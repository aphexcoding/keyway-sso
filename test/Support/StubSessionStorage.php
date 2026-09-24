<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use RuntimeException;
use yii\web\Session;

/** Craft's session bag as a plain array, with a switch for "the write blows up". */
final class StubSessionStorage extends Session
{
    /** @var array<string, mixed> */
    public array $bag = [];

    public bool $writesFail = false;

    public function __construct()
    {
        // Deliberately no parent::__construct(): no application, no PHP session.
    }

    public function set($key, $value): void
    {
        if ($this->writesFail) {
            throw new RuntimeException('session storage is unavailable');
        }

        $this->bag[(string)$key] = $value;
    }

    public function get($key, $defaultValue = null): mixed
    {
        return $this->bag[(string)$key] ?? $defaultValue;
    }
}
