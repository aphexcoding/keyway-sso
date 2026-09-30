<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Core\Port\RejectionDetailInterface;

/**
 * A FakeIdentityReader that also keeps an administrator-facing detail, as both shipped readers
 * do. Separate from the fake rather than a flag on it, so that the plain fake stays a reader
 * WITHOUT a detail - "a reader that has nothing to add" is one of the cases LoginFlow has to
 * handle, and it has to stay provable.
 *
 * `$detail` is public and unfiltered on purpose: the tests put hostile text in it.
 */
final class DetailedIdentityReader implements IdentityReaderInterface, RejectionDetailInterface
{
    public string $detail = '';

    private FakeIdentityReader $inner;

    public function __construct(FakeIdentityReader $inner)
    {
        $this->inner = $inner;
    }

    public function protocol(): string
    {
        return $this->inner->protocol();
    }

    public function read(array $request): IdentityPayload
    {
        return $this->inner->read($request);
    }

    public function detail(): string
    {
        return $this->detail;
    }
}
