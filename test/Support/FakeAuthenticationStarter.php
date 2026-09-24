<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\AuthenticationStarterInterface;
use Keyway\Sso\Core\State\StateStore;
use RuntimeException;

/**
 * A protocol request builder with the protocol taken out: it issues real state through the real
 * StateStore and returns a URL.
 *
 * `dropContext` is the point of the class. The contract on AuthenticationStarterInterface says
 * the caller's context must survive into the state, and a starter that rebuilds it instead of
 * merging it is the exact mistake that would silently disable both the connection check and the
 * browser binding. Switching that behaviour on here is how the suite proves the flow notices.
 */
final class FakeAuthenticationStarter implements AuthenticationStarterInterface
{
    private string $handle;
    private StateStore $stateStore;

    public bool $dropContext = false;

    /** @var array<string, string> Extra keys the starter adds, as the real ones do. */
    public array $ownContext = [];

    /** @var list<array<string, string>> Contexts this starter was called with. */
    public array $calls = [];

    /**
     * When set, start() throws it instead of returning.
     *
     * The real starters both do this - OidcAuthorizationRequest fetches the discovery document
     * first and IdentityReaderException comes back from every failed fetch, SamlAuthnRequest
     * throws when DEFLATE fails - and "the identity provider is unreachable" is the most likely
     * fault on a live site, so begin() has to answer it with a refusal rather than a 500 on the
     * page people use to get in.
     */
    public ?RuntimeException $throw = null;

    public function __construct(string $handle, StateStore $stateStore)
    {
        $this->handle = $handle;
        $this->stateStore = $stateStore;
    }

    public function connection(): string
    {
        return $this->handle;
    }

    public function start(?string $returnUrl, array $context): FakeAuthenticationStart
    {
        $this->calls[] = $context;

        if ($this->throw !== null) {
            throw $this->throw;
        }

        $token = $this->stateStore->issue(
            $returnUrl,
            $this->dropContext
                ? $this->ownContext
                : array_merge($context, $this->ownContext)
        );

        return new FakeAuthenticationStart(
            'https://idp.example.com/authorize?state=' . rawurlencode($token->value),
            $token
        );
    }
}
