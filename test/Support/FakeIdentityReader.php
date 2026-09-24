<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Core\State\StateStore;

/**
 * A protocol reader with the cryptography taken out, and with the one behaviour of the real ones
 * that the login flow depends on left in: IT CONSUMES THE LOGIN STATE ITSELF.
 *
 * Both shipped readers do that (SamlResponseReader::consumeLoginState, OidcTokenReader the
 * same), because they need the SAML request id, the OIDC nonce and the PKCE verifier out of the
 * state, and because burning it before the token endpoint call is what stops a replayed callback
 * from reaching the network. A double that skipped the burn would let LoginFlow's tests pass
 * while the real flow left a reusable state behind - which is precisely why `burns` can be
 * turned off: that is the STATE_NOT_BURNT case, and it has to be provable.
 */
final class FakeIdentityReader implements IdentityReaderInterface
{
    private string $protocol;
    private string $stateParameter;
    private StateStore $stateStore;

    public bool $burns = true;
    public ?IdentityPayload $payload = null;
    public ?IdentityReaderException $failure = null;

    /** @var list<array<string, mixed>> */
    public array $calls = [];

    public function __construct(string $protocol, string $stateParameter, StateStore $stateStore)
    {
        $this->protocol = $protocol;
        $this->stateParameter = $stateParameter;
        $this->stateStore = $stateStore;
    }

    public function protocol(): string
    {
        return $this->protocol;
    }

    public function read(array $request): IdentityPayload
    {
        $this->calls[] = $request;

        if ($this->burns) {
            $token = $request[$this->stateParameter] ?? '';
            $this->stateStore->consume(is_string($token) ? $token : '');
        }

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->payload ?? new IdentityPayload(
            'subject-1',
            ['email' => ['person@example.com'], 'groups' => ['editors']],
            'https://idp.example.com'
        );
    }
}
