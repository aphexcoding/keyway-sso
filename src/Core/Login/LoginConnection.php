<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use InvalidArgumentException;
use Keyway\Sso\Core\Port\AuthenticationStarterInterface;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Core\Support\Ascii;

/**
 * One configured identity provider, as the login flow sees it.
 *
 * The MVP ships a single connection at a time (Config\AuthProtocol: disabled, saml or oidc), so
 * today the handle is simply the protocol name. It is modelled as a handle rather than as an
 * enum because the value's JOB is different from the protocol's: it is written into the login
 * state and read back at the callback to decide WHICH configuration validates the response. On
 * the day a second connection is added, that is the string that stops one provider's response
 * from being validated against another's certificate.
 *
 * `$starter` is nullable and the nullability is real, not defensive: a protocol whose request
 * builder is not written yet can still be registered for the callback half of the flow, and
 * begin() refuses with a distinct reason instead of the plugin pretending the button works.
 */
final class LoginConnection
{
    public readonly string $handle;
    public readonly CallbackStyle $callbackStyle;
    public readonly string $callbackUrl;

    /**
     * The request field carrying the login state on the way back: `RelayState` for SAML,
     * `state` for OIDC.
     */
    public readonly string $stateParameter;

    private IdentityReaderInterface $reader;
    private ?AuthenticationStarterInterface $starter;

    public function __construct(
        IdentityReaderInterface $reader,
        ?AuthenticationStarterInterface $starter,
        CallbackStyle $callbackStyle,
        string $callbackUrl,
        string $stateParameter
    ) {
        $handle = Ascii::trim($reader->protocol());

        if ($handle === '') {
            throw new InvalidArgumentException('An identity reader must report a protocol handle.');
        }

        if ($starter !== null && Ascii::trim($starter->connection()) !== $handle) {
            // The starter writes the handle into the state and the reader is chosen by it. A
            // pair that disagrees produces a login that always starts and never finishes, and
            // the symptom (an unknown connection at the callback) points nowhere near the cause.
            throw new InvalidArgumentException(sprintf(
                'Connection "%s" pairs a starter for "%s" with a reader for "%s".',
                $handle,
                $starter->connection(),
                $handle
            ));
        }

        if (Ascii::trim($stateParameter) === '') {
            throw new InvalidArgumentException('A connection must name the field carrying its state.');
        }

        $this->handle = $handle;
        $this->reader = $reader;
        $this->starter = $starter;
        $this->callbackStyle = $callbackStyle;
        $this->callbackUrl = $callbackUrl;
        $this->stateParameter = Ascii::trim($stateParameter);
    }

    public function reader(): IdentityReaderInterface
    {
        return $this->reader;
    }

    public function canStart(): bool
    {
        return $this->starter !== null;
    }

    public function starter(): ?AuthenticationStarterInterface
    {
        return $this->starter;
    }
}
