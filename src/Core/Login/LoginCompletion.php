<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;

/**
 * The end of a login round trip, as a value: sign this person in, create them first, or refuse.
 *
 * Everything the Craft controller needs and nothing it has to work out for itself - which is
 * what keeps the controller small enough that not testing it is an honest choice rather than a
 * gap. In particular `clearBinding` is always present: the binding cookie has to come off the
 * browser whether the login succeeded or failed, and leaving that to the controller's judgement
 * is how a stale cookie survives into the next attempt.
 *
 * `decision()` is null on a refusal that happened BEFORE provisioning ran (bad state, bad
 * binding, rejected response). When it is not null, its own reason code says what provisioning
 * decided, and `reasonCode` here repeats it, so one field always answers "why".
 *
 * `$issuer` and `$subject` ride along on the ALLOWED path only, and they are UNMASKED - which is
 * the one thing about this class worth reading twice. They are here because the identity link
 * (IdentityLink, IdentityLinkStoreInterface) can only be written after Craft has created the
 * account and produced a user id, i.e. in the controller, after complete() has returned - and by
 * then the payload is gone. The obvious other source, `event()`, cannot serve: DiagnosticEvent
 * masks in its constructor, so its issuer and subject are display strings, and a link stored
 * from a masked issuer would match nothing on the next login. They are null on a refusal because
 * nothing downstream of a refusal may write anything.
 */
final class LoginCompletion
{
    public readonly bool $allowed;
    public readonly string $reasonCode;
    public readonly string $message;
    public readonly ?string $returnUrl;
    public readonly CookieDirective $clearBinding;
    public readonly ?DiagnosticEvent $event;
    public readonly bool $bindingVerified;

    /** Verified issuer of the response, unmasked, on an allowed completion only. */
    public readonly ?string $issuer;

    /** The identity provider's subject, unmasked, on an allowed completion only. */
    public readonly ?string $subject;

    /**
     * The SessionIndex of the assertion that started this session, or null when it carried none.
     *
     * Rides along for the same reason as $subject and is written down at the same moment: single
     * logout has to match an inbound LogoutRequest against the session it names, and the only
     * two values that identify a session the IdP's way are this and $subject. Both are recorded
     * through LogoutSessionInterface::remember() in the controller, after the account exists.
     *
     * NOT a licence to end anything. See InboundLogoutRequest.
     */
    public readonly ?string $sessionIndex;

    private ?ProvisioningDecision $decision;

    private function __construct(
        bool $allowed,
        string $reasonCode,
        string $message,
        ?string $returnUrl,
        CookieDirective $clearBinding,
        ?ProvisioningDecision $decision,
        ?DiagnosticEvent $event,
        bool $bindingVerified,
        ?string $issuer,
        ?string $subject,
        ?string $sessionIndex
    ) {
        $this->allowed = $allowed;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
        $this->returnUrl = $returnUrl;
        $this->clearBinding = $clearBinding;
        $this->decision = $decision;
        $this->event = $event;
        $this->bindingVerified = $bindingVerified;
        $this->issuer = $issuer;
        $this->subject = $subject;
        $this->sessionIndex = $sessionIndex;
    }

    /**
     * @param string $issuer  Verified issuer of the response, exactly as the reader read it.
     * @param string $subject The identity provider's subject, exactly as the reader read it.
     */
    public static function allow(
        ProvisioningDecision $decision,
        ?string $returnUrl,
        CookieDirective $clearBinding,
        ?DiagnosticEvent $event,
        bool $bindingVerified,
        string $issuer = '',
        string $subject = '',
        ?string $sessionIndex = null
    ): self {
        return new self(
            true,
            $decision->reasonCode,
            $decision->message,
            $returnUrl,
            $clearBinding,
            $decision,
            $event,
            $bindingVerified,
            $issuer,
            $subject,
            $sessionIndex
        );
    }

    public static function refuse(
        string $reasonCode,
        string $message,
        CookieDirective $clearBinding,
        ?ProvisioningDecision $decision = null,
        ?DiagnosticEvent $event = null,
        bool $bindingVerified = false
    ): self {
        // No issuer, no subject: a refusal is not a fact anything may be written from.
        return new self(
            false,
            $reasonCode,
            $message,
            null,
            $clearBinding,
            $decision,
            $event,
            $bindingVerified,
            null,
            null,
            null
        );
    }

    public function decision(): ?ProvisioningDecision
    {
        return $this->decision;
    }

    /**
     * Safe to show on the login screen: one sentence for every refusal.
     */
    public function publicMessage(): string
    {
        return $this->allowed ? 'Signing you in.' : LoginRefusal::PUBLIC_MESSAGE;
    }
}
