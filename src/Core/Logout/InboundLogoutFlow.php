<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Logout;

use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Throwable;
use Keyway\Sso\Core\Diagnostics\DiagnosticsRecorder;
use Keyway\Sso\Core\Port\LogoutSessionInterface;
use Keyway\Sso\Protocol\Saml\InboundLogoutRequest;

/**
 * The decision half of IdP-initiated single logout: match, then end - never the other way round.
 *
 * Lives in Core\ and not in the controller for the usual reason of this codebase: everything
 * here has security weight, and a rule that cannot be tested without booting a CMS is a rule
 * nobody re-tests after changing it. The controller reads a query string, hands over an already
 * verified InboundLogoutRequest, and turns the LogoutDecision into a redirect. Every "may this
 * session be ended" question is answered here.
 *
 * ------------------------------------------------------------------------------------------
 * THE ONE INVARIANT
 * ------------------------------------------------------------------------------------------
 *
 * endCurrentSession() is called on exactly ONE path: the one where the recorded subject matched
 * the subject the IdP named. There is no fallback, and adding one would not be a shortcut but a
 * different feature - "end whoever is holding this browser" - which is what a logout CSRF wants
 * and what an authentic-but-not-authorised message buys. Mismatch and no-session both answer
 * unknownPrincipal with nothing ended, and both are written to diagnostics, because from the
 * administrator's chair "the IdP says it logged them out and Craft did not" is otherwise
 * invisible.
 */
final class InboundLogoutFlow
{
    /** The diagnostics protocol label; the SLO endpoint is SAML-only. */
    public const PROTOCOL = 'saml';

    private LogoutSessionInterface $session;
    private DiagnosticsRecorder $diagnostics;

    public function __construct(LogoutSessionInterface $session, DiagnosticsRecorder $diagnostics)
    {
        $this->session = $session;
        $this->diagnostics = $diagnostics;
    }

    public function apply(InboundLogoutRequest $request): LogoutDecision
    {
        $subject = $this->session->current();

        if ($subject === null) {
            return $this->record(LogoutDecision::noSession());
        }

        if (!$request->matches($subject->nameId, $subject->sessionIndex)) {
            // NOT a degradation point. See the class docblock.
            return $this->record(LogoutDecision::subjectMismatch());
        }

        if (!$this->session->endCurrentSession()) {
            return $this->record(LogoutDecision::couldNotEnd());
        }

        // One browser holds one session. When the IdP named several, the others are somebody
        // else's browser or somebody else's service provider, and reporting Success for them
        // would be reporting a logout that did not happen.
        if ($request->namedSessionCount() > 1) {
            return $this->record(LogoutDecision::endedPartially($request->namedSessionCount()));
        }

        return $this->record(LogoutDecision::ended());
    }

    /**
     * Anything that went wrong before a decision could be made: a refused message, an unusable
     * connection, a fault inside the reader.
     *
     * HERE AND NOT IN THE CONTROLLER, because a catch block in a class nobody can test is a
     * catch block nobody can prove exists. The endpoint is public and unauthenticated: without
     * this, a misconfigured IdP or a malformed query turns into an uncaught exception, which
     * Craft renders as HTTP 500 with a stack trace in devMode - on an address anybody may call.
     * The answer is an ordinary refusal with a reason code on the diagnostics timeline.
     *
     * NOTHING IS ENDED on this path, and nothing can be: the session is never touched here. A
     * reader that refused a message has established nothing about who sent it.
     *
     * The exception's own message is not copied into diagnostics for a refusal we cannot
     * classify - the same rule LoginFlow applies to database faults: an arbitrary exception
     * message may carry a statement or a path, and DiagnosticEvent length-caps but does not mask
     * the message field. A known reader refusal is safe, because its message is one this
     * codebase wrote.
     */
    public function refused(Throwable $error): LogoutDecision
    {
        if ($error instanceof IdentityReaderException) {
            return $this->record(LogoutDecision::refused($error->reasonCode(), $error->getMessage()));
        }

        return $this->record(LogoutDecision::refused(
            LogoutDecision::REASON_UNREADABLE,
            'A single logout request could not be processed: ' . $error::class . '. '
            . 'No session was ended.'
        ));
    }

    /**
     * Every outcome reaches the panel: the refusals as failures, the clean logout as a notice.
     * A silent successful logout is the one an administrator chasing "why am I signed out"
     * cannot account for.
     */
    private function record(LogoutDecision $decision): LogoutDecision
    {
        if ($decision->reasonCode === null) {
            $this->diagnostics->recordNotice(
                self::PROTOCOL,
                DiagnosticEvent::STAGE_SESSION,
                'logout_completed',
                $decision->message
            );

            return $decision;
        }

        $this->diagnostics->recordFailure(
            self::PROTOCOL,
            DiagnosticEvent::STAGE_SESSION,
            $decision->reasonCode,
            $decision->message
        );

        return $decision;
    }
}
