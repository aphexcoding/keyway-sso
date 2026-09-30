<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Logout;

/**
 * What happened to the session, and what the identity provider is therefore going to be told.
 *
 * The two are one object on purpose. A logout that ends a session and answers unknownPrincipal,
 * or answers Success without ending one, is the failure mode worth designing out - and it is
 * only designed out if "was the session ended" and "what do we answer" cannot be decided in two
 * places. InboundLogoutFlow produces one of these; the controller translates it and has no
 * licence to disagree with it.
 */
final class LogoutDecision
{
    /** The named session is gone. Answer with SamlLogoutResponse::success(). */
    public const ANSWER_SUCCESS = 'success';

    /** Ours is gone, others the IdP named are not. SamlLogoutResponse::partialLogout(). */
    public const ANSWER_PARTIAL = 'partial';

    /** We hold no session for that subject, and ended nothing. unknownPrincipal(). */
    public const ANSWER_UNKNOWN_PRINCIPAL = 'unknown_principal';

    /** Our own failure - we tried and the session is still alive. responderError(). */
    public const ANSWER_RESPONDER_ERROR = 'responder_error';

    /** Reason codes, written to diagnostics so a refusal is visible in the panel. */
    public const REASON_NO_SESSION = 'logout_no_session';
    public const REASON_SUBJECT_MISMATCH = 'logout_subject_mismatch';
    public const REASON_SESSION_NOT_ENDED = 'logout_session_not_ended';
    public const REASON_PARTIAL = 'logout_partial';

    /** A fault we cannot classify. Never a 500 on a public endpoint. */
    public const REASON_UNREADABLE = 'logout_unreadable';

    public readonly string $answer;

    /** Whether the session in this browser was actually ended. Never inferred from $answer. */
    public readonly bool $sessionEnded;

    /** Null only when there is nothing an operator would need explained. */
    public readonly ?string $reasonCode;

    public readonly string $message;

    private function __construct(string $answer, bool $sessionEnded, ?string $reasonCode, string $message)
    {
        $this->answer = $answer;
        $this->sessionEnded = $sessionEnded;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
    }

    public static function ended(): self
    {
        return new self(
            self::ANSWER_SUCCESS,
            true,
            null,
            'A single logout request from the identity provider ended the session in this browser.'
        );
    }

    public static function endedPartially(int $namedSessions): self
    {
        return new self(
            self::ANSWER_PARTIAL,
            true,
            self::REASON_PARTIAL,
            sprintf(
                'The identity provider named %d sessions; the one in this browser was ended and '
                . 'the rest are beyond this site. Answered PartialLogout rather than Success.',
                $namedSessions
            )
        );
    }

    public static function noSession(): self
    {
        return new self(
            self::ANSWER_UNKNOWN_PRINCIPAL,
            false,
            self::REASON_NO_SESSION,
            'A logout request arrived in a browser holding no single sign-on session. '
            . 'Nothing was ended.'
        );
    }

    /**
     * The subject the IdP named is NOT the subject of this browser's session.
     *
     * Ends nothing, by construction. The browser carrying the request belongs to whoever
     * followed the link, and a mismatched subject is precisely the case where that is somebody
     * other than the person the IdP meant.
     */
    public static function subjectMismatch(): self
    {
        return new self(
            self::ANSWER_UNKNOWN_PRINCIPAL,
            false,
            self::REASON_SUBJECT_MISMATCH,
            'A logout request named a subject other than the one signed in to this browser. '
            . 'No session was ended.'
        );
    }

    public static function couldNotEnd(): self
    {
        return new self(
            self::ANSWER_RESPONDER_ERROR,
            false,
            self::REASON_SESSION_NOT_ENDED,
            'The subject matched but the session could not be ended. The identity provider was '
            . 'told so rather than being sent a Success for a session that is still open.'
        );
    }

    /** Anything thrown on the way - a refused message, a broken IdP, an unusable connection. */
    public static function refused(string $reasonCode, string $message): self
    {
        return new self(self::ANSWER_RESPONDER_ERROR, false, $reasonCode, $message);
    }
}
