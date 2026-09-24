<?php

declare(strict_types=1);

use Keyway\Sso\Core\Diagnostics\DiagnosticsRecorder;
use Keyway\Sso\Core\Logout\InboundLogoutFlow;
use Keyway\Sso\Core\Logout\LogoutDecision;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Logout\SessionSubject;
use Keyway\Sso\Protocol\Saml\InboundLogoutRequest;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CollectingSink;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\SequenceRandomSource;
use Keyway\Sso\Test\Support\StubLogoutSession;

/**
 * The Craft half of IdP-initiated single logout: which session gets ended, and what the identity
 * provider is told about it.
 *
 * BEHAVIOURAL THROUGHOUT. Nothing here greps a source file; every case runs the flow and looks
 * at two things - the decision it returned and whether the session stub was actually touched.
 * The second is the one that catches the failure this feature exists to avoid, because a flow
 * that refuses a mismatched subject and ends the session anyway returns exactly the same
 * decision as one that does not.
 */

/** @return array{0: InboundLogoutFlow, 1: StubLogoutSession, 2: CollectingSink} */
$build = static function (?SessionSubject $subject, bool $endsSuccessfully = true): array {
    $session = new StubLogoutSession($subject);
    $session->endsSuccessfully = $endsSuccessfully;
    $sink = new CollectingSink();
    $recorder = new DiagnosticsRecorder(
        $sink,
        new FixedClock(1_760_000_000),
        new SequenceRandomSource(['logout-id-0000000'])
    );

    return [new InboundLogoutFlow($session, $recorder), $session, $sink];
};

/** @param list<string> $sessionIndexes */
$request = static function (string $nameId, array $sessionIndexes): InboundLogoutRequest {
    return new InboundLogoutRequest('_idp_req_1', $nameId, null, $sessionIndexes, null);
};

return [
    'the named session is ended and the IdP is told Success' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $decision = $flow->apply($request('alice@example.test', ['_session_7']));

            Assert::same(LogoutDecision::ANSWER_SUCCESS, $decision->answer);
            Assert::true($decision->sessionEnded, 'the decision says the session is gone');
            Assert::same(1, $session->endings, 'and the session really was ended');
        },

    // THE CASE THIS FEATURE EXISTS FOR. The browser carrying the request belongs to whoever
    // followed the link; a subject that does not match is exactly the case where that is a
    // different person from the one the IdP meant. Degrading to "end the current session" here
    // would turn a signed GET into a way to log anybody out.
    'a request for somebody else ends NOTHING and answers unknownPrincipal' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $decision = $flow->apply($request('mallory@example.test', ['_session_7']));

            Assert::same(LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL, $decision->answer);
            Assert::false($decision->sessionEnded);
            Assert::same(0, $session->endings, 'the session of the person holding this browser survives');
        },

    // Same subject, a session index the IdP did not name: still not our session to end.
    'a request naming another session of the same subject ends nothing' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $decision = $flow->apply($request('alice@example.test', ['_session_9']));

            Assert::same(LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL, $decision->answer);
            Assert::same(0, $session->endings);
        },

    // An empty SessionIndex list is the WIDER request - every session of that subject - and not
    // "no session named, nothing to do".
    'no SessionIndex at all means every session of that subject, so ours goes' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $decision = $flow->apply($request('alice@example.test', []));

            Assert::same(LogoutDecision::ANSWER_SUCCESS, $decision->answer);
            Assert::same(1, $session->endings);
        },

    'a wide request still checks the subject' => static function () use ($build, $request): void {
        [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

        $decision = $flow->apply($request('mallory@example.test', []));

        Assert::same(LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL, $decision->answer);
        Assert::same(0, $session->endings);
    },

    // Reporting Success for sessions we never touched is a lie the IdP acts on: it marks the
    // whole logout done and stops asking the other service providers.
    'several named sessions, one ended: PartialLogout, not Success' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_a'));

            $decision = $flow->apply($request('alice@example.test', ['_session_a', '_session_b']));

            Assert::same(LogoutDecision::ANSWER_PARTIAL, $decision->answer);
            Assert::true($decision->sessionEnded);
            Assert::same(1, $session->endings);
        },

    'a browser with no session is told unknownPrincipal' => static function () use ($build, $request): void {
        [$flow, $session] = $build(null);

        $decision = $flow->apply($request('alice@example.test', ['_session_7']));

        Assert::same(LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL, $decision->answer);
        Assert::same(LogoutDecision::REASON_NO_SESSION, $decision->reasonCode);
        Assert::same(0, $session->endings);
    },

    'a session that refuses to end is a responder error, never a Success' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'), false);

            $decision = $flow->apply($request('alice@example.test', ['_session_7']));

            Assert::same(LogoutDecision::ANSWER_RESPONDER_ERROR, $decision->answer);
            Assert::false($decision->sessionEnded, 'the session is still open and we say so');
            Assert::same(1, $session->endings, 'we did try');
        },

    // From the administrator's chair, "the IdP says they were logged out and Craft did not do it"
    // is invisible without this.
    'every refusal reaches the diagnostics panel with a code' =>
        static function () use ($build, $request): void {
            [$flow, , $sink] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $flow->apply($request('mallory@example.test', ['_session_7']));

            $event = $sink->last();
            Assert::notNull($event, 'a refused logout is recorded');
            Assert::same(LogoutDecision::REASON_SUBJECT_MISMATCH, $event?->reasonCode);
            Assert::same('session', $event?->stage);
        },

    'a completed logout is recorded too' => static function () use ($build, $request): void {
        [$flow, , $sink] = $build(new SessionSubject('alice@example.test', '_session_7'));

        $flow->apply($request('alice@example.test', ['_session_7']));

        Assert::same(1, count($sink->events), 'one line per logout, always');
    },

    // Byte for byte: an IdP name id is opaque, and folding case or trimming would merge two
    // subjects SAML considers different.
    'the subject comparison is exact - no trimming, no case folding' =>
        static function () use ($build, $request): void {
            foreach (['Alice@example.test', ' alice@example.test', 'alice@example.test '] as $variant) {
                [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

                $decision = $flow->apply($request($variant, ['_session_7']));

                Assert::same(
                    LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL,
                    $decision->answer,
                    $variant . ' is a different subject'
                );
                Assert::same(0, $session->endings, $variant . ' must not end the session');
            }
        },

    'the session index comparison is exact too' => static function () use ($build, $request): void {
        [$flow, $session] = $build(new SessionSubject('alice@example.test', '_session_7'));

        $flow->apply($request('alice@example.test', [' _session_7']));

        Assert::same(0, $session->endings);
    },

    // The IdP named specific sessions and we cannot tell whether ours is one of them. Ending it
    // would be acting on a guess about which session was meant.
    'a session recorded without an index does not match a request that names one' =>
        static function () use ($build, $request): void {
            [$flow, $session] = $build(new SessionSubject('alice@example.test', null));

            $decision = $flow->apply($request('alice@example.test', ['_session_7']));

            Assert::same(LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL, $decision->answer);
            Assert::same(0, $session->endings);
        },

    // The endpoint is public and unauthenticated. Without this the first malformed query, or an
    // IdP whose certificate was rotated, is an uncaught exception - HTTP 500, and a stack trace
    // whenever devMode is on.
    'a refused message is an ordinary refusal with a code, not an exception' =>
        static function () use ($build): void {
            [$flow, $session, $sink] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $decision = $flow->refused(new IdentityReaderException(
                IdentityReaderException::SIGNATURE_INVALID,
                'The logout request signature did not verify.'
            ));

            Assert::same(LogoutDecision::ANSWER_RESPONDER_ERROR, $decision->answer);
            Assert::same(IdentityReaderException::SIGNATURE_INVALID, $decision->reasonCode);
            Assert::false($decision->sessionEnded);
            Assert::same(0, $session->endings, 'a refused message establishes nothing about anybody');
            Assert::same(IdentityReaderException::SIGNATURE_INVALID, $sink->last()?->reasonCode);
        },

    'an unclassifiable fault is refused too, without leaking its message' =>
        static function () use ($build): void {
            [$flow, $session, $sink] = $build(new SessionSubject('alice@example.test', '_session_7'));

            $decision = $flow->refused(new RuntimeException('SQLSTATE[42S02]: table keyway_sso_x missing'));

            Assert::same(LogoutDecision::ANSWER_RESPONDER_ERROR, $decision->answer);
            Assert::same(LogoutDecision::REASON_UNREADABLE, $decision->reasonCode);
            Assert::same(0, $session->endings);
            Assert::notContains(
                'SQLSTATE',
                (string)$sink->last()?->message,
                'an arbitrary exception message may carry a statement or a path'
            );
        },

    'but it does match the wider request' => static function () use ($build, $request): void {
        [$flow, $session] = $build(new SessionSubject('alice@example.test', null));

        $decision = $flow->apply($request('alice@example.test', []));

        Assert::same(LogoutDecision::ANSWER_SUCCESS, $decision->answer);
        Assert::same(1, $session->endings);
    },
];
