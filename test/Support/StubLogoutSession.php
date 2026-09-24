<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Logout\SessionSubject;
use Keyway\Sso\Core\Port\LogoutSessionInterface;

/**
 * A browser session with a memory of whether anybody ended it.
 *
 * `$endings` is the assertion that matters, and it is the reason this is a counter rather than a
 * boolean: a flow that refuses a mismatched subject with the right status code and ends the
 * session anyway would satisfy every assertion made on the returned decision. "Nothing was
 * ended" is not visible from a return value.
 */
final class StubLogoutSession implements LogoutSessionInterface
{
    /** Every endCurrentSession() call, counted. Must stay 0 on every refusal path. */
    public int $endings = 0;

    /** @var list<SessionSubject> Every remember() call, in order. */
    public array $remembered = [];

    /** Whether Craft would actually drop the session; false exercises the responder error. */
    public bool $endsSuccessfully = true;

    private ?SessionSubject $subject;

    public function __construct(?SessionSubject $subject = null)
    {
        $this->subject = $subject;
    }

    public function remember(SessionSubject $subject): void
    {
        $this->remembered[] = $subject;
        $this->subject = $subject;
    }

    public function current(): ?SessionSubject
    {
        return $this->subject;
    }

    public function endCurrentSession(): bool
    {
        $this->endings++;

        if ($this->endsSuccessfully) {
            $this->subject = null;
        }

        return $this->endsSuccessfully;
    }
}
