<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

/**
 * What happened when an allowed ProvisioningDecision was carried out against Craft.
 *
 * A value, so the controller stays a translator: it either redirects or shows the one public
 * sentence, and everything an administrator would need is already written down here.
 *
 * `$notes` is the half that is easy to leave out and expensive to lose: things that did NOT
 * stop the login but that somebody has to see - a mapped group handle that does not exist on
 * this site, a custom field the user's field layout does not have. Silently dropping either one
 * produces a login that works and a permission model that quietly is not what was configured.
 */
final class SignInResult
{
    /** The account named by the decision was gone by the time we went to load it. */
    public const ACCOUNT_VANISHED = 'account_vanished';

    /** Craft refused to save the user element; its validation errors are in the message. */
    public const USER_NOT_SAVED = 'user_not_saved';

    /** Craft's own authentication status check refused this account (see helpers\User). */
    public const AUTH_REFUSED = 'auth_refused';

    /** `craft\web\User::login()` returned false. */
    public const SESSION_NOT_STARTED = 'session_not_started';

    /**
     * The account exists and is healthy, but cannot reach the control panel - so signing it in
     * would hand somebody a 403 instead of an answer. Its own code, because the fix is a group
     * mapping change and nothing else on this list is.
     */
    public const NO_CP_ACCESS = 'no_cp_access';

    /** The decision handed over was a denial; nothing was executed. */
    public const NOT_ALLOWED = 'not_allowed';

    public const SIGNED_IN = 'signed_in';

    public readonly bool $ok;
    public readonly string $reasonCode;
    public readonly string $message;
    public readonly ?int $userId;
    public readonly ?string $returnUrl;

    /** @var list<string> */
    private array $notes;

    /**
     * @param list<string> $notes
     */
    private function __construct(
        bool $ok,
        string $reasonCode,
        string $message,
        ?int $userId,
        ?string $returnUrl,
        array $notes
    ) {
        $this->ok = $ok;
        $this->reasonCode = $reasonCode;
        $this->message = $message;
        $this->userId = $userId;
        $this->returnUrl = $returnUrl;
        $this->notes = array_values($notes);
    }

    /**
     * @param list<string> $notes
     */
    public static function signedIn(int $userId, ?string $returnUrl, array $notes = []): self
    {
        return new self(true, self::SIGNED_IN, 'Signed in.', $userId, $returnUrl, $notes);
    }

    /**
     * @param list<string> $notes
     */
    public static function failed(string $reasonCode, string $message, array $notes = []): self
    {
        return new self(false, $reasonCode, $message, null, null, $notes);
    }

    /** @return list<string> */
    public function notes(): array
    {
        return $this->notes;
    }
}
