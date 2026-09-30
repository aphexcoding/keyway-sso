<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

/**
 * The verdict of checking a returning login against the browser that started it.
 *
 * Six cases rather than a boolean, because the interesting part of this check is WHY it failed.
 * A support panel that can only say "rejected" cannot tell a customer whose corporate proxy
 * strips cookies apart from an attacker splicing a login into somebody else's browser, and
 * those two tickets have opposite answers.
 */
enum BindingStatus: string
{
    /** The cookie was presented and matches the hash stored with the state. */
    case Verified = 'verified';

    /**
     * The state says, in so many words, that no binding could be issued for this login -
     * a cross-site POST callback on a site without HTTPS. The login proceeds; the degradation
     * is recorded rather than hidden.
     */
    case NotIssued = 'not_issued';

    /**
     * The state says a binding WAS issued and the browser sent no cookie. Refused.
     *
     * This is the case that must never collapse into NotIssued: deciding "there was no binding"
     * from the absence of a cookie hands the attacker an off switch they operate by sending
     * nothing at all.
     */
    case CookieMissing = 'cookie_missing';

    /** A cookie arrived and is not the one this login was issued with. Refused. */
    case Mismatch = 'mismatch';

    /**
     * The state carries no binding decision at all - neither "bound" nor "unbound".
     *
     * That is not a browser problem, it is our own: something dropped the key between issuing
     * the state and reading it back (a starter that rebuilt the context, a storage layer that
     * filtered it). Refused, for the same reason a missing `connection` is refused: a security
     * decision inferred from missing data is not a decision.
     */
    case Undeclared = 'undeclared';

    /** The state says "bound" but carries no hash to compare against. Refused. */
    case Inconsistent = 'inconsistent';

    public function allowsLogin(): bool
    {
        return $this === self::Verified || $this === self::NotIssued;
    }
}
