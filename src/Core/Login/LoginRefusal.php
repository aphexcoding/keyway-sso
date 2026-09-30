<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

/**
 * Why a login was refused before a provisioning decision could be made - one code per cause.
 *
 * These are deliberately fine-grained, and that is the product feature, not tidiness. This
 * plugin's support model is "the administrator reads the diagnostics panel instead of e-mailing
 * us", so every refusal has to land on a row that says something an administrator can act on.
 * A single `login_failed` would collapse "your reverse proxy strips cookies", "somebody replayed
 * a callback" and "you changed the protocol while a login was in flight" into one unactionable
 * line.
 *
 * TWO AUDIENCES, as in ProvisioningDecision: these codes and their messages are for the
 * ADMINISTRATOR. What the person at the login screen is told is PUBLIC_MESSAGE - one sentence
 * for every refusal, so that nothing here becomes an oracle about the site's configuration or
 * about somebody else's login.
 */
final class LoginRefusal
{
    /** No request field carried a login state, so nothing ties this callback to us. */
    public const STATE_MISSING = 'state_missing';

    /** Two connections' state fields arrived at once; which login this is, is not knowable. */
    public const STATE_AMBIGUOUS = 'state_ambiguous';

    /** The state itself was refused; the StateValidation reason is carried in the message. */
    public const STATE_REJECTED = 'state_rejected';

    /**
     * The state carries no `connection`, so we do not know which configuration to validate
     * against. Refused rather than defaulted - see LoginFlow for why the default is the bug.
     */
    public const CONNECTION_MISSING = 'connection_missing';

    /** The state names a connection this site does not have configured any more. */
    public const CONNECTION_UNKNOWN = 'connection_unknown';

    /** The state came back through a different protocol's callback field than it was issued for. */
    public const CONNECTION_MISMATCH = 'connection_mismatch';

    /** The state carries no browser-binding decision at all (BindingStatus::Undeclared). */
    public const BINDING_UNDECLARED = 'binding_undeclared';

    /** The state says "bound" but carries no hash (BindingStatus::Inconsistent). */
    public const BINDING_INCONSISTENT = 'binding_inconsistent';

    /** A binding was issued and the browser sent no cookie back. */
    public const BINDING_COOKIE_MISSING = 'binding_cookie_missing';

    /** A binding cookie arrived and it is not this login's. */
    public const BINDING_MISMATCH = 'binding_mismatch';

    /** The login was allowed to proceed without a binding, because none could be issued. */
    public const BINDING_NOT_ISSUED = 'binding_not_issued';

    /**
     * A NOTICE, not a refusal, in the same shape as BINDING_NOT_ISSUED above: the login
     * succeeded, but part of what was configured could not be applied - a mapped user group that
     * does not exist on this site, a custom field that is not in the user's field layout. The
     * person is signed in with a permission set that is not the one on the settings screen, and
     * nothing else would ever say so.
     */
    public const PROVISIONING_INCOMPLETE = 'provisioning_incomplete';

    /**
     * A NOTICE as well, and the one an administrator has to see before they start blaming their
     * identity provider: the table recording which accounts single sign-on created could not be
     * read, so every account looks like one this plugin did not create. Logins to accounts made
     * just-in-time are then refused with `linking_disabled`, which reads like a configuration
     * mistake and is not one - the usual cause is that `craft up` has not been run.
     */
    public const IDENTITY_LINK_UNAVAILABLE = 'identity_link_unavailable';

    /** The protocol reader rejected the response; its own reason code is appended. */
    public const IDENTITY_REJECTED = 'identity_rejected';

    /** Attribute mapping refused the identity (required claim missing, unusable address). */
    public const ATTRIBUTES_REJECTED = 'attributes_rejected';

    /**
     * A completion said "allowed" while carrying no provisioning decision.
     *
     * Only reachable through a programming error - LoginCompletion::allow() is built from a
     * decision - and fail-closed for the same reason STATE_NOT_BURNT is: the alternative is
     * signing somebody in with nothing behind the decision to sign them in.
     */
    public const DECISION_MISSING = 'decision_missing';

    /**
     * The reader returned an identity without burning the login state.
     *
     * Only reachable through a programming error, and fail-closed on purpose: the alternative
     * is a login that succeeded and left a state somebody can use again.
     */
    public const STATE_NOT_BURNT = 'state_not_burnt';

    // -- begin() -------------------------------------------------------------------------

    /** Single sign-on is not configured, or not usable as configured. */
    public const NOT_CONFIGURED = 'not_configured';

    /** The connection has no request builder, so a login cannot be started with it yet. */
    public const CONNECTION_CANNOT_START = 'connection_cannot_start';

    /**
     * The starter dropped the bookkeeping LoginFlow put in the context, so the callback could
     * never have verified it. Caught at the start, where it points at the cause.
     */
    public const STATE_CONTEXT_LOST = 'state_context_lost';

    /**
     * Building the authentication request threw: the OIDC discovery document could not be
     * fetched or did not check out, or DEFLATE failed on the SAML AuthnRequest.
     *
     * This is the reason code for "the identity provider is unreachable or misconfigured",
     * which is the single most likely thing to be wrong on a live site, and it exists so that
     * the answer is a refusal on the login screen instead of a 500 on the page people use to
     * get in. The provider's own message is carried in the diagnostic event, not here.
     */
    public const START_FAILED = 'start_failed';

    /**
     * The only thing a refused visitor is ever told, matching ProvisioningDecision's rule and
     * for the same reason: any variation between causes is itself the oracle.
     */
    public const PUBLIC_MESSAGE = 'We could not sign you in with single sign-on. If you believe '
        . 'this is a mistake, ask the person who runs this site to check the single sign-on '
        . 'diagnostics.';

    private function __construct()
    {
    }
}
