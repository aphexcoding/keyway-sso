<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use Keyway\Sso\Core\Support\Ascii;

/**
 * "Write down that this issuer created this account" - as a value the Craft layer carries out.
 *
 * The same split as ProvisioningDecision, for the same reason, and it is worth saying why this
 * tiny object exists at all instead of three lines in the controller. The rule behind it -
 * WHEN a link may be written - is a security rule: a link written for a login that merely
 * ATTACHED itself to an existing account (`linkExistingAccounts` on) would keep step 4a open for
 * that account forever, so that turning the setting back off would no longer close anything.
 * That is exactly the kind of rule that must not live in a class nobody can test without booting
 * a CMS, and controllers\SsoController is such a class by design.
 *
 * So the rule lives here, in five conditions, all of which have to hold:
 *
 *  1. the login was ALLOWED - nothing is recorded about a refusal;
 *  2. the decision was ProvisioningAction::Create, i.e. this plugin made the account. Update and
 *     SignInOnly are deliberately excluded: the first is a link the site owner enabled and can
 *     disable again, the second is a login to an account already linked or already allowed;
 *  3. Craft came back with a user id, which only exists after the account was really written;
 *  4. the response carried an issuer, because a link with no issuer would be a link to
 *     "anybody", and IdentityLinkStoreInterface exists precisely to avoid that;
 *  5. the response carried a subject. The lookup compares (user, issuer, SUBJECT), so a link
 *     with a blank subject can never match anything - and it would be worse than useless: the
 *     unique index is on (user, issuer), so the dead row would occupy the slot and keep a real
 *     link from ever being written for that account. Both
 *     protocol readers already refuse a response with no `NameID` / `sub` (`subject_missing`),
 *     so this condition is a guard on the invariant rather than a path anybody reaches.
 */
final class IdentityLink
{
    public readonly string $userId;
    public readonly string $issuer;
    public readonly string $subject;

    private function __construct(string $userId, string $issuer, string $subject)
    {
        $this->userId = $userId;
        $this->issuer = $issuer;
        $this->subject = $subject;
    }

    /**
     * The link to write after a completed sign-in, or null when nothing should be written.
     *
     * @param int|null $userId Craft's id for the account that was just signed in (SignInResult),
     *                         or null when the sign-in produced none.
     */
    public static function afterSignIn(LoginCompletion $completion, ?int $userId): ?self
    {
        if (!$completion->allowed || $userId === null) {
            return null;
        }

        if ($completion->decision()?->createsUser() !== true) {
            return null;
        }

        $issuer = Ascii::trim($completion->issuer ?? '');
        $subject = Ascii::trim($completion->subject ?? '');

        if ($issuer === '' || $subject === '') {
            return null;
        }

        return new self((string)$userId, $issuer, $subject);
    }
}
