<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use craft\elements\User;
use craft\helpers\User as UserHelper;
use craft\services\Elements;
use craft\services\UserGroups;
use craft\services\Users;
use craft\web\User as UserSession;
use Keyway\Sso\Core\Access\ControlPanelAccess;
use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Attribute\UserField;
use Keyway\Sso\Core\Group\GroupSync;
use Keyway\Sso\Core\Provisioning\ProvisioningAction;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;
use Keyway\Sso\Core\Support\Ascii;
use Throwable;

/**
 * Carries out an allowed ProvisioningDecision: create or update the account, put it in the
 * groups the mapping asked for, and start the session.
 *
 * THE WHOLE POINT OF THE SPLIT. Everything about WHETHER somebody may sign in, WHICH account
 * they are, WHICH fields and groups they should end up with and WHY was decided upstream, in
 * classes with no Craft in them and a test each. This class knows none of that. It is the hand
 * that writes, and it has no opinion at all about what it is writing - which is what keeps the
 * part of this plugin that can lock a client out of their control panel inside the half that
 * `php bin/test.php` covers.
 *
 * As with CraftLoginRuntime, `Craft::$app` is never read here. The four services and the session
 * arrive as arguments, from Plugin.
 *
 * THE ONE EXTRA ARGUMENT - THE ELEMENT FACTORY - IS THERE FOR A MEASURED REASON. `new User()`
 * cannot be evaluated outside a booted Craft (it wires craft\behaviors\CustomFieldBehavior and
 * ends in "Unknown component ID: errorHandler"), so as long as the creation path built its own
 * element, that path was the one branch of this class no test could enter - and it is the branch
 * that was broken in production on 2026-09-15 (see resolveUser()). The seam is the smallest that
 * closes that: production passes nothing and gets `new User()`; the suite passes a fixture and
 * can watch what JIT provisioning actually writes.
 *
 * ------------------------------------------------------------------------------------------
 * THINGS MEASURED IN CRAFT'S OWN SOURCE, NOT ASSUMED
 * ------------------------------------------------------------------------------------------
 *
 *  - `User::$active` may be set only when the element is NEW. On an existing element Craft
 *    throws "Unable to change a user's active state like this" from afterSave()
 *    (`elements/User.php`, the `!$isNew` branch), so an update never touches it. The same branch
 *    is why `suspended`, `locked` and `pending` are not written either - which is fine, because
 *    Core\Attribute\UserField refuses to map to them in the first place.
 *  - `helpers\User::getAuthStatus()` is asked BEFORE the session starts, exactly as Craft's own
 *    SSO service does (`services/Sso.php::loginUser()`). It is not a duplicate of the
 *    provisioning policy's status check: it answers "is this account suspended, pending, locked,
 *    archived, or owed a password reset" for an account we may have just created.
 *  - CONTROL-PANEL ACCESS IS CHECKED SEPARATELY, AND THAT IS NOT BELT AND BRACES. getAuthStatus()
 *    asks `accessCp` only inside its `$request->getIsCpRequest()` branch (`helpers/User.php`),
 *    and `getIsCpRequest()` is true only under the site's `cpTrigger` or CP base URL
 *    (`web/Request.php`). The address this plugin tells an administrator to register with the
 *    identity provider is an ACTION URL (`/actions/keyway-sso/sso/acs`), which is not a control
 *    panel request - so relying on that branch would mean the same login succeeds or fails
 *    depending on which of two equivalent callback URLs was configured, and a just-created
 *    account with no `accessCp` would be signed in and dropped on the front end with no
 *    diagnostics row saying why. So `accessCp` (and `accessCpWhenSystemIsOff` when the system is
 *    offline) is asked here, unconditionally, and `$systemIsLive` is passed in rather than read
 *    from the application for the same reason as everything else in this class.
 *  - `assignUserToGroups()` replaces the whole set (`services/Users.php`), so the merge with the
 *    groups the account already has happens first, in Core\Group\GroupSync, where the two sync
 *    modes are a tested decision rather than a loop in this file.
 *
 * A MAPPED GROUP THAT DOES NOT EXIST ON THIS SITE IS A NOTE, NOT A REFUSAL. It is an
 * administrator's typo, and the alternative - failing the login - means one wrong character in
 * the group table locks everybody out. The handle is recorded in SignInResult::notes() and the
 * controller turns that into a diagnostics row.
 */
final class CraftSignIn
{
    private UserSession $session;
    private Users $users;
    private UserGroups $groups;
    private Elements $elements;
    private int $sessionDuration;
    private bool $systemIsLive;
    private bool $craftKeepsUserGroups;

    /** @var callable(): User Builds the element a JIT creation writes into. */
    private $newUser;

    /**
     * @param bool $craftKeepsUserGroups Whether this installation's Craft edition stores user
     *     group memberships at all - false below Craft Pro. Passed in, like `$systemIsLive`,
     *     rather than read from the application, so that the branch it controls is reachable in
     *     a test.
     * @param (callable(): User)|null $newUser Defaults to `new User()`; see the docblock above
     *     for why the creation path needs a seam at all.
     */
    public function __construct(
        UserSession $session,
        Users $users,
        UserGroups $groups,
        Elements $elements,
        int $sessionDuration,
        bool $systemIsLive = true,
        bool $craftKeepsUserGroups = true,
        ?callable $newUser = null
    ) {
        $this->session = $session;
        $this->users = $users;
        $this->groups = $groups;
        $this->elements = $elements;
        $this->sessionDuration = $sessionDuration;
        $this->systemIsLive = $systemIsLive;
        $this->craftKeepsUserGroups = $craftKeepsUserGroups;
        $this->newUser = $newUser ?? static fn (): User => new User();
    }

    public function signIn(ProvisioningDecision $decision): SignInResult
    {
        if ($decision->isDenied()) {
            // Defensive: LoginFlow never hands a denial this way. Executing one would be the
            // worst possible bug in this file, so it is refused rather than trusted.
            return SignInResult::failed(
                SignInResult::NOT_ALLOWED,
                'A denied provisioning decision was handed to the sign-in step and was not executed.'
            );
        }

        $notes = [];

        try {
            $user = $this->resolveUser($decision);
        } catch (Throwable $error) {
            return SignInResult::failed(
                SignInResult::ACCOUNT_VANISHED,
                'The account this login resolved to could not be loaded: ' . $error->getMessage()
            );
        }

        if ($user === null) {
            return SignInResult::failed(
                SignInResult::ACCOUNT_VANISHED,
                sprintf(
                    'The Craft account (id %s) this login matched no longer exists. It was most '
                    . 'likely deleted while the login was in flight.',
                    (string)$decision->userId
                )
            );
        }

        if ($decision->writesUser()) {
            $notes = array_merge($notes, $this->applyAttributes($user, $decision->attributes()));
            $this->applyAdmin($user, $decision);

            try {
                $saved = $this->elements->saveElement($user);
            } catch (Throwable $error) {
                return SignInResult::failed(
                    SignInResult::USER_NOT_SAVED,
                    'Craft refused to save the account: ' . $error->getMessage(),
                    $notes
                );
            }

            if (!$saved) {
                return SignInResult::failed(
                    SignInResult::USER_NOT_SAVED,
                    'Craft refused to save the account: ' . self::errorsOf($user),
                    $notes
                );
            }

            $notes = array_merge($notes, $this->applyGroups($user, $decision));
        }

        $authError = UserHelper::getAuthStatus($user);

        if ($authError !== null && $authError !== '') {
            return SignInResult::failed(
                SignInResult::AUTH_REFUSED,
                sprintf(
                    'Craft refused to authenticate the account after provisioning (%s). This is '
                    . 'the account\'s own state - suspended, pending, locked, archived or owed a '
                    . 'password reset - not a permissions problem.',
                    $authError
                ),
                $notes
            );
        }

        $missing = $this->missingCpPermission($user);

        if ($missing !== null) {
            return SignInResult::failed(
                SignInResult::NO_CP_ACCESS,
                sprintf(
                    'The account was provisioned but has no "%s" permission, so signing it in '
                    . 'would drop somebody on a page they cannot use. A just-created account '
                    . 'gets this when the group mapping put it in no group that grants control '
                    . 'panel access.',
                    $missing
                ),
                $notes
            );
        }

        if (!$this->session->login($user, $this->sessionDuration)) {
            return SignInResult::failed(
                SignInResult::SESSION_NOT_STARTED,
                'Craft accepted the account but would not start a session for it.',
                $notes
            );
        }

        // Craft's own stored return URL, used only as the fallback: the login state's return URL
        // wins, because it was captured and guarded (RedirectGuard) when the login started.
        $returnUrl = $this->session->getReturnUrl();
        $this->session->removeReturnUrl();

        return SignInResult::signedIn((int)$user->id, $returnUrl, $notes);
    }

    /**
     * The control-panel permission this account is missing, or null when it may come in.
     *
     * Asked directly rather than through getAuthStatus(), for the reason in the class docblock:
     * that helper only asks on a control-panel request, and the canonical callback URL is not one.
     *
     * The rule is Core\Access\ControlPanelAccess, not an `if` in this file, for the reason the
     * whole class exists: a decision that can lock somebody out of their control panel belongs
     * where `php bin/test.php` can reach it. This method is the half that cannot move - reading
     * two permissions off a Craft element.
     */
    private function missingCpPermission(User $user): ?string
    {
        return ControlPanelAccess::missingPermission(
            $user->can(ControlPanelAccess::ACCESS_CP),
            $user->can(ControlPanelAccess::ACCESS_CP_WHEN_SYSTEM_IS_OFF),
            $this->systemIsLive
        );
    }

    private function resolveUser(ProvisioningDecision $decision): ?User
    {
        // On the ACTION, not on "is there a user id". The two agree today, and a decision that
        // says Create while carrying an id would, under the other test, silently overwrite
        // somebody else's account instead of creating one.
        if ($decision->action === ProvisioningAction::Create) {
            $user = ($this->newUser)();
            // Only legal on a new element; see the class docblock. No activation e-mail is sent
            // and none is wanted: the identity provider has already vouched for this person.
            $user->active = true;

            // MEASURED IN A LIVE CRAFT 5 WITH OKTA, 2026-09-15. On Craft's DEFAULT configuration
            // (`useEmailAsUsername = false`) the very first SSO login failed with "username:
            // Username cannot be blank": an Okta profile mapping out of the box carries an
            // e-mail address and no username, applyAttributes() writes only the fields the
            // mapping actually has, so nothing ever set `username` and Craft refused to save the
            // account. Craft accepts an address as a username, so the address is the fallback -
            // the same rule the core already had in MappedAttributes::usernameOrEmail(), which
            // until now nothing on this side called.
            //
            // ORDER MATTERS AND IT IS THIS WAY ROUND ON PURPOSE. usernameOrEmail() already
            // prefers an explicitly mapped username, and applyAttributes() runs after this
            // method and writes that same mapped value again - so a username from the assertion
            // can never be overwritten by the e-mail address.
            //
            // An absent or blank value is left alone rather than written as "": inventing a name
            // out of nothing would create an account nobody can identify, whereas letting Craft
            // refuse the save produces the USER_NOT_SAVED row an administrator can act on.
            //
            // The opposite direction - applyAttributes() overwriting this fallback with a BLANK
            // mapped username - is unreachable from any settings, and is guarded here only
            // because "unreachable" should be stated rather than assumed: AttributeMapper's
            // collapse() (97-109) trims every value and drops the blanks, so an empty
            // `<AttributeValue/>` becomes "not sent", and SettingsTranslator::nullableStr()
            // (546-551) turns an empty `defaultValue` cell into null before a rule is built.
            // A blank string therefore never reaches MappedAttributes in the first place.
            $username = $decision->attributes()->usernameOrEmail();

            if ($username !== null && Ascii::trim($username) !== '') {
                $user->username = $username;
            }

            return $user;
        }

        return $this->users->getUserById((int)$decision->userId);
    }

    /**
     * @return list<string> notes about anything that could not be applied.
     */
    private function applyAttributes(User $user, MappedAttributes $attributes): array
    {
        $notes = [];

        foreach ($attributes->toArray() as $target => $value) {
            if (UserField::isCustom($target)) {
                $handle = substr($target, strlen(UserField::CUSTOM_PREFIX));

                if ($user->getFieldLayout()?->getFieldByHandle($handle) === null) {
                    $notes[] = sprintf(
                        'Attribute mapping writes to custom field "%s", which is not in the '
                        . 'user field layout on this site. The value was not stored.',
                        $handle
                    );

                    continue;
                }

                $user->setFieldValue($handle, $value);

                continue;
            }

            // The allow list in Core\Attribute\UserField is what makes this assignment safe:
            // only the five identity fields can reach it, and none of them grants access.
            $user->$target = $value;
        }

        return $notes;
    }

    private function applyAdmin(User $user, ProvisioningDecision $decision): void
    {
        $groups = $decision->groups();

        if ($groups->grantsAdmin()) {
            $user->admin = true;

            return;
        }

        if ($groups->revokesAdmin()) {
            $user->admin = false;
        }
    }

    /**
     * @return list<string>
     */
    private function applyGroups(User $user, ProvisioningDecision $decision): array
    {
        $assignment = $decision->groups();

        // BELOW CRAFT PRO, TOUCHING NOTHING IS THE ONLY SAFE MOVE, and doing the obvious thing
        // is actively destructive. Such an edition answers `getGroups()` with `[]` whatever the
        // account is really in, so the sync below would conclude "belongs to nothing", find no
        // handle it could resolve, and hand `assignUserToGroups()` an EMPTY set - a call that
        // replaces the whole set. That would strip the built-in group Craft itself had just put
        // the account into while saving it, on every single login. And there is nothing to gain
        // in exchange: the edition cannot even hold the groups a mapping names, because
        // `UserGroups::saveGroup()` refuses to create them.
        if (!$this->craftKeepsUserGroups) {
            if ($assignment->groups() === []) {
                return [];
            }

            return [sprintf(
                'Group mapping asked for user group(s) %s, but this Craft edition does not keep '
                . 'user group memberships - that needs Craft Pro. Group membership was left '
                . 'untouched. Sign-in, attribute mapping, the refuse-unless-mapped rule and the '
                . 'admin rule are unaffected.',
                implode(', ', array_map(
                    static fn (string $handle): string => '"' . $handle . '"',
                    $assignment->groups()
                ))
            )];
        }

        $existing = array_values(array_map(
            static fn ($group): string => (string)$group->handle,
            $user->getGroups()
        ));

        $wanted = GroupSync::resolve($assignment->groups(), $existing, $assignment->syncMode());

        if (!GroupSync::changes($existing, $wanted)) {
            return [];
        }

        $notes = [];
        $ids = [];

        foreach ($wanted as $handle) {
            $group = $this->groups->getGroupByHandle($handle);

            if ($group === null) {
                $notes[] = sprintf(
                    'Group mapping asked for user group "%s", which does not exist on this site. '
                    . 'The account was not put in it.',
                    $handle
                );

                continue;
            }

            $ids[] = (int)$group->id;
        }

        try {
            $this->users->assignUserToGroups((int)$user->id, $ids);
        } catch (Throwable $error) {
            $notes[] = 'Group membership could not be written: ' . $error->getMessage();
        }

        return $notes;
    }

    private static function errorsOf(User $user): string
    {
        $messages = [];

        foreach ($user->getErrors() as $attribute => $errors) {
            $messages[] = $attribute . ': ' . implode(' ', (array)$errors);
        }

        return $messages === [] ? 'no validation errors were reported' : implode('; ', $messages);
    }
}
