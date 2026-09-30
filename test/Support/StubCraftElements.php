<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\base\ElementInterface;
use craft\elements\User;
use craft\services\Elements;

/**
 * craft\services\Elements with the database taken out, and the two things Craft does to a user
 * element around a save kept in.
 *
 * Same trick as StubCraftUsers: the empty constructor skips the Yii component's init(), so the
 * real class and the real signature stay and only the connection goes away. That is what lets
 * the just-in-time creation path - the one `saveElement()` made unreachable for the whole suite
 * - be run here at all.
 *
 * WHY IT DOES NOT SIMPLY RETURN TRUE. A stub that accepted everything would have stayed green
 * through the bug this exists to catch: a live Craft 5 with Okta refused the first SSO login on
 * 2026-09-15 with "username: Username cannot be blank". So the two rules that decided that
 * outcome are copied, and they are quoted below from craftcms/cms 5.11.1 rather than assumed,
 * because a stub that lies about Craft is worse than no stub at all.
 *
 *  1. `User::beforeSave()` (elements/User.php:2570-2584) assigns `$this->username =
 *     $this->email` whenever `useEmailAsUsername` is on - UNCONDITIONALLY, at lines 2579-2581,
 *     with no `empty()` test. So on such an install the column is Craft's decision and a mapped
 *     username does not survive the save. (The `empty($this->username) && ...useEmailAsUsername`
 *     branch that looks like it says otherwise is at lines 859-861 and belongs to `init()`, not
 *     to the save: it runs while the element is being constructed, before anything has set
 *     `email`, so for a provisioning run it decides nothing.)
 *  2. On the DEFAULT configuration (`useEmailAsUsername` off) `defineRules()` adds
 *     `[['username'], 'required', 'when' => $treatAsActive]` (elements/User.php:995-998), and
 *     `$treatAsActive` (line 979) is true for a credentialed element - `getIsCredentialed()`
 *     (lines 1145-1148) is `$this->active || $this->pending`, and provisioning sets
 *     `active = true`. Hence the refusal, and hence the error this puts on the element.
 *
 * The order matters and is Craft's: `Elements::_saveElementInternal()` calls `beforeSave()` at
 * line 3918 and only validates at line 3971, which is why the assignment above happens here
 * before the blank check.
 *
 * NOTHING ELSE ABOUT SAVING IS IMITATED, and a test must not read more into a green line than
 * that: not the licence guard (`beforeSave()` lines 2572-2577 refuses a new user outright when
 * `Users::canCreateUsers()` says the edition is full), not uniqueness, not UsernameValidator,
 * not the e-mail rules, not the database. This reproduces two measured rules; the rest is the
 * acceptance test on a real install.
 *
 * `$saved` is the other half: the element is kept so a test can read what provisioning actually
 * wrote, rather than infer it from a return value. The id handed out on a successful save
 * mirrors Craft assigning one to a brand-new element.
 */
final class StubCraftElements extends Elements
{
    public const ASSIGNED_ID = 77;

    /** @var list<ElementInterface> Every element handed to saveElement(), in order. */
    public array $saved = [];

    /** Whether the install runs with `useEmailAsUsername`; see rule 1 in the class docblock. */
    public bool $useEmailAsUsername = false;

    public function __construct()
    {
        // Deliberately does not call parent::__construct(): no application, no database.
    }

    public function saveElement(
        ElementInterface $element,
        bool $runValidation = true,
        bool $propagate = true,
        ?bool $updateSearchIndex = null,
        bool $forceTouch = false,
        ?bool $crossSiteValidate = false,
        bool $saveContent = false,
    ): bool {
        $this->saved[] = $element;

        if ($element instanceof User) {
            if ($this->useEmailAsUsername) {
                // Rule 1: Craft owns the column on this install, mapped username or not.
                $element->username = $element->email;
            } elseif ($element->active || $element->pending) {
                // Rule 2, and the refusal measured in production.
                if (trim((string)($element->username ?? '')) === '') {
                    $element->addError('username', 'Username cannot be blank.');

                    return false;
                }
            }
        }

        if (!isset($element->id)) {
            $element->id = self::ASSIGNED_ID;
        }

        return true;
    }
}
