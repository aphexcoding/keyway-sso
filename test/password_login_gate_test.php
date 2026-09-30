<?php

declare(strict_types=1);

use Keyway\Sso\Core\Access\AdminFallback;
use Keyway\Sso\Core\Access\AdminFallbackSettings;
use Keyway\Sso\Core\Access\PasswordLoginDecision;
use Keyway\Sso\Core\Access\PasswordLoginGate;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;

/**
 * The enforcement half of the password fallback: what an authentication hook is allowed to do.
 *
 * admin_fallback_test.php already covers WHO may use a password. These cases cover the three
 * things that decide whether that answer is ever acted on - control-panel narrowing, passwords
 * versus passkeys, and what happens when working the answer out throws - because those were the
 * parts living nowhere, which is why the settings screen's five switches did nothing.
 */
$admin = new ExistingUser('1', 'admin@example.com', 'admin', true, AccountStatus::Active, false);
$editor = new ExistingUser('2', 'editor@example.com', 'editor', false, AccountStatus::Active, false);

/** SSO-only with the admin hatch open: refuses the editor, admits the admin. */
$ssoOnly = static fn (): AdminFallback => new AdminFallback(
    new AdminFallbackSettings(true),
    new FixedClock()
);

$never = static function (): ?ExistingUser {
    throw new LogicException('the account lookup must not run for this case');
};

return [
    'a refused password login on the control panel is denied' => static function () use ($ssoOnly, $editor): void {
        $decision = PasswordLoginGate::decide(
            true,
            true,
            'editor',
            $ssoOnly,
            static fn (): ?ExistingUser => $editor
        );

        Assert::false($decision->allowed);
        Assert::same(PasswordLoginDecision::SSO_REQUIRED, $decision->reasonCode);
    },

    'the admin hatch still opens through the gate' => static function () use ($ssoOnly, $admin): void {
        $decision = PasswordLoginGate::decide(
            true,
            true,
            'admin',
            $ssoOnly,
            static fn (): ?ExistingUser => $admin
        );

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginDecision::ADMIN_FALLBACK, $decision->reasonCode);
    },

    // RULE 1. The event Craft gives us is global; the setting says "on the control panel". A
    // front-end member logging into the client's shop must never meet this gate.
    'a front-end login is none of the plugin\'s business' => static function () use ($ssoOnly, $never): void {
        $decision = PasswordLoginGate::decide(false, true, 'editor', $ssoOnly, $never);

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginGate::NOT_CONTROL_PANEL, $decision->reasonCode);
    },

    // The narrowing has to come first, before anything is even consulted: $never throws if the
    // account lookup runs, so this also pins that a front-end login costs no database query.
    'the front-end short-circuit decides before consulting anything' => static function () use ($never, $editor): void {
        $exploding = static function (): AdminFallback {
            throw new LogicException('the settings must not be read for a front-end login');
        };

        $decision = PasswordLoginGate::decide(false, true, 'editor', $exploding, $never);

        Assert::same(PasswordLoginGate::NOT_CONTROL_PANEL, $decision->reasonCode);
    },

    // RULE 2. authenticateWithPasskey() fires the same event with $password === null. A passkey
    // holder shut out by a switch labelled "password fallback" is a lockout in disguise.
    'a passkey is not a password login and passes through' => static function () use ($ssoOnly, $never): void {
        $decision = PasswordLoginGate::decide(true, false, '', $ssoOnly, $never);

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginGate::NOT_A_PASSWORD, $decision->reasonCode);
    },

    // RULE 3, and the case the whole class exists for. Anything that throws means "let them in".
    'a failing settings read lets the password through' => static function () use ($editor): void {
        $broken = static function (): AdminFallback {
            throw new RuntimeException('project config is unreadable');
        };

        $decision = PasswordLoginGate::decide(
            true,
            true,
            'editor',
            $broken,
            static fn (): ?ExistingUser => $editor
        );

        Assert::true($decision->allowed, 'a broken gate must never refuse a password');
        Assert::same(PasswordLoginGate::GATE_UNAVAILABLE, $decision->reasonCode);
    },

    'a failing account lookup lets the password through' => static function () use ($ssoOnly): void {
        $decision = PasswordLoginGate::decide(
            true,
            true,
            'editor',
            $ssoOnly,
            static function (): ?ExistingUser {
                throw new RuntimeException('the database is down');
            }
        );

        Assert::true($decision->allowed, 'a failing lookup must never refuse a password');
        Assert::same(PasswordLoginGate::GATE_UNAVAILABLE, $decision->reasonCode);
    },

    // Not an Exception but an Error: a TypeError or a call to a missing method is exactly the
    // kind of bug of ours that must not become the client's lockout, so the catch is \Throwable.
    'even a PHP Error lets the password through' => static function () use ($ssoOnly): void {
        $decision = PasswordLoginGate::decide(
            true,
            true,
            'editor',
            $ssoOnly,
            static function (): ?ExistingUser {
                throw new Error('call to a member function on null');
            }
        );

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginGate::GATE_UNAVAILABLE, $decision->reasonCode);
    },

    // The emergency list may name somebody this installation cannot resolve to an account (a
    // typo, a deleted user, a lookup that fails). The typed identifier is checked in its own
    // right, which is why the gate forwards it rather than relying on the resolved user alone.
    'an emergency account named only in the form is still let in' => static function (): void {
        $fallback = static fn (): AdminFallback => new AdminFallback(
            new AdminFallbackSettings(true, false, ['rescue@example.com']),
            new FixedClock()
        );

        $decision = PasswordLoginGate::decide(
            true,
            true,
            'rescue@example.com',
            $fallback,
            static fn (): ?ExistingUser => null
        );

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginDecision::EMERGENCY_ACCOUNT, $decision->reasonCode);
    },

    'an unknown account under SSO-only is refused' => static function () use ($ssoOnly): void {
        $decision = PasswordLoginGate::decide(
            true,
            true,
            'nobody@example.com',
            $ssoOnly,
            static fn (): ?ExistingUser => null
        );

        Assert::false($decision->allowed);
        Assert::same(PasswordLoginDecision::SSO_REQUIRED, $decision->reasonCode);
    },

    // With the feature off the gate has to be invisible, including for accounts it would
    // otherwise refuse - this is the state every existing installation is in today.
    'with SSO-only off the gate refuses nobody' => static function () use ($editor): void {
        $decision = PasswordLoginGate::decide(
            true,
            true,
            'editor',
            static fn (): AdminFallback => new AdminFallback(new AdminFallbackSettings(), new FixedClock()),
            static fn (): ?ExistingUser => $editor
        );

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginDecision::PASSWORD_LOGIN_ENABLED, $decision->reasonCode);
    },

    // Without a replacement Craft tells an administrator their password was wrong when it was
    // right - the most misleading thing this feature could say.
    'a refusal gets a message that explains itself' => static function (): void {
        $message = PasswordLoginGate::failureMessage(PasswordLoginGate::AUTH_ERROR, false);

        Assert::notNull($message);
        Assert::contains('single sign-on', (string)$message);
    },

    // A distinct message is only ever reached for an account that EXISTS, so it doubles as an
    // account-existence oracle. Where the administrator asked Craft to prevent that, clarity loses.
    'the explanation is withheld when user enumeration is prevented' => static function (): void {
        Assert::null(PasswordLoginGate::failureMessage(PasswordLoginGate::AUTH_ERROR, true));
    },

    'other login failures keep Craft\'s own message' => static function (): void {
        Assert::null(PasswordLoginGate::failureMessage(null, false));
        Assert::null(PasswordLoginGate::failureMessage('invalidCredentials', false));
        Assert::null(PasswordLoginGate::failureMessage('accountLocked', false));
    },

    // THE ENUMERATION ORACLE, CLOSED ON BOTH SIDES. Craft does not keep $authError to itself:
    // _handleLoginFailure() passes it to asFailure() as data:['errorCode' => ...], and
    // web\Controller::asFailure() returns that as JSON for any request accepting JSON - which the
    // control panel login always is, because it posts through Craft.sendActionRequest. Silencing
    // only the message therefore left `{"errorCode":"keywaySsoRequired"}` readable for an account
    // that exists, versus "invalid_credentials" for one that does not.
    'the auth error code is silenced too when enumeration is prevented' => static function (): void {
        Assert::same(
            PasswordLoginGate::GENERIC_AUTH_ERROR,
            PasswordLoginGate::authError(true),
            'under the flag the refusal is indistinguishable from a bad password'
        );

        Assert::null(
            PasswordLoginGate::failureMessage(PasswordLoginGate::authError(true), true),
            'and the message stays generic, so neither field gives the account away'
        );
    },

    'without the flag the refusal identifies itself' => static function (): void {
        Assert::same(PasswordLoginGate::AUTH_ERROR, PasswordLoginGate::authError(false));
        Assert::notSame(PasswordLoginGate::GENERIC_AUTH_ERROR, PasswordLoginGate::authError(false));
        Assert::notNull(PasswordLoginGate::failureMessage(PasswordLoginGate::authError(false), false));
    },

    // Core\ carries no Composer dependency, so the generic code is a literal. This ties it back
    // to Craft whenever Craft is present, so an upstream rename fails here and not in production.
    'the generic code is Craft\'s own' => static function (): void {
        Assert::same('invalid_credentials', PasswordLoginGate::GENERIC_AUTH_ERROR);

        if (!class_exists(\craft\elements\User::class)) {
            return;
        }

        Assert::same(
            \craft\elements\User::AUTH_INVALID_CREDENTIALS,
            PasswordLoginGate::GENERIC_AUTH_ERROR,
            'the borrowed code still matches Craft\'s'
        );
    },

    // The code written onto Craft's $authError. Pinned because the Craft layer matches on it
    // again when rewriting the failure message, and a silent rename would leave the login screen
    // saying "Invalid username or password" to somebody whose password was perfectly fine.
    'the auth error code is not one of Craft\'s own' => static function (): void {
        Assert::same('keywaySsoRequired', PasswordLoginGate::AUTH_ERROR);

        if (!class_exists(\craft\elements\User::class)) {
            return;
        }

        $craftCodes = [];
        foreach ((new ReflectionClass(\craft\elements\User::class))->getConstants() as $name => $value) {
            if (str_starts_with($name, 'AUTH_')) {
                $craftCodes[] = $value;
            }
        }

        Assert::false(
            in_array(PasswordLoginGate::AUTH_ERROR, $craftCodes, true),
            'reusing a Craft AUTH_* code would borrow its consequences, including lockout accounting'
        );
    },
];
