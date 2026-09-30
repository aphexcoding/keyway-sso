<?php

declare(strict_types=1);

use Keyway\Sso\Core\Access\AdminFallback;
use Keyway\Sso\Core\Access\AdminFallbackSettings;
use Keyway\Sso\Core\Access\PasswordLoginDecision;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\FixedClock;

$admin = new ExistingUser('1', 'admin@example.com', 'admin', true, AccountStatus::Active, false);
$editor = new ExistingUser('2', 'editor@example.com', 'editor', false, AccountStatus::Active, false);

return [
    'password login is untouched when SSO-only is off' => static function () use ($editor): void {
        $fallback = new AdminFallback(new AdminFallbackSettings(), new FixedClock());

        $decision = $fallback->decidePasswordLogin($editor, 'editor');

        Assert::true($decision->allowed);
        Assert::same(PasswordLoginDecision::PASSWORD_LOGIN_ENABLED, $decision->reasonCode);
        Assert::true($fallback->shouldOfferPasswordForm());
    },

    'SSO-only stops a regular user but never the admin' => static function () use ($admin, $editor): void {
        $fallback = new AdminFallback(new AdminFallbackSettings(true), new FixedClock());

        Assert::true($fallback->isPasswordLoginAllowed($admin, 'admin'));
        Assert::same(
            PasswordLoginDecision::ADMIN_FALLBACK,
            $fallback->decidePasswordLogin($admin, 'admin')->reasonCode
        );

        $denied = $fallback->decidePasswordLogin($editor, 'editor');
        Assert::false($denied->allowed);
        Assert::same(PasswordLoginDecision::SSO_REQUIRED, $denied->reasonCode);
    },

    'an unknown identifier under SSO-only is refused' => static function (): void {
        $fallback = new AdminFallback(new AdminFallbackSettings(true), new FixedClock());

        Assert::false($fallback->isPasswordLoginAllowed(null, 'nobody@example.com'));
    },

    'the lockout guard re-enables admin passwords for a suicidal config' => static function (): void {
        $settings = new AdminFallbackSettings(true, false);

        Assert::true($settings->lockoutGuardApplied());
        Assert::true($settings->allowPasswordForAdmins);
        Assert::true(AdminFallbackSettings::wouldLockOut(true, false, []));
    },

    'the guard fires for blank-only emergency lists too' => static function (): void {
        $settings = new AdminFallbackSettings(true, false, ['  ', '']);

        Assert::sameList([], $settings->emergencyAccounts());
        Assert::true($settings->lockoutGuardApplied());
        Assert::true($settings->allowPasswordForAdmins);
    },

    'a configured admin lockout still leaves the admin a way in' => static function () use ($admin): void {
        $fallback = new AdminFallback(new AdminFallbackSettings(true, false), new FixedClock());

        $decision = $fallback->decidePasswordLogin($admin, 'admin');

        Assert::true($decision->allowed, 'the guard rewrites a configuration that would leave no way back in');
        Assert::same(PasswordLoginDecision::ADMIN_FALLBACK, $decision->reasonCode);
        Assert::true($fallback->shouldOfferPasswordForm());
    },

    'an emergency account is an accepted escape hatch and disables the guard' => static function () use ($editor): void {
        $settings = new AdminFallbackSettings(true, false, ['Rescue@Example.com']);
        $fallback = new AdminFallback($settings, new FixedClock());

        Assert::false($settings->lockoutGuardApplied());
        Assert::false($settings->allowPasswordForAdmins);
        Assert::sameList(['rescue@example.com'], $settings->emergencyAccounts());

        $allowed = $fallback->decidePasswordLogin(null, 'RESCUE@example.com');
        Assert::true($allowed->allowed);
        Assert::same(PasswordLoginDecision::EMERGENCY_ACCOUNT, $allowed->reasonCode);

        Assert::false($fallback->isPasswordLoginAllowed($editor, 'editor'));
        Assert::true($fallback->shouldOfferPasswordForm());
    },

    'an emergency account matches on the resolved user as well' => static function (): void {
        $settings = new AdminFallbackSettings(true, false, ['rescue']);
        $fallback = new AdminFallback($settings, new FixedClock());
        $user = new ExistingUser('9', 'someone@example.com', 'rescue', false, AccountStatus::Active, false);

        Assert::true($fallback->isPasswordLoginAllowed($user, 'someone@example.com'));
    },

    'break glass opens password login for everyone, until it expires' => static function () use ($editor): void {
        $clock = new FixedClock(1000);
        $fallback = new AdminFallback(
            new AdminFallbackSettings(true, true, [], true, 1600),
            $clock
        );

        Assert::true($fallback->isPasswordLoginAllowed($editor, 'editor'));
        Assert::same(
            PasswordLoginDecision::BREAK_GLASS,
            $fallback->decidePasswordLogin($editor, 'editor')->reasonCode
        );

        $clock->set(1600);
        Assert::false($fallback->isPasswordLoginAllowed($editor, 'editor'));
        Assert::same(
            PasswordLoginDecision::SSO_REQUIRED,
            $fallback->decidePasswordLogin($editor, 'editor')->reasonCode
        );
    },

    'break glass without an expiry is closed, not eternal' => static function () use ($editor): void {
        $clock = new FixedClock(1000);
        $settings = new AdminFallbackSettings(true, true, [], true, null);
        $fallback = new AdminFallback($settings, $clock);

        Assert::false($settings->breakGlassEnabled, 'an endless emergency switch is no switch');
        Assert::true($settings->breakGlassGuardApplied());
        Assert::null($settings->breakGlassExpiresAt);
        Assert::false($settings->isBreakGlassActive($clock->now()));
        Assert::null($settings->breakGlassRemaining($clock->now()));

        Assert::same(
            PasswordLoginDecision::SSO_REQUIRED,
            $fallback->decidePasswordLogin($editor, 'editor')->reasonCode
        );

        $clock->advance(10_000_000);
        Assert::false($fallback->isPasswordLoginAllowed($editor, 'editor'));
    },

    'saving break glass without an expiry is an error the admin sees' => static function (): void {
        $missing = Assert::throws(
            InvalidArgumentException::class,
            static fn () => AdminFallbackSettings::assertBreakGlassWindow(true, null, 1000)
        );

        // The assertion has to name the "no expiry at all" branch, not a substring both
        // branches share: `null <= 1000` is true in PHP, so deleting the null check leaves the
        // "in the past" message behind, and a test looking for the word "expiry" stays green
        // while the check it claims to cover is gone.
        Assert::contains('never closes', $missing->getMessage());

        $past = Assert::throws(
            InvalidArgumentException::class,
            static fn () => AdminFallbackSettings::assertBreakGlassWindow(true, 1000, 1000),
            'an expiry in the past'
        );
        Assert::contains('in the past', $past->getMessage());
        Assert::notContains('never closes', $past->getMessage(), 'the two branches must differ');
        Assert::notSame($missing->getMessage(), $past->getMessage());

        Assert::doesNotThrow(
            static fn () => AdminFallbackSettings::assertBreakGlassWindow(false, null, 1000)
        );
        Assert::doesNotThrow(
            static fn () => AdminFallbackSettings::assertBreakGlassWindow(
                true,
                1000 + AdminFallbackSettings::BREAK_GLASS_MAX_TTL,
                1000
            )
        );
    },

    'the break glass window has a ceiling' => static function () use ($editor): void {
        $now = 1_000_000;
        $tooFar = $now + AdminFallbackSettings::BREAK_GLASS_MAX_TTL + 1;

        $error = Assert::throws(
            InvalidArgumentException::class,
            static fn () => AdminFallbackSettings::assertBreakGlassWindow(true, $tooFar, $now)
        );
        Assert::contains('at most', $error->getMessage());

        // And a window that got past the settings screen anyway - hand-edited project config,
        // a millisecond timestamp - is not honoured at login time either.
        $settings = new AdminFallbackSettings(true, true, [], true, $tooFar);
        $fallback = new AdminFallback($settings, new FixedClock($now));

        Assert::false($settings->isBreakGlassActive($now));
        Assert::false($fallback->isPasswordLoginAllowed($editor, 'editor'));

        $atTheLimit = new AdminFallbackSettings(
            true,
            true,
            [],
            true,
            $now + AdminFallbackSettings::BREAK_GLASS_MAX_TTL
        );
        Assert::true($atTheLimit->isBreakGlassActive($now), 'the boundary itself is allowed');
        Assert::same(
            AdminFallbackSettings::BREAK_GLASS_MAX_TTL,
            $atTheLimit->breakGlassRemaining($now)
        );
    },

    'the break glass message matches what the code actually does' => static function () use ($editor): void {
        $now = 1_000_000;
        $fallback = new AdminFallback(
            new AdminFallbackSettings(true, true, [], true, $now + 1800),
            new FixedClock($now)
        );

        $decision = $fallback->decidePasswordLogin($editor, 'editor');

        Assert::true($decision->allowed);
        Assert::contains('temporarily', $decision->message);
        Assert::contains('30 minute', $decision->message, 'say how temporary, or do not say it');
    },

    'break glass does not count as the durable escape hatch' => static function (): void {
        $settings = new AdminFallbackSettings(true, false, [], true, 1600);

        Assert::true(
            $settings->lockoutGuardApplied(),
            'a time-limited switch cannot be the only way back into the panel'
        );
        Assert::true($settings->allowPasswordForAdmins);
    },

    'an expired break glass alone does not unlock anything' => static function () use ($editor): void {
        $clock = new FixedClock(2000);
        $fallback = new AdminFallback(
            new AdminFallbackSettings(true, true, [], true, 1600),
            $clock
        );

        Assert::false($fallback->isPasswordLoginAllowed($editor, 'editor'));
    },

    'a disabled break glass with a future expiry stays closed' => static function () use ($editor): void {
        $fallback = new AdminFallback(
            new AdminFallbackSettings(true, true, [], false, 9_999_999_999),
            new FixedClock(1000)
        );

        Assert::false($fallback->isPasswordLoginAllowed($editor, 'editor'));
    },

    'wouldLockOut answers false whenever any hatch remains' => static function (): void {
        Assert::false(AdminFallbackSettings::wouldLockOut(false, false, []));
        Assert::false(AdminFallbackSettings::wouldLockOut(true, true, []));
        Assert::false(AdminFallbackSettings::wouldLockOut(true, false, ['rescue@example.com']));
        Assert::true(AdminFallbackSettings::wouldLockOut(true, false, []));
    },

    // MEASURED, AND IT DECIDES A FEATURE THAT WAS NOT BUILT. shouldOfferPasswordForm() exists to
    // let the login screen hide the password fields, and the plan for this change was to wire it
    // into the `cp.login.alternative-login-methods` hook. It is not wired in, because it cannot
    // be reached: the only configuration that would return false - SSO-only, admins blocked, no
    // emergency account - is the exact configuration AdminFallbackSettings' lockout guard rewrites
    // in its constructor, by turning admin passwords back on.
    //
    // So every AdminFallbackSettings that can be built through the public constructor offers the
    // form, and code to hide it would be code that never runs - which is the defect this whole
    // change exists to remove, reintroduced one layer up. The settings screen says so in words
    // instead.
    //
    // This case is the pin: if the lockout guard is ever weakened, a hideable configuration
    // becomes reachable, this fails, and whoever did it is told that the login screen now has a
    // state nothing implements.
    'no configuration can hide the password form, because the lockout guard prevents one' =>
        static function (): void {
            $clock = new FixedClock();
            $now = $clock->now();
            $checked = 0;

            foreach ([true, false] as $ssoOnly) {
                foreach ([true, false] as $allowAdmins) {
                    foreach ([[], ['rescue@example.com']] as $emergency) {
                        foreach ([true, false] as $breakGlass) {
                            foreach ([null, $now + 3600, $now - 10, $now + 999999] as $expiry) {
                                $fallback = new AdminFallback(
                                    new AdminFallbackSettings(
                                        $ssoOnly,
                                        $allowAdmins,
                                        $emergency,
                                        $breakGlass,
                                        $expiry
                                    ),
                                    $clock
                                );

                                $checked++;
                                Assert::true(
                                    $fallback->shouldOfferPasswordForm(),
                                    'a reachable configuration hides the password form'
                                );
                            }
                        }
                    }
                }
            }

            Assert::same(64, $checked, 'the whole switch space was covered');
        },

    'a blank identifier never matches the emergency list' => static function (): void {
        $settings = new AdminFallbackSettings(true, true, ['rescue@example.com']);

        Assert::false($settings->isEmergencyAccount(''));
        Assert::false($settings->isEmergencyAccount('   '));
        Assert::true($settings->isEmergencyAccount(' Rescue@example.com '));
    },
];
