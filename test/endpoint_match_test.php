<?php

declare(strict_types=1);

use Keyway\Sso\Config\EndpointMatch;
use Keyway\Sso\Test\Support\Assert;

/**
 * The check behind the two fields an SSO configuration fails on most often: the ACS URL and the
 * OIDC redirect URI.
 *
 * No Craft here, which is the point - the rule is a comparison of two strings, and a rule that
 * can only be exercised by booting a CMS is a rule nobody re-tests. The address the plugin
 * actually answers on is produced by `Plugin::settingsHtml()`; everything below is what happens
 * once that string meets whatever an administrator pasted into the field.
 *
 * The cases are the real ones. A fresh install has the field empty. A careful administrator
 * copies the address and gets `Exact`. A less careful one copies it out of a browser address bar
 * and gains a trailing slash, or capitalises the host. Somebody reading the plugin's own control
 * panel routes types the alias with `cpTrigger` in it - which works until the day `cpTrigger`
 * changes. And somebody configuring a staging site pastes the production host, which is the one
 * case where nothing the identity provider sends can ever arrive.
 */
$canonical = 'https://site.example.com/actions/keyway-sso/sso/acs';

/** @param string $configured */
$verdict = static fn(string $configured): EndpointMatch => EndpointMatch::compare($canonical, $configured);

/**
 * What Plugin::installBaseUrls() hands over on a multi-site install: the control panel's base
 * URL and one per site, exactly as Craft stores them - trailing slashes and all.
 *
 * @var list<string> $sites
 */
$sites = [
    'https://site.example.com/',
    'https://second.example.com/',
    'https://third.example.com/',
];

return [
    // The starting state of every install. Colouring this red is how a working product looks
    // broken on the screen where somebody is still typing.
    'an empty field is the starting state, not a fault' => static function () use ($verdict): void {
        Assert::same(EndpointMatch::NotConfigured, $verdict(''));
        Assert::same(EndpointMatch::NotConfigured, $verdict("  \t\n "));
        Assert::false(EndpointMatch::NotConfigured->isWarning(), 'not a warning');
        Assert::contains('Copy the address above', EndpointMatch::NotConfigured->message());
    },

    'the address this site answers on matches itself' => static function () use ($canonical, $verdict): void {
        Assert::same(EndpointMatch::Exact, $verdict($canonical));
        Assert::false(EndpointMatch::Exact->isWarning());
        Assert::same('', EndpointMatch::Exact->message(), 'a correct field says nothing');
    },

    // Both connection configs trim before they store, so a stray space is not a difference
    // anywhere else in this plugin and must not be reported as one here.
    'surrounding whitespace is not a mismatch' => static function () use ($canonical, $verdict): void {
        Assert::same(EndpointMatch::Exact, $verdict("  $canonical\n"));
    },

    // Routing is unaffected; the remark exists because SamlResponseReader compares Destination
    // and Recipient with `!==`, so whatever is written here has to be written the same way at
    // the identity provider.
    'a trailing slash, letter case or a default port is the same endpoint' => static function () use ($verdict): void {
        foreach ([
            'https://site.example.com/actions/keyway-sso/sso/acs/',
            'HTTPS://site.example.com/actions/keyway-sso/sso/acs',
            'https://SITE.Example.COM/actions/keyway-sso/sso/acs',
            'https://site.example.com:443/actions/keyway-sso/sso/acs',
        ] as $configured) {
            Assert::same(EndpointMatch::Equivalent, EndpointMatch::compare(
                'https://site.example.com/actions/keyway-sso/sso/acs',
                $configured
            ), $configured);
        }

        Assert::false(EndpointMatch::Equivalent->isWarning(), 'a remark, not an alarm');
        Assert::contains('character for character', EndpointMatch::Equivalent->message());
    },

    'the default http port is normalised too' => static function (): void {
        Assert::same(EndpointMatch::Equivalent, EndpointMatch::compare(
            'http://localhost/actions/keyway-sso/sso/acs',
            'http://localhost:80/actions/keyway-sso/sso/acs'
        ));
    },

    // The control panel alias really does work - today. It contains cpTrigger, and the day the
    // site owner renames that, the identity provider is left posting to a 404.
    'the control panel alias is flagged as fragile, not as broken' => static function () use ($verdict): void {
        Assert::same(EndpointMatch::DifferentPath, $verdict('https://site.example.com/admin/sso/acs'));
        Assert::false(EndpointMatch::DifferentPath->isWarning(), 'it works today; saying "broken" would be a lie');

        $message = EndpointMatch::DifferentPath->message();
        Assert::contains('cpTrigger', $message, 'names the thing that will break it');
        Assert::contains('will not reach this plugin', $message, 'and the other possibility');
    },

    // A path is case-sensitive and Craft matches the action trigger with `===`, so this one is
    // simply wrong - but it is wrong on this site, and the wording covers both readings.
    'the path is compared case-sensitively' => static function () use ($verdict): void {
        Assert::same(EndpointMatch::DifferentPath, $verdict('https://site.example.com/Actions/keyway-sso/sso/acs'));
    },

    'a different query or fragment is a different address' => static function () use ($verdict): void {
        Assert::same(EndpointMatch::DifferentPath, $verdict('https://site.example.com/actions/keyway-sso/sso/acs?site=de'));
        Assert::same(EndpointMatch::DifferentPath, $verdict('https://site.example.com/actions/keyway-sso/sso/acs#done'));
    },

    // An install with `pathParam` and no path info addresses actions through index.php. That is
    // then the canonical form, and the pretty version of it does NOT route there.
    'an index.php install compares against its own shape' => static function (): void {
        $indexPhp = 'https://site.example.com/index.php?p=actions/keyway-sso/sso/callback';

        Assert::same(EndpointMatch::Exact, EndpointMatch::compare($indexPhp, $indexPhp));
        Assert::same(EndpointMatch::DifferentPath, EndpointMatch::compare(
            $indexPhp,
            'https://site.example.com/actions/keyway-sso/sso/callback'
        ));
    },

    // The one group that is certain: a host this installation does not serve cannot receive
    // anything on its behalf. This is the only reason it shouts.
    'a host this installation does not serve can never reach it' => static function () use ($verdict, $sites): void {
        foreach ([
            'https://other.example.com/actions/keyway-sso/sso/acs',
            'https://site.example.com.evil.test/actions/keyway-sso/sso/acs',
            'https://site-example.com/actions/keyway-sso/sso/acs',
        ] as $configured) {
            Assert::same(EndpointMatch::DifferentOrigin, $verdict($configured), $configured);

            // And it stays loud when the install's own addresses ARE known - the list is a
            // reason to be quieter about siblings, never about strangers.
            Assert::same(EndpointMatch::DifferentOrigin, EndpointMatch::compare(
                'https://site.example.com/actions/keyway-sso/sso/acs',
                $configured,
                $sites
            ), $configured . ' with the site list');
        }

        Assert::true(EndpointMatch::DifferentOrigin->isWarning(), 'this one earns the red');
        Assert::contains('will not reach this plugin', EndpointMatch::DifferentOrigin->message());
    },

    // THE FALSE ALARM THIS EXISTS TO STOP. Plugin settings are global - one ACS URL for the
    // whole installation - but the address on the screen can only be built from the site the
    // administrator has currently selected. On a multi-site install with a domain per site, a
    // CORRECT ACS URL therefore often names a sibling. Calling that "will not reach this
    // plugin" gets a working login dismantled, at the identity provider too.
    'a sibling site of the same installation is a remark, not an alarm' => static function () use ($sites): void {
        $verdict = EndpointMatch::compare(
            'https://site.example.com/actions/keyway-sso/sso/acs',
            'https://second.example.com/actions/keyway-sso/sso/acs',
            $sites
        );

        Assert::same(EndpointMatch::OtherOriginOfThisInstall, $verdict);
        Assert::false($verdict->isWarning(), 'a correct multi-site configuration is not painted red');
        Assert::contains('shared by every site', $verdict->message());
    },

    // The second hole in "another origin can never arrive here": a control panel reached over
    // http still needs an https redirect URI, because OidcConnectionConfig refuses anything
    // else. The only acceptable value must not be the one wearing the warning.
    'the same host over another scheme or port is a remark' => static function (): void {
        foreach ([
            ['http://site.example.com/actions/keyway-sso/sso/callback', 'https://site.example.com/actions/keyway-sso/sso/callback'],
            ['https://site.example.com/actions/keyway-sso/sso/acs', 'http://site.example.com/actions/keyway-sso/sso/acs'],
            ['https://site.example.com/actions/keyway-sso/sso/acs', 'https://site.example.com:8443/actions/keyway-sso/sso/acs'],
        ] as [$canonical, $configured]) {
            $verdict = EndpointMatch::compare($canonical, $configured);

            Assert::same(EndpointMatch::OtherOriginOfThisInstall, $verdict, $configured);
            Assert::false($verdict->isWarning(), $configured . ' is not an alarm');
        }
    },

    // The canonical host is ours whether or not anybody passed a list, so the degradation above
    // cannot depend on a caller remembering to supply one.
    'the canonical host counts as ours with no list at all' => static function () use ($verdict): void {
        Assert::same(EndpointMatch::OtherOriginOfThisInstall, $verdict('http://site.example.com/actions/keyway-sso/sso/acs'));
    },

    // Credentials in the authority are kept in the comparison rather than dropped, and they are
    // the one thing that never degrades: `https://user:pass@host/...` is not an address to hand
    // an identity provider, whoever owns the host.
    'embedded credentials are not the same address, even on our own host' => static function () use ($verdict, $sites): void {
        Assert::same(EndpointMatch::DifferentOrigin, $verdict('https://user:pass@site.example.com/actions/keyway-sso/sso/acs'));
        Assert::same(EndpointMatch::DifferentOrigin, EndpointMatch::compare(
            'https://site.example.com/actions/keyway-sso/sso/acs',
            'https://user:pass@second.example.com/actions/keyway-sso/sso/acs',
            $sites
        ));
    },

    // A site's base URL can be a relative path, an unresolved alias or simply missing; Craft
    // hands those over as they are, and one of them must not take the check down with it.
    'junk in the list of the installation\'s own addresses is ignored' => static function (): void {
        $verdict = EndpointMatch::compare(
            'https://site.example.com/actions/keyway-sso/sso/acs',
            'https://second.example.com/actions/keyway-sso/sso/acs',
            ['/', '', '@web', 'not a url', 'https://second.example.com/']
        );

        Assert::same(EndpointMatch::OtherOriginOfThisInstall, $verdict);
    },

    // The field validators refuse these before they can be saved; this only says why the check
    // above them has nothing to compare.
    'anything that is not an absolute http(s) URL cannot be compared' => static function () use ($verdict): void {
        foreach ([
            'acs',
            '/actions/keyway-sso/sso/acs',
            '//site.example.com/actions/keyway-sso/sso/acs',
            'mailto:admin@site.example.com',
            'ftp://site.example.com/acs',
            'https:///actions/keyway-sso/sso/acs',
        ] as $configured) {
            Assert::same(EndpointMatch::Unreadable, $verdict($configured), $configured);
        }

        Assert::true(EndpointMatch::Unreadable->isWarning());
        Assert::contains('absolute http or https URL', EndpointMatch::Unreadable->message());
    },

    // The screen renders `message()` straight into a field's tip or warning slot, so an empty
    // one means "no line at all" - and every case except Exact owes the administrator a sentence.
    'every verdict except the correct one has something to say' => static function (): void {
        foreach (EndpointMatch::cases() as $case) {
            if ($case === EndpointMatch::Exact) {
                continue;
            }

            Assert::true($case->message() !== '', $case->value . ' has a message');
        }

        Assert::sameList(
            ['different_origin', 'unreadable'],
            array_values(array_map(
                static fn(EndpointMatch $case): string => $case->value,
                array_filter(EndpointMatch::cases(), static fn(EndpointMatch $case): bool => $case->isWarning())
            )),
            'exactly two cases are loud, and they are the two we can be certain about - a '
            . 'sibling site of this install is not one of them'
        );
    },
];
