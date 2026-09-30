<?php

declare(strict_types=1);

use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Config\SettingsTranslator;
use Keyway\Sso\Protocol\Saml\IdpCertificate;
use Keyway\Sso\Protocol\Saml\SpMetadata;
use Keyway\Sso\Core\Attribute\AttributeTransform;
use Keyway\Sso\Core\Attribute\MultiValueStrategy;
use Keyway\Sso\Core\Group\GroupMatchType;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CertificateFixtures;
use Keyway\Sso\Test\Support\SamlFixtures;

/**
 * The translation layer between plugin settings and the typed objects the core consumes.
 *
 * No Craft anywhere in this file, and that is the point: everything with a rule in it lives in
 * SettingsTranslator, so the rules are testable on a host with no vendor directory, no database
 * and no CMS. The Craft classes on top (Plugin, Models\Settings) only declare shape and are
 * covered separately by craft_layer_test.php.
 *
 * The hostile cases here are the ones a real install produces: a hand-edited project config with
 * a misspelled enum, an editable table left with a blank row, a cleared attribute table, a
 * break-glass switch with no expiry.
 */
$now = 1_700_000_000;

/**
 * A REAL certificate, and it has to be one now.
 *
 * This used to be `str_repeat('MIIC', 80)` - a blob long enough to clear the "not a fingerprint"
 * floor in SamlConnectionConfig and nothing more. That is exactly the value problems() refuses
 * since the save-time check landed, so a fixture like it would have made every "nothing to
 * report" case below fail for a reason none of them is about. Weakening the check to keep the
 * fixture would have been the wrong direction: the blob is the defect, not the test.
 *
 * It is parsed, never signed with; the bytes and the reasoning live in CertificateFixtures.
 */
$cert = CertificateFixtures::body();

$saml = [
    'protocol' => 'saml',
    'samlIdpEntityId' => 'https://idp.example.com/realms/keyway',
    'samlIdpCertificate' => $cert,
    'samlIdpSsoUrl' => 'https://idp.example.com/realms/keyway/protocol/saml',
    'samlSpEntityId' => 'https://site.example.com',
    'samlAcsUrl' => 'https://site.example.com/keyway-sso/saml/acs',
];

$oidc = [
    'protocol' => 'oidc',
    'oidcIssuer' => 'https://idp.example.com/realms/keyway',
    'oidcClientId' => 'craft-cp',
    'oidcClientSecret' => 's3cret',
    'oidcRedirectUri' => 'https://site.example.com/keyway-sso/oidc/callback',
];

$cases = [
    // Single logout is configurable but off by default: the connection only reports canLogout()
    // once the IdP endpoint, our own endpoint and a signing key are all present, and a half
    // configured SLO must not advertise itself.
    // "Disabled" has to disable. sso/slo asks canLogout() and nothing else, so a connection that
    // still reports true after the administrator switched SAML off is a live session-ending
    // endpoint on an install that believes it has no SSO - while spMetadata() in the same state
    // correctly publishes nothing.
    'single logout dies with the protocol, not just with the fields' => static function () use ($saml): void {
        $configured = $saml;
        $configured['samlIdpSloUrl'] = 'https://idp.example.com/realms/keyway/protocol/saml/logout';
        $configured['samlSpSloUrl'] = 'https://site.example.com/actions/keyway-sso/sso/slo';
        $configured['samlSpPrivateKey'] = "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----";

        Assert::true(
            SettingsTranslator::samlConnection($configured)->canLogout(),
            'with SAML selected this is exactly the configuration that works'
        );

        foreach (['disabled', 'oidc'] as $protocol) {
            $off = $configured;
            $off['protocol'] = $protocol;

            $connection = SettingsTranslator::samlConnection($off);

            Assert::false(
                $connection->canLogout(),
                'protocol ' . $protocol . ': the logout endpoint must be dead'
            );
            Assert::null($connection->idpSloUrl, 'protocol ' . $protocol . ': nothing to send to either');
            Assert::null(
                SettingsTranslator::spMetadata($off),
                'protocol ' . $protocol . ': and metadata says the same thing'
            );
        }
    },

    // Behavioural, because the mutant that matters here is a RENAME: the key is not a declared
    // property (it is derived, never stored), so the drift guard in craft_layer_test cannot see
    // it, and a misspelling on either side turns single logout off in silence.
    'the derived SP logout address reaches the connection under the key both sides agree on' =>
        static function () use ($saml): void {
            $settings = $saml;
            $settings['samlSpSloUrl'] = 'https://site.example.com/actions/keyway-sso/sso/slo';

            Assert::same(
                'https://site.example.com/actions/keyway-sso/sso/slo',
                SettingsTranslator::samlConnection($settings)->spSloUrl
            );
        },

    // The element is a PROMISE. Published without the gate, it points every identity provider
    // that reads the document at an endpoint which refuses everything they send.
    'metadata advertises SingleLogoutService only when the connection can honour it' =>
        static function () use ($saml): void {
            $half = $saml;
            $half['samlSpSloUrl'] = 'https://site.example.com/actions/keyway-sso/sso/slo';

            $document = SettingsTranslator::spMetadata($half)?->toXml() ?? '';
            Assert::notContains('SingleLogoutService', $document, 'no IdP endpoint, no promise');

            $whole = $half;
            $whole['samlIdpSloUrl'] = 'https://idp.example.com/realms/keyway/protocol/saml/logout';
            $whole['samlSpPrivateKey'] = "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----";

            $published = SettingsTranslator::spMetadata($whole)?->toXml() ?? '';
            Assert::contains('md:SingleLogoutService', $published);
            Assert::contains(
                'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"',
                $published,
                'the only binding sso/slo can verify'
            );
            Assert::contains('https://site.example.com/actions/keyway-sso/sso/slo', $published);
        },

    'single logout stays off until every part of it is configured' => static function () use ($saml): void {
        $off = SettingsTranslator::samlConnection($saml);
        Assert::null($off->idpSloUrl, 'nothing configured, nothing claimed');
        Assert::false($off->canLogout());

        $halfway = $saml;
        $halfway['samlIdpSloUrl'] = 'https://idp.example.com/realms/keyway/protocol/saml/logout';
        $connection = SettingsTranslator::samlConnection($halfway);
        Assert::same('https://idp.example.com/realms/keyway/protocol/saml/logout', $connection->idpSloUrl);
        Assert::false($connection->canLogout(), 'without our own endpoint there is nowhere to be told about');

        $whole = $halfway;
        $whole['samlSpSloUrl'] = 'https://site.example.com/actions/keyway-sso/sso/slo';
        $whole['samlSpPrivateKey'] = "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----";
        $ready = SettingsTranslator::samlConnection($whole);
        Assert::same('https://site.example.com/actions/keyway-sso/sso/slo', $ready->spSloUrl);
        Assert::true($ready->canLogout());
    },

    'protocol defaults to disabled' => static function (): void {
        Assert::same(AuthProtocol::Disabled, SettingsTranslator::protocol([]));
        Assert::same(AuthProtocol::Saml, SettingsTranslator::protocol(['protocol' => 'saml']));
        Assert::same(AuthProtocol::Oidc, SettingsTranslator::protocol(['protocol' => ' OIDC ']));
    },

    // A hand-edited project config must not take the login screen down with it.
    'unknown protocol falls back to disabled rather than throwing' => static function (): void {
        Assert::same(AuthProtocol::Disabled, SettingsTranslator::protocol(['protocol' => 'ldap']));
        Assert::same(AuthProtocol::Disabled, SettingsTranslator::protocol(['protocol' => 42]));
        Assert::false(SettingsTranslator::protocol(['protocol' => 'ldap'])->isEnabled());
    },

    'unknown protocol is still reported on the settings screen' => static function () use ($now): void {
        $problems = SettingsTranslator::problems(['protocol' => 'ldap'], $now);
        $fields = array_column($problems, 0);

        Assert::true(in_array('protocol', $fields, true), 'protocol problem reported');
    },

    'empty attribute table means the shipped defaults, not an empty mapping' => static function (): void {
        $map = SettingsTranslator::attributeMap([]);

        Assert::false($map->isEmpty());
        Assert::sameList(
            ['email', 'firstName', 'lastName'],
            array_map(static fn($rule): string => $rule->target, $map->rules())
        );
    },

    'a table of blank rows is still empty' => static function (): void {
        $map = SettingsTranslator::attributeMap([
            'attributeRules' => [
                ['source' => '', 'target' => ''],
                ['source' => '  ', 'target' => '  '],
            ],
        ]);

        Assert::sameList(
            ['email', 'firstName', 'lastName'],
            array_map(static fn($rule): string => $rule->target, $map->rules())
        );
    },

    'attribute rows become AttributeRule objects' => static function (): void {
        $map = SettingsTranslator::attributeMap([
            'attributeRules' => [
                [
                    'source' => 'mail',
                    'target' => 'Email',
                    'strategy' => 'join',
                    'separator' => ', ',
                    'required' => '1',
                    'transform' => 'lowercase',
                ],
                ['source' => 'displayName', 'target' => 'fullName', 'defaultValue' => 'Unknown'],
            ],
        ]);

        $rules = $map->rules();
        Assert::same(2, count($rules));

        Assert::same('mail', $rules[0]->source);
        // Canonicalised: a rule written as "Email" must write the field the core reads.
        Assert::same('email', $rules[0]->target);
        Assert::same(MultiValueStrategy::Join, $rules[0]->strategy);
        Assert::same(', ', $rules[0]->separator);
        Assert::true($rules[0]->required);
        Assert::same(AttributeTransform::Lowercase, $rules[0]->transform);
        Assert::null($rules[0]->defaultValue);

        Assert::same('fullName', $rules[1]->target);
        Assert::same('Unknown', $rules[1]->defaultValue);
        Assert::false($rules[1]->required);
    },

    // AttributeRule refuses required + default; the settings screen must not be able to post it.
    'a required rule drops its default instead of failing to build' => static function (): void {
        $map = SettingsTranslator::attributeMap([
            'attributeRules' => [
                ['source' => 'mail', 'target' => 'email', 'required' => true, 'defaultValue' => 'x@y.z'],
            ],
        ]);

        Assert::true($map->rules()[0]->required);
        Assert::null($map->rules()[0]->defaultValue);
    },

    'mapping to an access-granting field is refused' => static function () use ($now): void {
        $settings = ['attributeRules' => [['source' => 'isBoss', 'target' => 'admin']]];

        Assert::throws(
            InvalidArgumentException::class,
            static fn() => SettingsTranslator::attributeMap($settings)
        );

        $problems = SettingsTranslator::problems($settings, $now);
        Assert::same('attributeRules', $problems[0][0]);
        Assert::contains('not allowed', $problems[0][1]);
    },

    'group rows become rules, admin rows stay separate' => static function (): void {
        $map = SettingsTranslator::groupMap([
            'groupRules' => [
                ['matchType' => 'prefix', 'pattern' => 'craft-', 'targetGroup' => 'editors'],
                ['matchType' => '', 'pattern' => '', 'targetGroup' => ''],
            ],
            'adminRules' => [
                ['matchType' => 'suffix', 'pattern' => '-admins'],
                ['matchType' => 'exact', 'pattern' => ''],
            ],
            'allowAdminEscalation' => true,
            'groupSyncMode' => 'replace',
            'defaultGroup' => 'everyone',
            'groupSourceAttributes' => "groups\nmemberOf",
        ]);

        Assert::same(1, count($map->rules()));
        Assert::same(GroupMatchType::Prefix, $map->rules()[0]->matchType);
        Assert::same('editors', $map->rules()[0]->targetGroup);

        Assert::same(1, count($map->adminRules()));
        Assert::same('-admins', $map->adminRules()[0]->pattern);

        Assert::same(GroupSyncMode::Replace, $map->syncMode());
        Assert::same('everyone', $map->defaultGroup());
        Assert::sameList(['groups', 'memberOf'], $map->sourceAttributes());
        Assert::true($map->allowsAdminEscalation());
    },

    'a cleared source attribute list falls back to `groups`' => static function (): void {
        $map = SettingsTranslator::groupMap(['groupSourceAttributes' => "\n  \n"]);

        Assert::sameList(['groups'], $map->sourceAttributes());
    },

    'a misspelled enum narrows rather than throws' => static function (): void {
        $map = SettingsTranslator::groupMap([
            'groupRules' => [['matchType' => 'regex', 'pattern' => 'anything', 'targetGroup' => 'editors']],
            'groupSyncMode' => 'obliterate',
        ]);

        Assert::same(GroupMatchType::Exact, $map->rules()[0]->matchType);
        Assert::same(GroupSyncMode::Append, $map->syncMode());
    },

    'provisioning switches survive the round trip' => static function (): void {
        $provisioning = SettingsTranslator::provisioning([
            'allowJit' => false,
            'updateOnLogin' => '0',
            'denyIfNoGroupMatch' => '1',
            'matchBy' => 'username',
            'allowedDomains' => "example.com\n.eu.example.com\n",
            'linkExistingAccounts' => true,
            'linkAdminAccounts' => true,
        ]);

        Assert::false($provisioning->allowJit);
        Assert::false($provisioning->updateOnLogin);
        Assert::true($provisioning->denyIfNoGroupMatch);
        Assert::same(UserMatchKey::Username, $provisioning->matchBy);
        Assert::sameList(['example.com', '.eu.example.com'], $provisioning->allowedDomains());
        Assert::true($provisioning->linkAdminAccounts);
    },

    'provisioning defaults are the cautious end of every switch' => static function (): void {
        $provisioning = SettingsTranslator::provisioning([]);

        Assert::true($provisioning->allowJit);
        Assert::false($provisioning->linkExistingAccounts);
        Assert::false($provisioning->linkAdminAccounts);
        Assert::false($provisioning->restrictsDomains());
    },

    'the lockout guard fires through the translator too' => static function () use ($now): void {
        $settings = ['ssoOnly' => true, 'allowPasswordForAdmins' => false, 'emergencyAccounts' => []];
        $fallback = SettingsTranslator::adminFallback($settings);

        Assert::true($fallback->lockoutGuardApplied());
        Assert::true($fallback->allowPasswordForAdmins);

        $warnings = SettingsTranslator::warnings($settings, $now);
        Assert::same(1, count($warnings));
        Assert::contains('password login for admins was turned back on', $warnings[0]);
    },

    'break glass without an expiry: closed at runtime, refused on save' => static function () use ($now): void {
        $settings = ['breakGlassEnabled' => true, 'breakGlassExpiresAt' => null];

        // Runtime: fail closed, never throw while a login page is rendering.
        Assert::false(SettingsTranslator::adminFallback($settings)->isBreakGlassActive($now));

        // Save time: the administrator hears about it.
        $fields = array_column(SettingsTranslator::problems($settings, $now), 0);
        Assert::true(in_array('breakGlassExpiresAt', $fields, true), 'expiry problem reported');
    },

    'break glass longer than a day is refused on save' => static function () use ($now): void {
        $problems = SettingsTranslator::problems([
            'breakGlassEnabled' => true,
            'breakGlassExpiresAt' => $now + 86_401,
        ], $now);

        Assert::same('breakGlassExpiresAt', $problems[0][0]);
        Assert::contains('at most 24 hours', $problems[0][1]);
    },

    'an active break glass window is reported as a warning' => static function () use ($now): void {
        $warnings = SettingsTranslator::warnings([
            'breakGlassEnabled' => true,
            'breakGlassExpiresAt' => $now + 1800,
        ], $now);

        Assert::same(1, count($warnings));
        Assert::contains('30 minute(s)', $warnings[0]);
    },

    // The runtime decision (Core\Login\BrowserBinding) and this warning must be driven by the
    // same value, or the screen will say one thing while the login does another.
    'a SAML callback that is not HTTPS warns that the browser binding is off'
        => static function () use ($now, $saml): void {
            $settings = $saml;
            $settings['samlAcsUrl'] = 'http://site.example.com/keyway-sso/saml/acs';

            $warnings = SettingsTranslator::warnings($settings, $now);

            Assert::same(1, count($warnings));
            Assert::contains('WITHOUT', $warnings[0]);
            Assert::contains('SameSite=None', $warnings[0]);
            Assert::same(
                'http://site.example.com/keyway-sso/saml/acs',
                SettingsTranslator::callbackUrl($settings)
            );
        },

    'an HTTPS callback earns no binding warning' => static function () use ($now, $saml): void {
        Assert::same([], SettingsTranslator::warnings($saml, $now));
    },

    'an OIDC redirect URI that is not HTTPS warns, but about a different thing'
        => static function () use ($now, $oidc): void {
            $settings = $oidc;
            $settings['oidcRedirectUri'] = 'http://site.example.com/callback';

            $warnings = SettingsTranslator::warnings($settings, $now);

            Assert::same(1, count($warnings));
            Assert::contains('still tied to the browser', $warnings[0], 'Lax needs no Secure');
        },

    'a disabled connection has no callback to warn about' => static function () use ($now): void {
        Assert::null(SettingsTranslator::callbackUrl(['samlAcsUrl' => 'http://x.example/acs']));
        Assert::same([], SettingsTranslator::warnings(['samlAcsUrl' => 'http://x.example/acs'], $now));
    },

    'linking and admin escalation each earn a warning' => static function () use ($now): void {
        $warnings = SettingsTranslator::warnings([
            'linkExistingAccounts' => true,
            'allowAdminEscalation' => true,
        ], $now);

        Assert::same(2, count($warnings));
    },

    // The plugin's own edition warning. It exists because Craft's alert for `minCmsEdition`
    // does not block installation, so a site below Pro can be sitting there with group rules
    // that quietly assign nothing.
    'below Craft Pro, a mapping that names a Craft group is warned about' => static function () use ($now): void {
        $warnings = SettingsTranslator::warnings([
            'groupRules' => [
                ['matchType' => 'exact', 'pattern' => 'idp-editors', 'targetGroup' => 'editors'],
            ],
            'defaultGroup' => 'staff',
        ], $now, false);

        Assert::same(1, count($warnings));
        Assert::contains('"editors"', $warnings[0], 'the mapped handle is named');
        Assert::contains('"staff"', $warnings[0], 'and so is the default group');
        Assert::contains('Craft Pro', $warnings[0]);
    },

    // THE NARROWNESS IS THE FEATURE, and this is the case that pins it. Both of these work
    // perfectly on an edition with no user groups - the refusal compares PROVIDER groups against
    // the mapping on this screen, and admin is a column on the user - so warning about them
    // would teach an administrator to distrust a feature that is doing its job.
    'the edition warning ignores admin rules and deny-if-no-match, which work without groups'
        => static function () use ($now): void {
            Assert::same([], SettingsTranslator::warnings([
                'denyIfNoGroupMatch' => true,
                'adminRules' => [['matchType' => 'exact', 'pattern' => 'idp-admins']],
                // A rule with no target group names nothing to assign.
                'groupRules' => [['matchType' => 'exact', 'pattern' => 'idp-editors', 'targetGroup' => '']],
            ], $now, false));
        },

    'on an edition that keeps groups the same mapping is silent' => static function () use ($now): void {
        Assert::same([], SettingsTranslator::warnings([
            'groupRules' => [
                ['matchType' => 'exact', 'pattern' => 'idp-editors', 'targetGroup' => 'editors'],
            ],
        ], $now, true));
    },

    'a complete SAML connection builds' => static function () use ($saml, $cert): void {
        $connection = SettingsTranslator::samlConnection($saml);

        Assert::same('https://idp.example.com/realms/keyway', $connection->idpEntityId);
        Assert::same(60, $connection->clockSkew);
        Assert::false($connection->canDecrypt());

        // ARMOURED, not the raw setting. The sign-in path hands this value to
        // Utils::validateSign() -> XMLSecurityKey::loadKey(), which calls openssl_x509_read()
        // on the raw string, and openssl_x509_read() does not read base64 without armour - so
        // the bare body an identity-provider panel displays used to save cleanly and then fail
        // every login. SamlConnectionConfig normalises it once, on the boundary.
        Assert::contains('-----BEGIN CERTIFICATE-----', $connection->idpX509Cert);
        Assert::contains('-----END CERTIFICATE-----', $connection->idpX509Cert);

        // Same bytes, only re-wrapped: normalising must not alter the certificate itself.
        Assert::same($cert, preg_replace(
            '/\s+/',
            '',
            str_replace(
                ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'],
                '',
                $connection->idpX509Cert
            )
        ) ?? '');

        // A value that already carries armour is passed through untouched - apart from the
        // trim() the constructor has always done, which takes the trailing newline off. Both
        // readers accept a PEM block without it (measured through SamlResponseReader::read()).
        $armoured = $saml;
        $armoured['samlIdpCertificate'] = CertificateFixtures::pem();
        Assert::same(
            trim(CertificateFixtures::pem()),
            SettingsTranslator::samlConnection($armoured)->idpX509Cert
        );
    },

    'a SAML fingerprint is not a certificate' => static function () use ($saml, $now): void {
        $settings = $saml;
        $settings['samlIdpCertificate'] = str_repeat('ab', 32);

        $problems = SettingsTranslator::problems($settings, $now);
        Assert::same('samlIdpEntityId', $problems[0][0]);
        Assert::contains('fingerprint is not accepted', $problems[0][1]);

        // ONE message, not two. The save-time certificate check refuses the same value, and a
        // screen that says "this is a fingerprint" and "openssl does not recognise this" about
        // the same box is a screen that reads like two separate faults.
        Assert::same(1, count($problems), 'one paste, one complaint');
    },

    'an over-wide clock skew is refused' => static function () use ($saml, $now): void {
        $settings = $saml;
        $settings['samlClockSkew'] = 600;

        $problems = SettingsTranslator::problems($settings, $now);
        Assert::contains('Clock skew', $problems[0][1]);
    },

    'a complete OIDC connection builds, scopes included' => static function () use ($oidc): void {
        $settings = $oidc;
        $settings['oidcScopes'] = "profile\nemail\n";

        $connection = SettingsTranslator::oidcConnection($settings);

        Assert::same('craft-cp', $connection->clientId);
        Assert::true($connection->isConfidential());
        // `openid` is mandatory and gets prepended when the administrator removes it.
        Assert::sameList(['openid', 'profile', 'email'], $connection->scopes());
    },

    // Clearing the scopes field is "give me the defaults", not "ask for nothing": an
    // authorization request without `openid` is not an OIDC request at all.
    'cleared scopes fall back to the shipped set' => static function () use ($oidc): void {
        $settings = $oidc;
        $settings['oidcScopes'] = '';

        Assert::sameList(['openid', 'profile', 'email'], SettingsTranslator::oidcConnection($settings)->scopes());
        $settings['oidcScopes'] = [];
        Assert::sameList(['openid', 'profile', 'email'], SettingsTranslator::oidcConnection($settings)->scopes());
    },

    // project.yaml is a file people hand-edit, and YAML turns `off` into a string here, not a
    // boolean. Reading it as true would switch on whatever the administrator switched off.
    'the words YAML uses for false are read as false' => static function (): void {
        foreach (['off', 'no', 'false', '0', 'OFF', ' false '] as $word) {
            Assert::false(SettingsTranslator::provisioning(['allowJit' => $word])->allowJit, 'allowJit=' . $word);
        }

        foreach (['on', 'yes', 'true', '1'] as $word) {
            Assert::true(SettingsTranslator::provisioning(['allowJit' => $word])->allowJit, 'allowJit=' . $word);
        }

        // Absent and blank both mean "untouched", which is the shipped default, not false.
        Assert::true(SettingsTranslator::provisioning([])->allowJit);
        Assert::true(SettingsTranslator::provisioning(['allowJit' => ''])->allowJit);
    },

    'an empty client secret means a public client, not an empty string' => static function () use ($oidc): void {
        $settings = $oidc;
        $settings['oidcClientSecret'] = '   ';

        Assert::false(SettingsTranslator::oidcConnection($settings)->isConfidential());
    },

    'a plain http issuer is refused' => static function () use ($oidc, $now): void {
        $settings = $oidc;
        $settings['oidcIssuer'] = 'http://idp.example.com/realms/keyway';

        $problems = SettingsTranslator::problems($settings, $now);
        Assert::same('oidcIssuer', $problems[0][0]);
        Assert::contains('https', $problems[0][1]);
    },

    // Half-filled SAML fields left over after switching to OIDC must not block a save.
    'only the selected protocol is validated' => static function () use ($oidc, $now): void {
        $settings = $oidc;
        $settings['samlIdpEntityId'] = '';
        $settings['samlIdpCertificate'] = 'not-a-certificate';

        Assert::sameList([], SettingsTranslator::problems($settings, $now));
    },

    // The most expensive default in the plugin: flipped to false it locks whoever set up SSO
    // out of their own control panel, and wouldLockOut() cannot catch it - with ssoOnly off it
    // answers false without ever looking at this field.
    'password login for admins is on until somebody turns it off' => static function (): void {
        Assert::true(SettingsTranslator::adminFallback([])->allowPasswordForAdmins);
        Assert::false(SettingsTranslator::adminFallback(['allowPasswordForAdmins' => false])->allowPasswordForAdmins);
    },

    'a clean configuration reports nothing' => static function () use ($saml, $now): void {
        Assert::sameList([], SettingsTranslator::problems($saml, $now));
    },

    'metadata is published only when there is something honest to publish' =>
        static function () use ($saml, $oidc): void {
            $document = SettingsTranslator::spMetadata($saml);
            Assert::true($document instanceof SpMetadata, 'a configured SAML site has metadata');

            $xml = new DOMDocument();
            Assert::true($xml->loadXML($document->toXml()), 'and the document parses');
            Assert::same(
                $saml['samlSpEntityId'],
                $xml->documentElement?->getAttribute('entityID'),
                'naming the entity id the reader will compare the audience against'
            );

            $acs = $xml->getElementsByTagNameNS(
                'urn:oasis:names:tc:SAML:2.0:metadata',
                'AssertionConsumerService'
            );
            Assert::same(1, $acs->length);
            Assert::same(
                $saml['samlAcsUrl'],
                $acs->item(0)?->getAttribute('Location'),
                'and the ACS URL the response reader will compare against'
            );

            // The two gaps this document deliberately carries. Both are named in
            // SettingsTranslator::spMetadata; asserted here so that "we do not have SLO yet"
            // cannot quietly become "we advertise an SLO endpoint that 404s".
            Assert::same(
                0,
                $xml->getElementsByTagNameNS(
                    'urn:oasis:names:tc:SAML:2.0:metadata',
                    'SingleLogoutService'
                )->length,
                'no logout endpoint is advertised while the product has none'
            );
            Assert::same(
                0,
                $xml->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'KeyDescriptor')->length,
                'and no key, because the plugin stores a private key and not a certificate'
            );
            Assert::false(
                $xml->documentElement?->hasAttribute('validUntil'),
                'no expiry by default: the file is downloaded now and uploaded days later'
            );
        },

    'an expiry is written only when the caller asks for one' => static function () use ($saml): void {
        $document = SettingsTranslator::spMetadata($saml, 1_700_000_000);
        Assert::true($document instanceof SpMetadata);

        $xml = new DOMDocument();
        $xml->loadXML($document->toXml());

        Assert::same(
            gmdate('Y-m-d\TH:i:s\Z', 1_700_000_000),
            $xml->documentElement?->getAttribute('validUntil')
        );
    },

    'nothing is published when the document would be a lie' => static function () use ($saml, $oidc): void {
        // An IdP configured from a document naming a blank entity id is an IdP configured
        // against a sign-in that can never validate - so the answer is null, and the endpoint
        // that asks this question answers 404.
        Assert::null(SettingsTranslator::spMetadata($oidc), 'an OIDC install is not a SAML SP');
        Assert::null(
            SettingsTranslator::spMetadata(['protocol' => 'disabled'] + $saml),
            'nor is an install with single sign-on switched off, however complete its SAML fields'
        );

        // A list of pairs and not a map: two of these four cases share a field name, and an
        // array literal would silently keep only the last of them.
        $unusable = [
            ['samlSpEntityId', ''],
            ['samlSpEntityId', '   '],
            ['samlAcsUrl', ''],
            ['samlAcsUrl', 'not-a-url'],
            ['samlAcsUrl', '/actions/keyway-sso/sso/acs'],
        ];

        foreach ($unusable as [$field, $value]) {
            $broken = $saml;
            $broken[$field] = $value;
            Assert::null(
                SettingsTranslator::spMetadata($broken),
                $field . ' = ' . var_export($value, true) . ' publishes nothing'
            );
        }
    },

    'readiness is what the login screen asks before drawing a button' => static function () use ($saml, $oidc): void {
        Assert::true(SettingsTranslator::isReadyToSignIn($saml));
        Assert::true(SettingsTranslator::isReadyToSignIn($oidc));

        // Disabled is not "not ready yet" - it is a deliberate answer. The SAML case alone would
        // pass for the wrong reason (a disabled protocol falls through to the OIDC branch, which
        // throws on an empty issuer), so the assertion that actually pins the guard is the one
        // where everything except the protocol is valid and ready to go.
        Assert::false(SettingsTranslator::isReadyToSignIn(['protocol' => 'disabled'] + $saml));
        Assert::false(SettingsTranslator::isReadyToSignIn(['protocol' => 'disabled'] + $oidc));

        $broken = $saml;
        $broken['samlAcsUrl'] = 'not-a-url';
        Assert::false(SettingsTranslator::isReadyToSignIn($broken));
    },
];

// ---------------------------------------------------------------------------------------------
// The save-time certificate check. Separate because it is the one group in this file that needs
// ext-openssl: the check asks openssl to parse the value, and where the extension is absent it
// deliberately accepts everything rather than locking an administrator out of the settings
// screen (IdpCertificate, decision 2). Asserting a refusal there would assert the opposite of
// the rule. The skip is printed rather than silent - a group that quietly disappears reads as
// green.
// ---------------------------------------------------------------------------------------------

if (!extension_loaded('openssl')) {
    fwrite(STDOUT, sprintf(
        "%-26s %s\n",
        'settings_translator',
        'skipped (certificate cases): ext-openssl absent'
    ));

    return $cases;
}

/** Everything problems() says about the IdP certificate field. */
$certificateProblems = static function (string $value) use ($saml, $now): array {
    $settings = $saml;
    $settings['samlIdpCertificate'] = $value;

    return array_values(array_filter(
        SettingsTranslator::problems($settings, $now),
        static fn (array $problem): bool => $problem[0] === 'samlIdpCertificate'
    ));
};

/**
 * Everything warnings() says while the certificate field holds $value.
 *
 * The $saml fixture warns about nothing on its own (HTTPS callback, no linking, no escalation),
 * so the count below is the count of certificate warnings and nothing else.
 */
$certificateWarnings = static function (string $value) use ($saml, $now): array {
    $settings = $saml;
    $settings['samlIdpCertificate'] = $value;

    return SettingsTranslator::warnings($settings, $now);
};

return $cases + [
    // THE DEFECT THIS GROUP EXISTS FOR (measured 2026-09-15): the shape floor accepts any 256+
    // character base64 blob, so a private key, a half-copied certificate or noise SAVED CLEANLY
    // and then failed at the first login - as a signature-verification error that reads like a
    // fault in the identity provider, three screens away from the field that caused it.
    'a private key pasted into the certificate field is refused at save time'
        => static function () use ($certificateProblems): void {
            // The shape the defect was measured on: armour removed, which is what a panel that
            // shows "the key" and a copy without the header both produce. Nothing but openssl
            // can tell it from a certificate, and nothing but openssl did.
            $problems = $certificateProblems(CertificateFixtures::privateKeyBody());

            Assert::same(1, count($problems), 'the save is refused');
            Assert::contains('PRIVATE KEY', $problems[0][1], 'and it says what was pasted');
        },

    // The armoured key was already refused before this check existed - the dashes break
    // SamlConnectionConfig's base64 rule - so it is pinned where it actually lands, on
    // samlIdpEntityId, rather than moved. It is also the one shape where the message is still
    // the generic one: the certificate check is skipped once the connection itself has
    // complained, because two messages about one paste read as two separate faults.
    'an armoured private key was already refused, and stays refused'
        => static function () use ($saml, $now): void {
            $settings = $saml;
            $settings['samlIdpCertificate'] = "-----BEGIN PRIVATE KEY-----\n"
                . chunk_split(CertificateFixtures::privateKeyBody(), 64, "\n")
                . "-----END PRIVATE KEY-----\n";

            $problems = SettingsTranslator::problems($settings, $now);

            Assert::same(1, count($problems));
            Assert::same('samlIdpEntityId', $problems[0][0]);
            Assert::contains('PEM or base64 X.509 certificate', $problems[0][1]);
        },

    // Half a certificate is the most common bad paste there is: the copy stopped at the edge of
    // the scroll box. It is legal base64 and long enough to clear every shape rule we have.
    'a certificate cut short in the paste is refused, and the message says so'
        => static function () use ($certificateProblems): void {
            $problems = $certificateProblems(CertificateFixtures::truncatedBody());

            Assert::same(1, count($problems));
            Assert::contains('cut short', $problems[0][1]);

            // BOTH NUMBERS, because both are quoted to the administrator and an off-by-one in
            // the DER header arithmetic would send somebody counting bytes in the wrong file.
            // 400 base64 characters decode to 300 bytes; the structure they open declares 793.
            Assert::contains('793-byte', $problems[0][1]);
            Assert::contains('only 300 bytes', $problems[0][1]);
        },

    // The literal false positive from the 2026-09-15 measurement, pinned as a case: 320
    // characters of base64 that mean nothing, accepted by the shape floor.
    'a long base64 blob that is not a certificate is refused'
        => static function () use ($certificateProblems): void {
            $repeated = $certificateProblems(str_repeat('MIIC', 80));
            Assert::same(1, count($repeated));

            // WHICH MESSAGE IT GETS IS ASSERTED, because it is not the obvious one and the
            // surprise belongs in the test rather than in a support ticket: `MIIC` repeated
            // decodes to 0x30 0x82 0x02 ... - a SEQUENCE declaring 564 bytes, of which 240 are
            // there - so the classifier calls it a paste that was cut short. Nothing was
            // actually cut; the bytes say so, and the sentence only reports what they say.
            Assert::contains('cut short', $repeated[0][1]);
            Assert::contains('564-byte', $repeated[0][1]);
            Assert::contains('only 240 bytes', $repeated[0][1]);

            // Noise that does not even open a DER structure gets the general sentence instead.
            $noise = $certificateProblems(str_repeat('QUJD', 80));
            Assert::same(1, count($noise));
            Assert::contains('does not recognise this as an X.509 certificate', $noise[0][1]);
        },

    // The other half of the DER length arithmetic, and the only case in this file that calls
    // IdpCertificate directly instead of going through problems().
    //
    // THAT IS DELIBERATE. DER writes a length under 128 in one byte (short form) and anything
    // larger in several (long form), and the two are separate lines of code. Every value that
    // can reach the settings screen uses the long form - SamlConnectionConfig's floor demands
    // 256 base64 characters, which is 192 bytes, and a short-form structure tops out at 129 -
    // so the short-form line is unreachable from there and a mutation of it (2 + $first ->
    // 1 + $first) stayed green through the whole suite. The numbers land in a sentence an
    // administrator reads, so the arithmetic is pinned where it can be reached at all.
    'the short-form DER length is counted correctly too'
        => static function (): void {
            $error = Assert::throws(
                InvalidArgumentException::class,
                static fn () => IdpCertificate::assertUsable(
                    base64_encode("\x30\x7f" . str_repeat("\x00", 10))
                )
            );

            // 0x7F content bytes plus the two header bytes = 129; twelve are present.
            Assert::contains('129-byte', $error->getMessage());
            Assert::contains('only 12 bytes', $error->getMessage());
        },

    // THE 2026-09-22 MEASUREMENT, pinned: a certificate that parses as X.509 and yields no
    // usable public key. openssl_x509_read() - the obvious check, and the one this gate used
    // first - accepts it; openssl_pkey_get_public(), which is what both readers really call,
    // does not. One flipped bit inside the key does it.
    'a certificate that parses but yields no public key is refused'
        => static function () use ($certificateProblems): void {
            $problems = $certificateProblems(CertificateFixtures::damagedBody());

            Assert::same(1, count($problems));
            Assert::contains('no public key can be read out of it', $problems[0][1]);
            Assert::contains('damaged', $problems[0][1], 'and it does not send them after a new file');
        },

    // MEASURED: OpenSSL's base64 decoder skips spaces, tabs, CR and LF inside a PEM body, and
    // stops at a vertical tab or a form feed - the two characters a copy out of a PDF or a
    // word processor brings with it. Inside an armoured block nothing strips them before the
    // reader sees them, so this is a value that would save cleanly and fail every login.
    'a PEM block carrying a character OpenSSL will not skip is refused'
        => static function () use ($certificateProblems): void {
            $problems = $certificateProblems(CertificateFixtures::pemWithUnskippableWhitespace());

            Assert::same(1, count($problems));
            Assert::contains('plain-text', $problems[0][1]);
            Assert::contains('vertical tab', $problems[0][1], 'the message names the character');
        },

    // U-5 of the 2026-09-22 review, and it is not cosmetic: openssl queues errors instead of
    // throwing them, so an undrained queue surfaces on the NEXT openssl call in the same
    // request - as a confusing error about a document that was fine. Removing the body of
    // drainOpenSslErrors() left the suite green until this case existed.
    'refusing a certificate leaves no openssl errors behind for the next caller'
        => static function () use ($certificateProblems): void {
            while (openssl_error_string() !== false) {
                // start from a clean queue, whatever ran before this case
            }

            Assert::same(1, count($certificateProblems(CertificateFixtures::privateKeyBody())));

            Assert::false(
                openssl_error_string() !== false,
                'the openssl error queue is empty after a refusal'
            );
        },

    // Decision 1: panels hand out PEM and bare base64 in roughly equal measure, and a copy out
    // of a browser brings stray indentation with it. All three are the same certificate.
    'PEM armour, bare base64 and a sloppy copy are all accepted'
        => static function () use ($certificateProblems): void {
            $spaced = "  \n" . chunk_split(CertificateFixtures::body(), 40, " \r\n  ") . "\n ";

            foreach (
                [
                    'bare base64' => CertificateFixtures::body(),
                    'PEM block' => CertificateFixtures::pem(),
                    'PEM block indented' => "\n   " . CertificateFixtures::pem() . "   \n",
                    'bare body with stray whitespace' => $spaced,
                ] as $shape => $value
            ) {
                Assert::sameList([], $certificateProblems($value), $shape . ' saves');
            }
        },

    // A block that was never closed produces a mangled body inside Utils::formatCert(), so the
    // login fails on a value the screen called fine.
    'an unclosed PEM block is refused' => static function () use ($certificateProblems): void {
        $problems = $certificateProblems(
            "-----BEGIN CERTIFICATE-----\n" . chunk_split(CertificateFixtures::body(), 64, "\n")
        );

        Assert::same(1, count($problems));
        Assert::contains('never closed', $problems[0][1]);
    },

    // The pinned fixture must not be the reason the rule passes. This one is generated in the
    // test run - openssl_pkey_new() + openssl_csr_new() + openssl_csr_sign() + openssl_x509_export(),
    // through SamlFixtures, which already owns that code for the signing suites.
    'a certificate generated in this test run is accepted too'
        => static function () use ($certificateProblems): void {
            $generated = SamlFixtures::cert();

            Assert::contains('BEGIN CERTIFICATE', $generated, 'the fixture really is a PEM certificate');
            Assert::sameList([], $certificateProblems($generated), 'PEM as generated');

            Assert::sameList(
                [],
                $certificateProblems(preg_replace(
                    '/\s+/',
                    '',
                    str_replace(
                        ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'],
                        '',
                        $generated
                    )
                ) ?? ''),
                'and de-armoured'
            );
        },

    // Same rule as samlIdpEntityId: SAML fields left behind after a switch to OIDC - or after
    // switching SSO off entirely - are not errors. A settings screen that refuses to save
    // because of a connection the site does not use is how an administrator ends up deleting
    // their fallback configuration to get past a message.
    'the certificate is only parsed while SAML is the selected protocol'
        => static function () use ($saml, $now): void {
            foreach (['oidc', 'disabled', 'ldap'] as $protocol) {
                $settings = $saml;
                $settings['protocol'] = $protocol;
                $settings['samlIdpCertificate'] = CertificateFixtures::privateKeyBody();

                $fields = array_column(SettingsTranslator::problems($settings, $now), 0);

                Assert::false(
                    in_array('samlIdpCertificate', $fields, true),
                    'protocol ' . $protocol . ': the certificate field is not parsed'
                );
            }
        },

    // One complaint at a time about one connection. While something else in the SAML block is
    // still wrong, the certificate check stays quiet - an administrator halfway through filling
    // the screen should not collect a second message about a field they have not reached yet.
    // The certificate problem appears on the next save, once the rest of the block is valid.
    'a half-filled SAML connection reports its own fault, not a certificate fault'
        => static function () use ($saml, $now): void {
            $settings = $saml;
            $settings['samlIdpSsoUrl'] = 'not-a-url';

            $problems = SettingsTranslator::problems($settings, $now);

            Assert::same(1, count($problems));
            Assert::same('samlIdpEntityId', $problems[0][0]);
            Assert::contains('IdP SSO URL', $problems[0][1]);
        },

    // -----------------------------------------------------------------------------------------
    // A PRIVATE KEY PASTED IN NEXT TO THE CERTIFICATE. These values WORK - openssl takes the
    // first structure and so do both readers - so the save-time gate must keep accepting them,
    // and the screen must still say that somebody's private key is now in the settings table,
    // in project config and in every backup of either. Warning, never refusal: blocking the
    // save would lock an administrator out of a configuration that signs in perfectly well.
    // -----------------------------------------------------------------------------------------

    'a certificate with a private key pasted after it saves, and the screen says so'
        => static function () use ($certificateProblems, $certificateWarnings): void {
            $value = CertificateFixtures::pemWithPrivateKeyAppended();

            // THE SAVE IS UNCHANGED. This half is the point of the pairing: the warning was
            // added without turning a working configuration into an unsaveable one.
            Assert::sameList([], $certificateProblems($value), 'the save still goes through');

            $warnings = $certificateWarnings($value);

            Assert::same(1, count($warnings));
            Assert::contains('pasted together with a private key', $warnings[0]);
            Assert::contains('Sign-in still works', $warnings[0], 'it does not claim a breakage');
            Assert::contains('treat it as exposed', $warnings[0], 'and it says what to do');
        },

    // THE ORDER IS NOT COSMETIC: an export written "key then cert" produces this, it still saves
    // (openssl walks past the key block to reach the certificate), and a detector that only
    // looked for a key AFTER the certificate would leave the screen silent on it.
    'a private key pasted before the certificate is found too'
        => static function () use ($certificateProblems, $certificateWarnings): void {
            $value = CertificateFixtures::pemWithPrivateKeyFirst();

            Assert::sameList([], $certificateProblems($value), 'the save still goes through');

            $warnings = $certificateWarnings($value);

            Assert::same(1, count($warnings));
            Assert::contains('pasted together with a private key', $warnings[0]);
        },

    // The shape no rule based on appearance can see: base64(DER(certificate) . DER(key)), which
    // looks exactly like one long certificate. The readers take the first structure and succeed,
    // so this is the paste that used to save, work, and carry a key into project config silently.
    'the de-armoured certificate-plus-key blob is found too'
        => static function () use ($certificateProblems, $certificateWarnings): void {
            $value = CertificateFixtures::bodyWithPrivateKeyAppended();

            Assert::sameList([], $certificateProblems($value), 'the save still goes through');

            $warnings = $certificateWarnings($value);

            Assert::same(1, count($warnings));
            Assert::contains('private key', $warnings[0]);
        },

    // A CHAIN IS NOT A PRIVATE KEY. Both shapes here carry two structures in one field and both
    // are legitimate, so a warning that counted structures instead of asking what they are would
    // fire on them - and a warning that cries wolf on a normal paste teaches administrators to
    // scroll past the other six. This case is the guard against that, not a formality.
    'a certificate chain saves and warns about nothing'
        => static function () use ($certificateProblems, $certificateWarnings): void {
            foreach (
                [
                    'de-armoured chain' => CertificateFixtures::chainBody(),
                    'two PEM blocks' => CertificateFixtures::chainPem(),
                ] as $shape => $value
            ) {
                Assert::sameList([], $certificateProblems($value), $shape . ' saves');

                while (openssl_error_string() !== false) {
                    // start from a clean queue, whatever ran before this case
                }

                Assert::sameList([], $certificateWarnings($value), $shape . ' is silent');

                // THE QUEUE IS ASSERTED ON THIS VALUE AND NOT ON THE WARNING CASE, deliberately:
                // openssl queues errors rather than throwing them, and an undrained queue
                // surfaces on somebody else's call later in the request - as an error about a
                // document that was fine. A value that WARNS queues nothing (the first key
                // armour tried succeeds), so the assertion would be decorative there; the
                // de-armoured chain is the value that really fills the queue, because the
                // remainder is tried against all three key armours and fails all three. MEASURED
                // before it was put here: 15 entries queued for one chain, none afterwards.
                Assert::false(
                    openssl_error_string() !== false,
                    $shape . ': the openssl error queue is empty after a warning check'
                );
            }
        },

    'an ordinary certificate warns about nothing, in either shape'
        => static function () use ($certificateWarnings): void {
            Assert::sameList([], $certificateWarnings(CertificateFixtures::body()), 'bare base64');
            Assert::sameList([], $certificateWarnings(CertificateFixtures::pem()), 'PEM block');
        },

    // ONE MESSAGE PER PASTE. A field holding nothing but a private key is already refused, in
    // words that name the mistake; adding a warning about the same value would put an error and
    // a warning on the screen for one field, and the administrator would be left wondering
    // whether they are two faults. Both shapes of "key on its own" are pinned: de-armoured
    // (refused by the certificate gate) and armoured (refused a layer earlier, by the shape
    // floor, on samlIdpEntityId).
    'a private key on its own is refused once and not warned about as well'
        => static function () use ($certificateProblems, $certificateWarnings, $saml, $now): void {
            $bare = CertificateFixtures::privateKeyBody();

            Assert::same(1, count($certificateProblems($bare)), 'still refused');
            Assert::sameList([], $certificateWarnings($bare), 'and not also warned about');

            $armoured = $saml;
            $armoured['samlIdpCertificate'] = CertificateFixtures::privateKeyPem();

            Assert::same(1, count(SettingsTranslator::problems($armoured, $now)), 'still refused');
            Assert::sameList([], SettingsTranslator::warnings($armoured, $now));
        },

    // "SIGN-IN STILL WORKS" IS A STATEMENT OF FACT, so it may only appear where it is true.
    // Each value below carries a private key next to a certificate that CANNOT verify anything -
    // damaged bytes, a vertical tab from a word processor, a copy cut short, a block never
    // closed - so assertUsable() refuses the save in its own words. Putting the warning on the
    // screen as well would tell the administrator that sign-in works in the same breath as the
    // error saying the configuration was not even saved, and would break the rule this whole
    // group is built on: ONE MESSAGE PER PASTE.
    //
    // Built inline rather than as fixtures: each is an existing fixture with
    // CertificateFixtures::privateKeyPem() stuck to it, which is exactly how the real paste is
    // produced - the administrator concatenates whatever the export gave them.
    'a private key next to an unusable certificate is refused, not warned about'
        => static function () use ($certificateProblems, $certificateWarnings): void {
            $key = CertificateFixtures::privateKeyPem();
            $der = static fn (string $b64): string => (string)base64_decode($b64, true);

            foreach (
                [
                    'a certificate a word processor put a vertical tab into'
                        => CertificateFixtures::pemWithUnskippableWhitespace() . $key,
                    'a certificate block that was never closed'
                        => "-----BEGIN CERTIFICATE-----\n"
                            . chunk_split(CertificateFixtures::body(), 64, "\n") . $key,
                    'a de-armoured damaged certificate'
                        => base64_encode(
                            $der(CertificateFixtures::damagedBody())
                            . $der(CertificateFixtures::privateKeyBody())
                        ),
                ] as $shape => $value
            ) {
                Assert::same(1, count($certificateProblems($value)), $shape . ' is refused');
                Assert::sameList(
                    [],
                    $certificateWarnings($value),
                    $shape . ': and the screen does not also claim sign-in works'
                );
            }
        },

    // Same rule as every other SAML field: a value left behind after switching to OIDC or
    // switching SSO off is not worth a sentence on the screen.
    'the private key warning only fires while SAML is the selected protocol'
        => static function () use ($saml, $now): void {
            foreach (['oidc', 'disabled', 'ldap'] as $protocol) {
                $settings = $saml;
                $settings['protocol'] = $protocol;
                $settings['samlIdpCertificate'] = CertificateFixtures::pemWithPrivateKeyAppended();

                Assert::sameList(
                    [],
                    SettingsTranslator::warnings($settings, $now),
                    'protocol ' . $protocol . ': the certificate field is not examined'
                );
            }
        },

    // The predicate itself, on the two things the call through warnings() cannot reach.
    //
    // THE LABEL IS TAKEN AT ITS WORD in the armoured shape, deliberately: a key too mangled to
    // parse is still a key sitting in project config, still has to be removed and still has to
    // be rotated, so requiring a successful parse would mean the worse paste gets the quieter
    // screen. What is pinned is that EVERY label ending in "PRIVATE KEY" counts, not a list of
    // the ones we thought of. (Not wider than that: the pattern wants five dashes, so
    // ssh.com/PuTTY's four-dash `---- BEGIN SSH2 ... ----` does not match. No identity provider
    // exports it, so it is left alone.)
    //
    // ENCRYPTED PRIVATE KEY IS THE CASE THIS LIST EXISTS FOR (measured 2026-09-23, openssl
    // 3.5.5): `openssl pkcs12 -in idp.pfx -out idp.pem` writes CERTIFICATE + ENCRYPTED PRIVATE
    // KEY, and `-nodes` - the flag that would make it a plain PRIVATE KEY - is the one people
    // leave out. PKCS#12 is how ADFS, Entra and keytool hand over a certificate together with
    // its key, so this is the COMMON shape of this paste, and the first version of the detector
    // was silent on it: its regex listed PKCS#8, PKCS#1 and SEC1 while an encrypted key IS
    // PKCS#8 (EncryptedPrivateKeyInfo). DSA and OPENSSH were silent for the same reason. Remove
    // any label below from the pattern and this case has to go red.
    'the private-key detector knows every key armour, parseable or not'
        => static function (): void {
            foreach (
                [
                    'PRIVATE KEY',
                    'ENCRYPTED PRIVATE KEY',
                    'RSA PRIVATE KEY',
                    'EC PRIVATE KEY',
                    'DSA PRIVATE KEY',
                    'OPENSSH PRIVATE KEY',
                ] as $label
            ) {
                Assert::true(
                    IdpCertificate::carriesPrivateKey(
                        CertificateFixtures::pem()
                        . '-----BEGIN ' . $label . "-----\nnot-even-base64\n"
                        . '-----END ' . $label . "-----\n"
                    ),
                    $label . ' counts even when the block itself is mangled'
                );
            }

            // And an empty field is not a leak, on any code path.
            Assert::false(IdpCertificate::carriesPrivateKey(''));
            Assert::false(IdpCertificate::carriesPrivateKey('   '));

            // NEXT TO, NOT INSTEAD OF: two DER structures and not a certificate among them.
            // There is nothing here that could verify a signature, so the save is refused with
            // a sentence naming that, and a warning as well would be a second message about one
            // paste. Pinned by the usability gate at the top of carriesPrivateKey() rather than
            // by the branch below it. Built inline rather than as a fixture because no identity
            // provider produces it; it is here to pin the rule, not the paste.
            $key = (string)base64_decode(CertificateFixtures::privateKeyBody(), true);

            Assert::false(
                IdpCertificate::carriesPrivateKey(base64_encode($key . $key)),
                'no certificate in the field: that is a refusal, not a warning'
            );
        },
];
