<?php

declare(strict_types=1);

use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Models\Settings;
use Keyway\Sso\Plugin;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CertificateFixtures;

/**
 * The thin Craft layer: the plugin class Craft loads, and the settings model it stores.
 *
 * These cases do NOT boot Craft. There is no database, no application, no web request - the
 * classes are inspected by reflection and the settings model is instantiated on its own, which
 * works because `craft\base\Model` is an ordinary Yii model and because everything with a rule
 * in it was pushed into SettingsTranslator (see settings_translator_test.php, which needs no
 * vendor directory at all).
 *
 * What is verified here is the wiring nobody notices until an install fails: that the class
 * `composer.json` advertises exists and extends the right base, that `hasCpSettings` matches the
 * manifest, that the settings template is where settingsHtml() looks for it, and - the one most
 * likely to rot - that every settings key the translator reads is a property the model actually
 * declares.
 *
 * When `vendor/` is absent the suite skips with a visible line rather than disappearing: a test
 * file that silently returns nothing reads as "all green" in the runner output, which is how a
 * regression gets shipped.
 */
if (!class_exists(\craft\base\Plugin::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_layer', 'skipped: vendor absent (run composer install)'));

    return [];
}

// Craft's own bootstrap does this; validators reach for `Yii::createObject()` and nothing else.
if (!class_exists(\Yii::class, false)) {
    require __DIR__ . '/../vendor/yiisoft/yii2/Yii.php';
}

/** @var array<string, mixed> $manifest */
$manifest = json_decode((string)file_get_contents(__DIR__ . '/../composer.json'), true, 512, JSON_THROW_ON_ERROR);

/**
 * A REAL certificate: since the save-time check landed (SettingsTranslator::problems() ->
 * IdpCertificate), a blob that merely clears the shape floor is refused, and validate() would
 * fail here for a reason none of these cases is about. Same bytes as settings_translator_test
 * and saml_metadata_test.
 */
$cert = CertificateFixtures::body();

$configureSaml = static function (Settings $settings) use ($cert): Settings {
    $settings->protocol = AuthProtocol::Saml->value;
    $settings->samlIdpEntityId = 'https://idp.example.com/realms/keyway';
    $settings->samlIdpCertificate = $cert;
    $settings->samlIdpSsoUrl = 'https://idp.example.com/realms/keyway/protocol/saml';
    $settings->samlSpEntityId = 'https://site.example.com';
    $settings->samlAcsUrl = 'https://site.example.com/keyway-sso/saml/acs';

    return $settings;
};

$cases = [
    // The exact failure that forced `craftcms/plugin-installer` off on 2026-09-12: the installer
    // resolves extra.class and dies with "Unable to determine the base path" when it is missing.
    'the class composer.json advertises exists and is a Craft plugin' => static function () use ($manifest): void {
        Assert::same(Plugin::class, $manifest['extra']['class']);
        Assert::true(class_exists($manifest['extra']['class']), 'plugin class is autoloadable');
        Assert::true(is_subclass_of(Plugin::class, \craft\base\Plugin::class));
    },

    'the manifest and the class agree about control panel settings' => static function () use ($manifest): void {
        $defaults = (new ReflectionClass(Plugin::class))->getDefaultProperties();

        Assert::same($manifest['extra']['hasCpSettings'], $defaults['hasCpSettings']);
        Assert::same($manifest['extra']['hasCpSection'], $defaults['hasCpSection']);
        Assert::true($defaults['hasCpSettings'], 'settings screen is advertised');

        // The number `craft up` compares against what an installed site has stored. It is
        // pinned rather than read from anywhere, because the schema and the version are two
        // files that have to move together: 1.1.0 is the links table
        // (m260916_101500_add_identity_links_table), and leaving it at 1.0.0 is what kept that
        // table from ever reaching the installation the bug was measured on.
        Assert::same('1.1.0', $defaults['schemaVersion']);
    },

    // A one-word property nobody looks at again, and the one a buyer is judged by. Craft's
    // default is `Solo`, where `Users::getMaxUsers()` allows ONE account - single sign-on with
    // nowhere to provision. `Team` is the floor that was measured to work: sign-in, just-in-time
    // accounts, attribute mapping, the refuse-unless-mapped rule and the admin rule all run
    // there. It is deliberately NOT `Pro`, even though writing Craft group memberships needs
    // Pro: overstating the requirement turns away buyers for whom everything but one feature
    // works, and that one feature degrades loudly (see the guard in CraftSignIn and the settings
    // warning). Pinned because the value can only be corrected by tagging a NEW release - an
    // accidental change is not a listing edit, it is a re-release.
    'the plugin declares the Craft edition it was measured to need' => static function (): void {
        $defaults = (new ReflectionClass(Plugin::class))->getDefaultProperties();

        $edition = $defaults['minCmsEdition'];

        // By NAME, not by comparing the two enum cases: Assert::same reports objects as their
        // class, so a mismatch there prints "expected craft\enums\CmsEdition, got
        // craft\enums\CmsEdition" - a red test that names neither the wrong value nor the right
        // one. This says "expected 'Team', got 'Solo'".
        Assert::same('Team', $edition->name);
        Assert::true(
            $edition->value > \craft\enums\CmsEdition::Solo->value,
            'never falls back to the one-account edition, where provisioning cannot work'
        );
    },

    'the settings hooks are overridden with the signatures Craft calls' => static function (): void {
        foreach (['createSettingsModel', 'settingsHtml'] as $name) {
            $method = new ReflectionMethod(Plugin::class, $name);

            Assert::same(Plugin::class, $method->getDeclaringClass()->name, $name . ' is overridden');
            Assert::true($method->isProtected(), $name . ' stays protected');
            Assert::true($method->getReturnType()?->allowsNull() ?? false, $name . ' is nullable');
        }
    },

    // settingsHtml() renders "keyway-sso/_settings.twig"; Craft resolves that to the plugin's
    // own base path plus /templates, so the handle and the directory have to line up.
    'the settings template is where the plugin looks for it' => static function () use ($manifest): void {
        $basePath = dirname((string)(new ReflectionClass(Plugin::class))->getFileName());

        Assert::same('keyway-sso', $manifest['extra']['handle']);
        Assert::true(is_file($basePath . '/templates/_settings.twig'), 'settings template exists');

        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());
        Assert::contains("'keyway-sso/_settings.twig'", $source);
    },

    'the protocol dropdown offers exactly the protocols that exist' => static function (): void {
        Assert::sameList(
            AuthProtocol::values(),
            array_column(Plugin::protocolOptions(), 'value')
        );
    },

    'the settings model is a Craft model and builds without an application' => static function (): void {
        Assert::true(is_subclass_of(Settings::class, \craft\base\Model::class));

        $settings = new Settings();

        Assert::same(AuthProtocol::Disabled, $settings->protocol());
        Assert::false($settings->isReadyToSignIn(), 'a fresh install does not touch the login screen');
        Assert::sameList([], $settings->warnings());
    },

    // The drift guard: rename a property and the translator would quietly read nothing, which
    // would look exactly like "the administrator left it empty".
    'every key the translator reads is a declared property' => static function (): void {
        $declared = array_keys((new ReflectionClass(Settings::class))->getDefaultProperties());

        $keys = [
            'protocol',
            'samlIdpEntityId', 'samlIdpCertificate', 'samlIdpSsoUrl', 'samlSpEntityId', 'samlAcsUrl',
            'samlSpPrivateKey', 'samlClockSkew', 'samlIdpSloUrl',
            'oidcIssuer', 'oidcClientId', 'oidcClientSecret', 'oidcRedirectUri', 'oidcScopes',
            'oidcClockSkew', 'oidcFetchUserinfo',
            'attributeRules',
            'groupRules', 'adminRules', 'defaultGroup', 'groupSourceAttributes', 'groupSyncMode',
            'groupMatchCaseSensitive', 'allowAdminEscalation', 'revokeAdminWhenUnmatched',
            'allowJit', 'updateOnLogin', 'denyIfNoGroupMatch', 'matchBy', 'allowedDomains',
            'linkExistingAccounts', 'linkAdminAccounts',
            'ssoOnly', 'allowPasswordForAdmins', 'emergencyAccounts', 'breakGlassEnabled',
            'breakGlassExpiresAt',
        ];

        // The one key the translator reads that is NOT a declared property, and cannot be: our
        // own SLO address is derived from the registered route, never stored. It is therefore
        // invisible to the loop below - a rename on either side turns single logout off in
        // silence - so it is pinned behaviourally instead, in settings_translator_test
        // ('the derived SP logout address reaches the connection under the key both sides agree
        // on') and here, through the model's own accessor.
        Assert::same(
            'https://site.example.com/actions/keyway-sso/sso/slo',
            (static function (): ?string {
                $settings = new Settings();
                $settings->protocol = 'saml';
                $settings->samlIdpEntityId = 'https://idp.example.com/realms/keyway';
                $settings->samlIdpCertificate = CertificateFixtures::body();
                $settings->samlIdpSsoUrl = 'https://idp.example.com/realms/keyway/protocol/saml';
                $settings->samlSpEntityId = 'https://site.example.com';
                $settings->samlAcsUrl = 'https://site.example.com/keyway-sso/saml/acs';

                return $settings
                    ->samlConnection('https://site.example.com/actions/keyway-sso/sso/slo')
                    ->spSloUrl;
            })(),
            'the derived SP logout address survives the trip through the settings model'
        );

        foreach ($keys as $key) {
            Assert::true(in_array($key, $declared, true), 'Settings declares ' . $key);
        }
    },

    'the defaults Craft stores are the defaults the core reads' => static function (): void {
        $settings = new Settings();

        Assert::sameList(
            ['email', 'firstName', 'lastName'],
            array_map(static fn($rule): string => $rule->target, $settings->attributeMap()->rules())
        );
        Assert::sameList(['groups'], $settings->groupMap()->sourceAttributes());
        Assert::false($settings->groupMap()->allowsAdminEscalation());
        Assert::true($settings->provisioning()->allowJit);
        Assert::false($settings->provisioning()->linkExistingAccounts);
        Assert::true($settings->adminFallback()->allowPasswordForAdmins);
    },

    'a complete SAML configuration validates and is ready to sign in' => static function () use ($configureSaml): void {
        $settings = $configureSaml(new Settings());

        Assert::true($settings->validate(), 'validate(): ' . json_encode($settings->getErrors()));
        Assert::true($settings->isReadyToSignIn());
        Assert::same('https://site.example.com', $settings->samlConnection()->spEntityId);
    },

    // The settings screen offers `suggestEnvVars: true` for both secrets, so the value stored in
    // project config is usually `$KEYWAY_SP_KEY` and not a key. Whoever reads it has to expand
    // it; before 2026-09-13 nobody did, and the plugin reported canDecrypt() on a dollar sign.
    'an env reference reaches the core expanded, not literal' => static function () use ($configureSaml): void {
        $_SERVER['KEYWAY_TEST_SP_KEY'] = "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----";

        try {
            $settings = $configureSaml(new Settings());
            $settings->samlSpPrivateKey = '$KEYWAY_TEST_SP_KEY';

            Assert::true($settings->validate(), 'validate(): ' . json_encode($settings->getErrors()));
            Assert::same($_SERVER['KEYWAY_TEST_SP_KEY'], $settings->samlConnection()->spPrivateKey);
            Assert::true($settings->samlConnection()->canDecrypt());
            Assert::true($settings->isReadyToSignIn());
        } finally {
            unset($_SERVER['KEYWAY_TEST_SP_KEY']);
        }
    },

    // Fail closed: a reference to a variable nobody set is a broken configuration, and it has to
    // read as one on the screen. Treating it as "no key" would announce a working SAML login
    // that dies inside OpenSSL on the first encrypted assertion.
    'an env reference with nothing behind it is not ready to sign in' => static function () use ($configureSaml): void {
        unset($_SERVER['KEYWAY_TEST_MISSING_KEY']);

        $settings = $configureSaml(new Settings());
        $settings->samlSpPrivateKey = '$KEYWAY_TEST_MISSING_KEY';

        Assert::false($settings->isReadyToSignIn());
        Assert::false($settings->validate());
        Assert::contains('KEYWAY_TEST_MISSING_KEY', implode(' ', $settings->getErrors('samlSpPrivateKey')));
    },

    // isReadyToSignIn() fails closed either way, so the screen already said "not usable yet" -
    // it just did not say why, while the field on the page looked filled in. The fault is in the
    // server environment, so the name of the variable is the only actionable part.
    'the warnings name the environment variable that did not resolve' => static function (): void {
        unset($_SERVER['KEYWAY_TEST_MISSING_SECRET']);

        $settings = new Settings();
        $settings->protocol = AuthProtocol::Oidc->value;
        $settings->oidcIssuer = 'https://idp.example.com/realms/keyway';
        $settings->oidcClientId = 'keyway';
        $settings->oidcRedirectUri = 'https://site.example.com/keyway-sso/oidc/callback';
        $settings->oidcClientSecret = '$KEYWAY_TEST_MISSING_SECRET';

        $warnings = implode(' ', $settings->warnings());

        Assert::contains('KEYWAY_TEST_MISSING_SECRET', $warnings);
        Assert::contains('oidcClientSecret', $warnings);
    },

    // The variant that reads as "configured" everywhere else: the variable exists in the
    // environment and holds nothing. App::parseEnv() answers null for that, exactly as it does
    // for a variable nobody set, so the same warning has to fire.
    'a variable that is set but empty is named too' => static function () use ($configureSaml): void {
        $_SERVER['KEYWAY_TEST_EMPTY_KEY'] = '';

        try {
            $settings = $configureSaml(new Settings());
            $settings->samlSpPrivateKey = '$KEYWAY_TEST_EMPTY_KEY';

            $warnings = implode(' ', $settings->warnings());

            Assert::contains('KEYWAY_TEST_EMPTY_KEY', $warnings);
            Assert::contains('samlSpPrivateKey', $warnings);
            Assert::false($settings->isReadyToSignIn());
        } finally {
            unset($_SERVER['KEYWAY_TEST_EMPTY_KEY']);
        }
    },

    // A resolved reference is not a warning; otherwise the banner would cry wolf on every
    // correctly configured install that uses environment variables, which is all of them.
    'a resolved reference produces no warning' => static function () use ($configureSaml): void {
        $_SERVER['KEYWAY_TEST_SET_KEY'] = "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----";

        try {
            $settings = $configureSaml(new Settings());
            $settings->samlSpPrivateKey = '$KEYWAY_TEST_SET_KEY';

            Assert::sameList([], $settings->warnings());
        } finally {
            unset($_SERVER['KEYWAY_TEST_SET_KEY']);
        }
    },

    // Same rule for OIDC, where the silent failure is worse: null means "public client", so an
    // unset variable would quietly turn a confidential client into one that authenticates with
    // nothing but PKCE.
    'an unset OIDC secret reference does not become a public client' => static function (): void {
        unset($_SERVER['KEYWAY_TEST_MISSING_SECRET']);

        $settings = new Settings();
        $settings->protocol = AuthProtocol::Oidc->value;
        $settings->oidcIssuer = 'https://idp.example.com/realms/keyway';
        $settings->oidcClientId = 'keyway';
        $settings->oidcRedirectUri = 'https://site.example.com/keyway-sso/oidc/callback';
        $settings->oidcClientSecret = '$KEYWAY_TEST_MISSING_SECRET';

        Assert::false($settings->isReadyToSignIn());
        Assert::false($settings->validate());
    },

    // The core objects are the validation; the settings screen must not carry a second copy of
    // the rule that could drift away from the one the reader enforces.
    'a core rejection surfaces as a Craft validation error' => static function () use ($configureSaml): void {
        $settings = $configureSaml(new Settings());
        $settings->samlIdpCertificate = str_repeat('ab', 32);

        Assert::false($settings->validate());
        Assert::contains('fingerprint is not accepted', implode(' ', $settings->getErrors('samlIdpEntityId')));
    },

    'an unknown protocol fails validation instead of being stored' => static function (): void {
        $settings = new Settings();
        $settings->protocol = 'ldap';

        Assert::false($settings->validate());
        Assert::notSame([], $settings->getErrors('protocol'));
    },

    'an over-wide clock skew fails on the field that carries it' => static function () use ($configureSaml): void {
        $settings = $configureSaml(new Settings());
        $settings->samlClockSkew = 600;

        Assert::false($settings->validate());
        Assert::notSame([], $settings->getErrors('samlClockSkew'));
    },

    // AdminFallbackSettings self-heals rather than throwing; the screen has to say so, and
    // saving must still be allowed - a guard that blocks the save it just corrected locks
    // somebody out of their own site.
    'the lockout guard warns through the model without blocking the save' => static function (): void {
        $settings = new Settings();
        $settings->ssoOnly = true;
        $settings->allowPasswordForAdmins = false;

        Assert::true($settings->validate(), 'validate(): ' . json_encode($settings->getErrors()));
        Assert::true($settings->adminFallback()->allowPasswordForAdmins);
        Assert::same(1, count($settings->warnings()));
    },

    'break glass without an expiry is refused at save time' => static function (): void {
        $settings = new Settings();
        $settings->breakGlassEnabled = true;

        Assert::false($settings->validate());
        Assert::notSame([], $settings->getErrors('breakGlassExpiresAt'));
    },

    'settings posted as strings still reach the core as objects' => static function (): void {
        $settings = new Settings();
        $settings->setAttributes([
            'allowedDomains' => "example.com\n.eu.example.com",
            'emergencyAccounts' => "owner@example.com",
            'groupSourceAttributes' => "memberOf",
            'oidcScopes' => "profile\nemail",
        ], false);

        Assert::sameList(['example.com', '.eu.example.com'], $settings->provisioning()->allowedDomains());
        Assert::true($settings->adminFallback()->isEmergencyAccount('OWNER@example.com'));
        Assert::sameList(['memberOf'], $settings->groupMap()->sourceAttributes());
    },

    // ------------------------------------------------------------------------------------
    // The three lines that connect the diagnostics module to the product.
    //
    // Every one of them was, at review time, deletable with the whole suite still green - and
    // each deletion is silent in a different way. Remove the sink and logins stop writing rows
    // while the screen keeps saying "nothing recorded yet". Remove the route and the screen is
    // unreachable by the address the settings page links to. Remove the link and the screen has
    // no way in at all, because the plugin deliberately registers no navigation item.
    //
    // Asserted on the source, like the rules in sso_controller_test.php, because none of them
    // can be exercised without booting Craft: they are properties of the wiring itself.
    // ------------------------------------------------------------------------------------

    'logins write diagnostics to the table, not only to the log' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        // Narrow to the runtime's own construction. `$this->diagnosticsSink()` also appears in
        // the accessor and in diagnosticsReader(), so asserting on the whole file would let the
        // one argument that matters be swapped back to the log sink with the suite still green
        // - measured: that mutation survived the first version of this case.
        // preg_match, NOT preg_replace: a pattern that fails to match makes preg_replace hand
        // back the WHOLE subject, so this narrowing would silently degrade into the wide
        // assertion it was written to replace - and the wide one demonstrably passes while the
        // runtime is wired to the wrong sink. Asserting that the match happened is the
        // difference between a narrowed assertion and one that merely looks narrowed.
        Assert::same(
            1,
            preg_match('/new CraftLoginRuntime\\s*\\((.*?)\\);/s', $source, $matches),
            'the runtime construction was found at all'
        );

        $runtimeCall = $matches[1];

        Assert::contains(
            '$this->diagnosticsSink()',
            $runtimeCall,
            'the login runtime writes to the table, not only to the log'
        );
        Assert::contains('new CraftDbDiagnosticsSink(', $source);
        Assert::same(
            1,
            substr_count($source, 'new CraftLogDiagnosticsSink()'),
            'the log sink appears once, as the fallback inside the db sink'
        );

        // The panel and the login must share one instance: the memoised "is the table usable"
        // answer costs a failed query on an install that never ran `craft up`.
        Assert::contains('return $this->diagnosticsSink();', $source, 'the reader IS the sink');
        Assert::true(
            method_exists(Plugin::class, 'diagnosticsReader'),
            'the panel has an accessor to read through'
        );
    },

    'the metadata document has a route, a way in, and a settings screen that knows both' =>
        static function () use ($configureSaml): void {
            $basePath = dirname((string)(new ReflectionClass(Plugin::class))->getFileName());
            $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());
            $settingsTemplate = (string)file_get_contents($basePath . '/templates/_settings.twig');

            // The three lines that connect the document to the product. Every one of them could
            // be deleted with the whole suite still green if it were not asserted here: the route
            // (nothing answers), the address on screen (nobody finds it), the readiness flag
            // (the screen promises a file the endpoint refuses to serve).
            Assert::contains("self::METADATA_PATH => 'keyway-sso/sso/metadata'", $source, 'the route exists');
            Assert::contains("'metadataUrl' => self::metadataUrl()", $source, 'the screen is given the address');
            Assert::contains(
                "'metadataReady' => \$settings->spMetadata() !== null",
                $source,
                'and the same answer the endpoint will give, asked once'
            );
            Assert::contains('{{ metadataUrl }}', $settingsTemplate, 'the template links to it');
            Assert::contains('metadataReady', $settingsTemplate, 'and changes what it says when there is nothing to serve');

            // The link must not EXIST when there is nothing to download. Craft's `.disabled`
            // only greys an element out - it sets no `pointer-events` - so a disabled-looking
            // `<a href>` is still clickable and still reachable with Tab+Enter, and would take
            // the administrator out of the settings screen onto a 404.
            Assert::same(
                1,
                substr_count($settingsTemplate, 'href="{{ metadataUrl }}"'),
                'exactly one anchor carries the address'
            );
            // The rule is "the anchor lives inside the truthy branch", so the assertion looks at
            // what stands between the `{% if %}` and the anchor and allows anything that is not
            // another Twig tag. Pinning the exact whitespace would make a comment added inside
            // the branch look like a regression.
            Assert::same(
                1,
                preg_match(
                    '/\{%\s*if metadataReady\s*%\}(?:(?!\{%).)*<a [^>]*href="\{\{ metadataUrl \}\}"/s',
                    $settingsTemplate
                ),
                'and it is rendered only in the branch where the endpoint answers'
            );
            Assert::notContains(
                'class="btn disabled" href=',
                $settingsTemplate,
                'a greyed-out anchor is a live anchor'
            );

            // An action URL, not a control-panel path: identity providers re-fetch this document
            // themselves, and a `cpTrigger` is a value the site owner may rename at any time.
            Assert::contains(
                'return self::canonicalEndpointUrl(self::METADATA_PATH);',
                $source,
                'the address is built off the registered route, not written out by hand'
            );
            Assert::true(method_exists(Plugin::class, 'metadataUrl'), 'and is reachable from the screen');

            // The accessor the endpoint reads through, exercised for real rather than by name:
            // a settings model that cannot produce a document makes the route pointless.
            $settings = $configureSaml(new Settings());
            Assert::true(
                $settings->spMetadata() !== null,
                'a configured SAML install publishes metadata'
            );
            Assert::null(
                (new Settings())->spMetadata(),
                'a fresh install publishes nothing - the endpoint answers 404'
            );
        },

    // Same convention as the metadata case above, and for the same reason: every line here could
    // be deleted with the whole suite still green, because none of them can be executed without
    // a CMS. The failure they guard is silent in all four cases - a logout endpoint that is not
    // routed, a Destination pinned to the wrong address, an address nobody can find, and a
    // readiness flag that promises an endpoint which refuses everything.
    'the single logout endpoint has a route, an address, and a settings screen that knows both' =>
        static function () use ($configureSaml): void {
            $basePath = dirname((string)(new ReflectionClass(Plugin::class))->getFileName());
            $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());
            $settingsTemplate = (string)file_get_contents($basePath . '/templates/_settings.twig');

            Assert::contains("self::SLO_PATH => 'keyway-sso/sso/slo'", $source, 'the route exists');
            // Built off the registered route, never written out by hand: this string is the
            // Destination an inbound LogoutRequest is pinned against AND the Location published
            // in metadata, so an address that drifts from the route rejects every message with
            // `destination_mismatch` - a refusal that looks like an IdP fault.
            Assert::contains(
                'return self::canonicalEndpointUrl(self::SLO_PATH);',
                $source,
                'the address comes from the route'
            );
            Assert::true(method_exists(Plugin::class, 'sloUrl'), 'and is reachable from the screen');
            Assert::contains("'sloUrl' => self::sloUrl()", $source, 'the screen is given the address');
            Assert::contains("'sloReady' => self::sloReady(\$settings)", $source, 'and the same answer sso/slo will give');

            Assert::contains("name: 'samlIdpSloUrl'", $settingsTemplate, 'the IdP endpoint can be entered');
            Assert::contains('value: sloUrl,', $settingsTemplate, 'and ours can be copied out');
            Assert::contains('sloReady', $settingsTemplate, 'with wording that changes when it is off');
        },

    'the diagnostics screen has a route and a way in from the settings page' => static function (): void {
        $basePath = dirname((string)(new ReflectionClass(Plugin::class))->getFileName());
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());
        $settingsTemplate = (string)file_get_contents($basePath . '/templates/_settings.twig');

        Assert::contains("'keyway-sso/diagnostics/index'", $source, 'the route points at the action');
        Assert::contains('diagnosticsUrl', $source, 'the settings screen is given the address');
        Assert::contains('{{ diagnosticsUrl }}', $settingsTemplate, 'and links to it');

        // No nav item by design (hasCpSection is false), so that link is the only door.
        Assert::false(
            (new ReflectionClass(Plugin::class))->newInstanceWithoutConstructor()->hasCpSection,
            'a nav item would make the link optional; there is none'
        );
    },

    // ------------------------------------------------------------------------------------
    // PASSWORD FALLBACK ENFORCEMENT.
    //
    // The rule itself is in PasswordLoginGate and covered behaviourally in
    // password_login_gate_test.php. What is pinned HERE is the part no test can execute without
    // a booted CMS: that the gate is actually subscribed to Craft's authentication event, and
    // that the registration is unconditional.
    //
    // This distinction is the whole reason the case exists. Until this change AdminFallback and
    // PasswordLoginDecision were fully tested AND completely dead - nothing outside the settings
    // screen called them - so five switches on the settings screen did nothing while the suite
    // reported total success. A behavioural test of a rule proves the rule; only this proves the
    // rule is connected.
    // ------------------------------------------------------------------------------------

    'the password gate is subscribed to Craft\'s authentication event' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        Assert::contains('User::EVENT_BEFORE_AUTHENTICATE', $source, 'the gate is wired to authentication');
        Assert::contains('$this->enforcePasswordFallback($event)', $source, 'and the handler runs the gate');
        Assert::contains('PasswordLoginGate::decide(', $source, 'through the core rule, not a second copy');
        Assert::contains(
            '$account->authError = PasswordLoginGate::authError(',
            $source,
            'a refusal is expressed the way Craft stops a login'
        );

        // Craft returns false from authenticate() only when $authError is set by the handler, so
        // an enforcement that never writes it is an enforcement that does nothing at all.
        Assert::same(
            1,
            substr_count($source, '$account->authError ='),
            'exactly one place refuses, so there is one thing to read and one thing to mutate'
        );

        // Through authError(), NEVER the bare constant. Craft publishes the value as `errorCode`
        // in the JSON failure body, so writing AUTH_ERROR unconditionally would hand an
        // account-existence oracle to any installation running `preventUserEnumeration`.
        Assert::notContains(
            'authError = PasswordLoginGate::AUTH_ERROR',
            $source,
            'the code is chosen by the gate, not hard-coded past the enumeration flag'
        );
        Assert::contains(
            'preventUserEnumeration',
            $source,
            'and the flag is what it is chosen from'
        );
    },

    // The narrowing to control-panel requests must be an ARGUMENT, never a registration that is
    // skipped: a handler registered only on control-panel requests would look identical in
    // behaviour today and be untestable forever. It also has to stay out of the `if` that guards
    // the login-button hook, which is exactly such a registration.
    'the control-panel narrowing is passed to the gate, not expressed by skipping it' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        Assert::same(
            1,
            preg_match('/PasswordLoginGate::decide\\s*\\((.*?)\\);/s', $source, $matches),
            'the gate call was found at all'
        );

        Assert::contains(
            '$request->getIsCpRequest()',
            $matches[1],
            'the gate is told whether this is a control-panel request'
        );

        // The front end is the client's own shop or website. EVENT_BEFORE_AUTHENTICATE is global,
        // so without this argument the plugin would refuse member logins nobody bought it for.
        Assert::contains(
            'PasswordLoginGate::decide(',
            $source,
            'and decides from that fact rather than from where it was registered'
        );
    },

    // Craft fires the same event for passkeys (authenticateWithPasskey), where $password is null.
    // A passkey holder shut out by a switch labelled "password fallback" is a lockout in disguise.
    'a passkey is told apart from a password' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        Assert::contains('$event->password !== null', $source, 'passkeys are not password logins');
    },

    // The outer net. PasswordLoginGate fails open for anything thrown while deciding, but the
    // handler also reads the request and the sender, and an exception escaping into
    // User::authenticate() would break every login on the site - lockout by another route.
    'the handler itself fails open' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        Assert::same(
            1,
            preg_match(
                '/private function enforcePasswordFallback.*?\\n    \\}/s',
                $source,
                $matches
            ),
            'the handler was found at all'
        );

        $body = $matches[0];

        Assert::contains('try {', $body, 'the body is guarded');
        Assert::contains('catch (\\Throwable)', $body, 'against anything, not a chosen few');

        // THE ASSERTION THAT ACTUALLY DEFENDS THE PROMISE. Checking that `try` merely APPEARS is
        // worthless: a reviewer moved `$request = Craft::$app->getRequest();` above it and the
        // whole suite still passed, leaving an unguarded read whose failure propagates out of
        // User::authenticate() and breaks every login on the site. So the position is pinned -
        // nothing that can throw may be read before the guard opens.
        // Comments stripped first: the prose above `try` legitimately NAMES the things it must
        // not read, and matching on that would make this case pass or fail on wording.
        $code = (string)preg_replace('~//[^\\n]*~', '', $body);

        $guard = strpos($code, 'try {');
        Assert::notSame(false, $guard, 'the guard was located');

        $firstApp = strpos($code, 'Craft::$app');
        if ($firstApp !== false) {
            Assert::true(
                $guard < $firstApp,
                'Craft::$app is read inside the guard, never before it'
            );
        }

        $firstEvent = strpos($code, '$event->');
        if ($firstEvent !== false) {
            Assert::true(
                $guard < $firstEvent,
                'the event is inspected inside the guard, never before it'
            );
        }

        // The signature too: a TypeError raised while BINDING a narrowed parameter fires before
        // the body runs, so it would sail straight past the try block above.
        Assert::contains(
            'enforcePasswordFallback(Event $event)',
            $body,
            'the parameter is wide, and narrowed inside the guard instead'
        );
    },

    // The mapping onto ExistingUser has to be the plugin's one. A second, hand-written mapping
    // at this call site would drift from CraftUserDirectory's, and the fields it reads - admin,
    // status, locked - are the fields that decide who gets in.
    'the account is mapped with the mapping the rest of the plugin uses' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        Assert::contains('CraftUserSnapshot::map(', $source, 'the shared mapping is used');
        Assert::notContains('new ExistingUser(', $source, 'and no second mapping is built by hand');
    },

    // The bug this whole change came from was not the missing enforcement alone - it was the
    // settings screen describing a behaviour the code did not have. "Hides password login on the
    // control panel" was false before this change (nothing was enforced) and would still be false
    // after it (the form is refused on submit, not hidden), so it is pinned as forbidden wording
    // rather than left to be noticed again by a reviewer.
    'the settings screen does not promise to hide the password form' => static function (): void {
        $basePath = dirname((string)(new ReflectionClass(Plugin::class))->getFileName());
        $settingsTemplate = (string)file_get_contents($basePath . '/templates/_settings.twig');

        Assert::same(
            1,
            preg_match('/forms\\.lightswitchField\\(\\{[^}]*?name: .ssoOnly./s', $settingsTemplate, $matches),
            'the SSO-only switch was found at all'
        );

        Assert::notContains('Hides password login', $matches[0], 'the form is refused, not hidden');
        Assert::contains('Refuses password sign-in', $matches[0], 'and the screen says what happens');
        Assert::contains('control panel', $matches[0], 'including where it happens');
    },

    'a refusal gets a truthful message instead of "invalid password"' => static function (): void {
        $source = (string)file_get_contents((new ReflectionClass(Plugin::class))->getFileName());

        Assert::contains('UsersController::EVENT_LOGIN_FAILURE', $source, 'the message hook is wired');
        Assert::contains('PasswordLoginGate::failureMessage(', $source, 'and the decision is the core\'s');
        Assert::contains('preventUserEnumeration', $source, 'including whether it may be specific at all');
    },
];

// The one case here that needs ext-openssl: without it the save-time certificate check accepts
// everything by design (IdpCertificate), so asserting a refusal would assert the opposite of
// the rule. Skipped out loud - a case that returns early reports itself as green while checking
// nothing, which is the same as not having it.
if (!extension_loaded('openssl')) {
    fwrite(STDOUT, sprintf(
        "%-26s %s\n",
        'craft_layer',
        'skipped (certificate case): ext-openssl absent'
    ));

    return $cases;
}

return $cases + [
    // The certificate problem has to land ON THE CERTIFICATE FIELD, and only the Craft layer
    // can prove it: Settings::validateConfiguration() attaches an error to the named attribute
    // only when the model declares it, and silently re-attributes it to `protocol` otherwise. A
    // misspelled key there would put "this is a private key" under the protocol dropdown.
    'a private key in the certificate field fails validation on that field'
        => static function () use ($configureSaml): void {
            $settings = $configureSaml(new Settings());
            $settings->samlIdpCertificate = CertificateFixtures::privateKeyBody();

            Assert::false($settings->validate());
            Assert::contains('PRIVATE KEY', implode(' ', $settings->getErrors('samlIdpCertificate')));
            Assert::sameList([], $settings->getErrors('protocol'), 'not on the dropdown');
        },
];
