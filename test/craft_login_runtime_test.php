<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftLoginRuntime;
use Keyway\Sso\Adapter\CraftStateStorage;
use Keyway\Sso\Adapter\SingleUseKeys;
use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Core\Login\LoginConnection;
use Keyway\Sso\Core\Login\LoginFlow;
use Keyway\Sso\Core\Login\LoginRefusal;
use Keyway\Sso\Core\Port\IdentityReaderInterface;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Models\Settings;
use Keyway\Sso\Plugin;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CollectingSink;
use Keyway\Sso\Test\Support\RecordingArrayCache;
use Keyway\Sso\Test\Support\RecordingMutex;
use Keyway\Sso\Test\Support\StubCraftUsers;

/**
 * The composition root: settings plus Craft's services become a login flow, or become nothing.
 *
 * Run against a REAL Yii cache and the REAL protocol readers - no application, no database, no
 * request. That is possible only because CraftLoginRuntime takes its collaborators as arguments
 * instead of reaching for `Craft::$app`, and one of the cases below asserts exactly that, at the
 * source level, because it is the property that keeps this suite able to exist.
 *
 * What is NOT exercised here: starting an OIDC login. OidcAuthorizationRequest::start() fetches
 * the discovery document first, so calling it would put a network request in the suite. The
 * OIDC half is therefore checked structurally, and the end-to-end path is checked with SAML,
 * whose reader needs nothing but the request it is handed.
 */
if (!class_exists(\yii\caching\ArrayCache::class) || !class_exists(\craft\base\Plugin::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_login_runtime', 'skipped: vendor absent (run composer install)'));

    return [];
}

if (!class_exists(\Yii::class, false)) {
    require __DIR__ . '/../vendor/yiisoft/yii2/Yii.php';
}

$cert = str_repeat('MIIC', 80);

$saml = static function (Settings $settings) use ($cert): Settings {
    $settings->protocol = AuthProtocol::Saml->value;
    $settings->samlIdpEntityId = 'https://idp.example.com/realms/keyway';
    $settings->samlIdpCertificate = $cert;
    $settings->samlIdpSsoUrl = 'https://idp.example.com/realms/keyway/protocol/saml';
    $settings->samlSpEntityId = 'https://site.example.com';
    $settings->samlAcsUrl = 'https://site.example.com/actions/keyway-sso/sso/acs';

    return $settings;
};

$oidc = static function (Settings $settings): Settings {
    $settings->protocol = AuthProtocol::Oidc->value;
    $settings->oidcIssuer = 'https://idp.example.com/realms/keyway';
    $settings->oidcClientId = 'craft-cp';
    $settings->oidcClientSecret = 's3cret';
    $settings->oidcRedirectUri = 'https://site.example.com/actions/keyway-sso/sso/callback';

    return $settings;
};

$runtime = static function (Settings $settings, ?RecordingArrayCache $cache = null): array {
    $cache ??= new RecordingArrayCache();
    $mutex = new RecordingMutex();
    $sink = new CollectingSink();

    return [
        new CraftLoginRuntime(
            $settings,
            $cache,
            $mutex,
            new StubCraftUsers(),
            $sink,
            new \Keyway\Sso\Test\Support\InMemoryIdentityLinkStore()
        ),
        $cache,
        $mutex,
        $sink,
    ];
};

/** Reads a private field out of an assembled object graph, to check the wiring from inside. */
$peek = static function (object $object, string $property): mixed {
    $reflection = new ReflectionProperty($object, $property);
    $reflection->setAccessible(true);

    return $reflection->getValue($object);
};

return [
    'a fresh install assembles nothing and leaves the login screen alone' => static function () use ($runtime): void {
        [$subject] = $runtime(new Settings());

        Assert::null($subject->loginFlow(), 'disabled means disabled');
    },

    'a half-configured connection assembles nothing rather than throwing later'
        => static function () use ($runtime): void {
            $settings = new Settings();
            $settings->protocol = AuthProtocol::Saml->value;
            $settings->samlIdpEntityId = 'https://idp.example.com/realms/keyway';
            // No certificate, no SP entity id, no ACS URL.

            Assert::null($runtime($settings)[0]->loginFlow());
        },

    'a configured SAML connection assembles a flow' => static function () use ($runtime, $saml): void {
        $flow = $runtime($saml(new Settings()))[0]->loginFlow();

        Assert::notNull($flow);
        Assert::true($flow instanceof LoginFlow);
    },

    'the flow is built once per runtime' => static function () use ($runtime, $saml): void {
        [$subject] = $runtime($saml(new Settings()));

        Assert::same(
            $subject->loginFlow(),
            $subject->loginFlow(),
            'two flows would mean two objects each believing they own the single-use claim'
        );
    },

    'the SAML connection is wired for a cross-site POST callback on the ACS URL'
        => static function () use ($runtime, $saml, $peek): void {
            $flow = $runtime($saml(new Settings()))[0]->loginFlow();
            $connections = $peek($flow, 'connections');

            Assert::sameList(['saml2'], array_keys($connections));

            /** @var LoginConnection $connection */
            $connection = $connections['saml2'];
            Assert::same(CallbackStyle::CrossSitePost, $connection->callbackStyle);
            Assert::same('https://site.example.com/actions/keyway-sso/sso/acs', $connection->callbackUrl);
            Assert::same('RelayState', $connection->stateParameter);
            Assert::same('saml2', $peek($flow, 'activeConnection'));
        },

    // The case this file used to assert the opposite of: with the AuthnRequest builder wired in,
    // the SAML button leads to the configured identity provider rather than to a refusal.
    //
    // This is the SECOND place in the suite that runs through gzdeflate(), and unlike
    // test/saml_authn_request_test.php it cannot skip the whole file - everything else here is
    // about wiring and has nothing to do with zlib. So the guard is per-case: without it a build
    // without zlib reports a fatal from somewhere inside the runtime rather than saying what is
    // missing.
    'a SAML login starts and goes to the configured identity provider'
        => static function () use ($runtime, $saml): void {
            if (!function_exists('gzdeflate')) {
                return;
            }

            $start = $runtime($saml(new Settings()))[0]->loginFlow()?->begin('/admin');

            Assert::true($start?->started ?? false, 'the SAML request builder is wired in');
            Assert::notSame(LoginRefusal::CONNECTION_CANNOT_START, $start?->reasonCode);
            Assert::contains(
                'https://idp.example.com/realms/keyway/protocol/saml?SAMLRequest=',
                (string)$start?->redirectUrl
            );
        },

    'the OIDC connection is wired for a top-level redirect and CAN start a login'
        => static function () use ($runtime, $oidc, $peek): void {
            $flow = $runtime($oidc(new Settings()))[0]->loginFlow();
            $connections = $peek($flow, 'connections');

            Assert::sameList(['oidc'], array_keys($connections));

            /** @var LoginConnection $connection */
            $connection = $connections['oidc'];
            Assert::same(CallbackStyle::TopLevelRedirect, $connection->callbackStyle);
            Assert::same('state', $connection->stateParameter);
            Assert::true($connection->canStart(), 'the OIDC request builder exists');
            Assert::same('oidc', $connection->starter()?->connection());
        },

    // The whole chain, through a real Yii cache and the real SAML reader: state issued by the
    // assembled store, read back by the assembled flow, refused by the assembled reader.
    'an end-to-end callback runs through the assembled graph' => static function () use ($runtime, $saml, $peek): void {
        [$subject, $cache] = $runtime($saml(new Settings()));
        $flow = $subject->loginFlow();

        /** @var StateStore $stateStore */
        $stateStore = $peek($flow, 'stateStore');
        $token = $stateStore->issue('/admin/entries', [
            'connection' => 'saml2',
            BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
        ]);

        Assert::true($cache->writeCount() > 0, 'the state really went through the Craft cache');

        // A callback with a valid state and no SAMLResponse: everything up to the reader worked.
        $result = $flow->complete(['RelayState' => $token->value], null);

        Assert::false($result->allowed);
        Assert::same(LoginRefusal::IDENTITY_REJECTED, $result->reasonCode);
        Assert::contains('malformed_response', $result->message);
    },

    'a callback with no state never reaches the reader' => static function () use ($runtime, $saml): void {
        $result = $runtime($saml(new Settings()))[0]->loginFlow()?->complete(['SAMLResponse' => 'x'], null);

        Assert::same(LoginRefusal::STATE_MISSING, $result?->reasonCode);
    },

    // Both single-use guarantees have to sit in the same store; CraftStateStorage's docblock
    // explains what two stores would cost. This checks the assembly actually honours it.
    'the state store and the replay guard share one cache handle'
        => static function () use ($runtime, $saml, $peek): void {
            [$subject, $cache, $mutex] = $runtime($saml(new Settings()));
            $flow = $subject->loginFlow();

            /** @var StateStore $stateStore */
            $stateStore = $peek($flow, 'stateStore');
            $storage = $peek($stateStore, 'storage');
            Assert::true($storage instanceof CraftStateStorage);
            Assert::same($cache, $peek($storage, 'cache'));

            $stateClaim = $peek($storage, 'singleUse');
            Assert::true($stateClaim instanceof SingleUseKeys);
            Assert::same($cache, $peek($stateClaim, 'cache'));
            Assert::same($mutex, $peek($stateClaim, 'mutex'), 'no mutex means no compare-and-set');

            $connections = $peek($flow, 'connections');
            $reader = $connections['saml2']->reader();
            $replayClaim = $peek($peek($reader, 'replayGuard'), 'singleUse');
            Assert::same($cache, $peek($replayClaim, 'cache'));
            Assert::same($mutex, $peek($replayClaim, 'mutex'));
        },

    // The property that lets this whole suite run without an application. A `Craft::$app` call
    // inside the runtime would undo it silently, so it is asserted rather than trusted.
    'the composition root never reaches for the running application' => static function (): void {
        // Comments stripped, because this file TALKS about `Craft::$app` at length and a naive
        // grep would pass on the prose while missing a real call, or fail on the prose while
        // the code is clean. Only executable tokens count.
        $code = '';
        foreach (token_get_all((string)file_get_contents(__DIR__ . '/../src/Adapter/CraftLoginRuntime.php')) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $code .= is_array($token) ? $token[1] : $token;
        }

        Assert::notContains('Craft::', $code, 'collaborators arrive as arguments, from Plugin');
        Assert::contains('Craft::$app->getCache()', (string)file_get_contents(__DIR__ . '/../src/Plugin.php'));
        Assert::contains('Craft::$app->getMutex()', (string)file_get_contents(__DIR__ . '/../src/Plugin.php'));
    },

    // The browser-binding gate lives in LoginFlow, so a caller that could fetch the reader could
    // walk around it. The runtime hands out the flow and nothing else.
    'the runtime exposes no way to get at a reader behind the flow' => static function (): void {
        foreach ((new ReflectionClass(CraftLoginRuntime::class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            $type = $method->getReturnType();
            $name = $type instanceof ReflectionNamedType ? $type->getName() : '';

            Assert::false(
                $name === IdentityReaderInterface::class || is_subclass_of($name, IdentityReaderInterface::class),
                $method->name . ' must not hand out a reader'
            );
        }

        // `diagnostics()` joined the list when the sign-in step moved into the Craft layer: the
        // account write and the session start need to land on the same diagnostics timeline as
        // everything LoginFlow recorded before them. A recorder is not a reader, and the
        // assertion above is what keeps the difference honest.
        Assert::sameList(
            ['__construct', 'loginFlow', 'diagnostics'],
            array_map(
                static fn (ReflectionMethod $m): string => $m->name,
                (new ReflectionClass(CraftLoginRuntime::class))->getMethods(ReflectionMethod::IS_PUBLIC)
            )
        );
    },

    'the plugin owns exactly one runtime per request' => static function (): void {
        $property = new ReflectionProperty(Plugin::class, 'loginRuntime');

        Assert::true($property->isPrivate(), 'nobody swaps the assembly from outside');

        $method = new ReflectionMethod(Plugin::class, 'loginRuntime');
        Assert::true($method->isPublic());
        Assert::same(CraftLoginRuntime::class, ($method->getReturnType())?->getName());
    },
];
