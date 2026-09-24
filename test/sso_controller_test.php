<?php

declare(strict_types=1);

use Keyway\Sso\Core\Login\LoginRefusal;
use Keyway\Sso\Plugin;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\controllers\SsoController;
use craft\web\Controller;

/**
 * The sign-in controller, checked WITHOUT booting Craft - which is the only honest way to check
 * it, and a smaller claim than it looks.
 *
 * The controller is a translator: every decision it would otherwise make was pushed into a class
 * that has its own suite (LoginFlow for the refusals and the start guard, CraftCookie for the
 * cookie mapping, SsoLoginButton for the button, CraftSignIn for the account write). What is
 * left in the file is four rules that CANNOT be moved anywhere, because they are properties of
 * the file itself - the order of two statements, a flag, a constant. They are asserted here, on
 * the source, rather than described in a docblock and hoped for:
 *
 *  1. the binding cookie is added to the response BEFORE the redirect is returned;
 *  2. the binding is cleared on EVERY path out of the callback, not only the refusals;
 *  3. CSRF validation is turned off for the SAML callback and for nothing else;
 *  4. the visitor is shown PUBLIC_MESSAGE and never a reason.
 *
 * WHAT THIS FILE DOES NOT AND CANNOT VERIFY, stated plainly so nobody mistakes a green line for
 * coverage: that Yii sends the cookie, that the redirect reaches the browser, that Craft resolves
 * the routes, that the assertion POST survives CSRF being off. Those need a running CMS and an
 * identity provider, and they are the acceptance test, not a unit test.
 */
if (!class_exists(Controller::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'sso_controller', 'skipped: vendor absent (run composer install)'));

    return [];
}

/** The controller's source with comments removed: prose about a rule is not the rule. */
$code = static function (): string {
    $source = (string)file_get_contents(
        (string)(new ReflectionClass(SsoController::class))->getFileName()
    );

    $stripped = '';
    foreach (token_get_all($source) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }

        $stripped .= is_array($token) ? $token[1] : $token;
    }

    return $stripped;
};

/** @return array<string, string> */
$routes = static function (): array {
    $property = new ReflectionClassConstant(Plugin::class, 'CP_ROUTES');

    /** @var array<string, string> $value */
    $value = $property->getValue();

    return $value;
};

return [
    // Craft derives the controller namespace from the plugin class as `<Namespace>\controllers`,
    // lower-cased (craft\base\Plugin::__construct). On a case-sensitive filesystem, PSR-4 then
    // demands `src/controllers/` - `src/Controllers/` autoloads nowhere and the routes 404.
    'the controller sits where Craft will look for it' => static function (): void {
        $class = new ReflectionClass(SsoController::class);

        Assert::same('Keyway\Sso\controllers', $class->getNamespaceName());
        Assert::true(is_subclass_of(SsoController::class, Controller::class));
        Assert::same(
            'controllers',
            basename(dirname((string)$class->getFileName())),
            'PSR-4 maps the lower-cased namespace to a lower-cased directory'
        );
    },

    'every action is reachable by a guest, live and offline' => static function (): void {
        $anonymous = (new ReflectionClass(SsoController::class))
            ->getDefaultProperties()['allowAnonymous'];

        $both = Controller::ALLOW_ANONYMOUS_LIVE | Controller::ALLOW_ANONYMOUS_OFFLINE;

        // Offline is not an oversight: an administrator who took the system offline still has to
        // be able to sign in and bring it back. Craft's own login actions carry the same pair.
        // `metadata` joins them for a different reason, and it is worth stating so that nobody
        // "tightens" it later: SAML metadata is a public document (entity id, ACS address,
        // and nothing an attacker could use), several identity providers re-fetch it on a
        // schedule with no session, and behind a login it would only ever return the login
        // screen. An unconfigured site answers 404, not an empty document.
        // `slo` joins them for yet another reason: the browser arriving there has just been
        // logged out by the identity provider, or never had a session here at all. A logout
        // endpoint behind a login could never answer the one message it exists for - and it
        // ends nothing on its own say-so anyway, because InboundLogoutFlow matches the subject
        // first.
        foreach (['start', 'acs', 'callback', 'metadata', 'slo'] as $action) {
            Assert::same($both, $anonymous[$action] ?? null, $action . ' is anonymous');
        }

        Assert::same(5, count($anonymous), 'no action is anonymous by accident');
    },

    'the metadata action serves a document as a file, or nothing at all' =>
        static function () use ($code, $routes): void {
            $source = $code();

            Assert::true(method_exists(SsoController::class, 'actionMetadata'));
            Assert::same(
                'keyway-sso/sso/metadata',
                $routes()['sso/metadata'] ?? null,
                'the registered route reaches this action'
            );

            // Fail closed, and with the honest status: a site that is not a SAML service
            // provider has no metadata, and an empty-but-valid document would be worse than a
            // 404 - an identity provider would accept it and be configured against endpoints
            // that never match.
            Assert::contains('throw new NotFoundHttpException(', $source);
            Assert::contains('$metadata === null', $source, 'the refusal is the null document');

            // A file, not a page: the administrator uploads this into Okta or Keycloak.
            Assert::contains('Response::FORMAT_RAW', $source, 'no JSON or HTML wrapping');
            Assert::contains('$this->response->data = $metadata->toXml();', $source, 'the body IS the document');
            Assert::contains('application/samlmetadata+xml', $source, 'the media type SAML registers');
            Assert::contains('attachment; filename="%s"', $source, 'and it downloads rather than renders');
            Assert::contains(
                'SpMetadata::fileName($metadata->entityId())',
                $source,
                'the file name comes from the document, so a header can never disagree with it'
            );
        },

    'CSRF validation is disabled for the two SAML entrances and nothing else' =>
        static function () use ($code): void {
            $source = $code();

            // Both carry a message written by the identity provider: `acs` a cross-site POST
            // from its form, `slo` a redirect it sends the browser. Neither can carry this
            // site's token, and a signature over the message stands in place of it.
            Assert::contains("\$action->id === 'acs' || \$action->id === 'slo'", $source);
            Assert::same(
                1,
                substr_count($source, 'enableCsrfValidation = false'),
                'one branch, both entrances - and nothing else gives up the check'
            );

            // The start action and the OIDC callback are GETs, which Yii never validates anyway;
            // turning the flag off for them would weaken them for no gain.
            Assert::notContains("\$action->id === 'start'", $source);
            Assert::notContains("\$action->id === 'callback'", $source);
        },

    // The rule LoginStart's own docblock puts on the controller: "a redirect sent first, cookie
    // second, is a login that starts unbound and fails at the callback". Both statements write
    // to `$this->response`, so the only way to get it wrong is to write them in the wrong order.
    'the binding cookie is set before the redirect is returned' => static function () use ($code): void {
        $source = $code();
        $start = strpos($source, 'public function actionStart');
        Assert::true($start !== false);

        $body = substr($source, (int)$start, (int)strpos($source, 'public function actionAcs') - (int)$start);

        $cookie = strpos($body, 'getCookies()->add(');
        $redirect = strpos($body, '$this->redirect(');

        Assert::true($cookie !== false, 'the start sets the binding cookie');
        Assert::true($redirect !== false, 'the start redirects');
        Assert::true((int)$cookie < (int)$redirect, 'cookie first, redirect second, one response');
    },

    // LoginCompletion::$clearBinding is non-nullable precisely so this is not a judgement call.
    // A binding cookie left behind arrives at the NEXT login, where it can only be wrong.
    'the binding is cleared before any way out of the callback' => static function () use ($code): void {
        $source = $code();
        $body = substr($source, (int)strpos($source, 'private function finish('));

        $clear = strpos($body, 'clearBinding');
        $firstReturnAfterComplete = strpos($body, 'if (!$completion->allowed)');

        Assert::true($clear !== false, 'the callback clears the binding');
        Assert::true(
            (int)$clear < (int)$firstReturnAfterComplete,
            'the cookie comes off before the first refusal can return'
        );
    },

    // The link can only be written after CraftSignIn has created the account and produced an
    // id, so this is an ORDER rule inside one method - a property of the file, like the two
    // above, and therefore checked the same way. Written before the redirect as well, because
    // a `return` in between would skip it on exactly the path that needs it.
    'the account\'s origin is recorded after the sign-in and before the redirect' =>
        static function () use ($code): void {
            $body = substr($code(), (int)strpos($code(), 'private function finish('));

            $signIn = strpos($body, '->signIn()->signIn($decision)');
            $link = strpos($body, 'IdentityLink::afterSignIn(');
            $remember = strpos($body, '->identityLinks()->remember(');
            $redirect = strrpos($body, '$this->redirect(');

            Assert::true($signIn !== false, 'the decision is carried out');
            Assert::true($link !== false, 'the rule for writing a link is IdentityLink\'s, not this file\'s');
            Assert::true($remember !== false, 'and the link is actually written');
            Assert::true((int)$signIn < (int)$link, 'the user id does not exist before the sign-in');
            Assert::true((int)$remember < (int)$redirect, 'nothing returns between the two');

            // The controller must not re-derive the rule: no second reading of the action, no
            // "if it looks like a create" of its own.
            Assert::notContains('ProvisioningAction::Create', $body);
        },

    'the visitor is never told why' => static function () use ($code): void {
        $source = $code();

        Assert::contains('LoginRefusal::PUBLIC_MESSAGE', $source);
        Assert::notContains('$completion->message', $source);
        Assert::notContains('$start->message', $source);

        // One sentence for every cause, or the wording itself is the oracle.
        Assert::same(
            1,
            substr_count($source, 'PUBLIC_MESSAGE'),
            'one public sentence, rendered in one place'
        );
        Assert::contains('sign you in with single sign-on', LoginRefusal::PUBLIC_MESSAGE);
    },

    // `Craft::$app` is read in Plugin and nowhere deeper; the controller takes the ONE runtime
    // the plugin built. Two runtimes in a request means two discovery fetches and two objects
    // each believing they own the single-use claim.
    'the controller takes the plugin\'s runtime rather than assembling its own' =>
        static function () use ($code): void {
            $source = $code();

            Assert::contains('Plugin::getInstance()->loginRuntime()', $source);
            Assert::notContains('new CraftLoginRuntime', $source);
            Assert::notContains('Craft::$app', $source);
        },

    // Widened when the diagnostics screen added the plugin's SECOND controller and
    // this case failed on `sso/diagnostics` - correctly: the assertion had the controller name
    // hard-coded as 'sso'. The rule being checked was never "everything routes to SsoController",
    // it was "no registered route points at an action nobody wrote", which is the failure Craft
    // reports as a 404 at the exact moment somebody follows a link on the settings screen.
    // Resolving the class from the route segment keeps that rule and drops the accidental part.
    'every registered control panel route points at an action that exists' =>
        static function () use ($routes): void {
            foreach ($routes() as $path => $route) {
                $segments = explode('/', $route);
                $studly = static fn (string $part): string => str_replace(
                    ' ',
                    '',
                    ucwords(str_replace('-', ' ', $part))
                );

                Assert::same('keyway-sso', $segments[0], $path . ' routes into this plugin');

                $controller = 'Keyway\\Sso\\controllers\\' . $studly($segments[1]) . 'Controller';

                Assert::true(
                    class_exists($controller),
                    $route . ' names a controller class that exists (' . $controller . ')'
                );
                Assert::true(
                    method_exists($controller, 'action' . $studly($segments[2])),
                    $route . ' has an action behind it'
                );
            }
        },

    // Craft answers `loginRequired()` for a GUEST on any non-action control-panel request whose
    // first segment is a plugin handle, before routing happens (craft\web\Application). A
    // callback under `keyway-sso/...` would therefore bounce the identity provider's POST to the
    // login screen - and the callback is the one request guaranteed to have no session.
    'no control panel route starts with the plugin handle' => static function () use ($routes): void {
        foreach (array_keys($routes()) as $path) {
            Assert::notSame('keyway-sso', explode('/', $path)[0], $path . ' would be intercepted');
        }
    },

    // The mechanism the button depends on, pinned to Craft's own shipped template rather than to
    // our memory of it. If a Craft upgrade renames or removes this hook, the button silently
    // stops rendering - and this line is what says so.
    'the login screen hook this plugin uses still exists in Craft' => static function (): void {
        $template = dirname(__DIR__)
            . '/vendor/craftcms/cms/src/templates/_special/login.twig';

        if (!is_file($template)) {
            // Visible, not silent: a case that returns without asserting reads as green in the
            // runner output, which is exactly how a regression gets shipped.
            fwrite(STDOUT, sprintf(
                "\n%-26s %s\n",
                'sso_controller',
                'login.twig not in vendor/: the button mechanism was not verified'
            ));

            return;
        }

        Assert::contains(
            "{% hook '" . Plugin::LOGIN_BUTTON_HOOK . "' %}",
            (string)file_get_contents($template),
            'the alternative-login-methods hook is how anything gets onto that screen'
        );
    },
];
