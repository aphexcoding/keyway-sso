<?php

declare(strict_types=1);

namespace Keyway\Sso\controllers;

use craft\web\Controller;
use craft\web\View;
use Keyway\Sso\Adapter\CraftCookie;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\IdentityLink;
use Keyway\Sso\Core\Login\LoginRefusal;
use Keyway\Sso\Core\Logout\LogoutDecision;
use Keyway\Sso\Core\Logout\SessionSubject;
use Keyway\Sso\Core\Support\SystemClock;
use Keyway\Sso\Plugin;
use Keyway\Sso\Protocol\Saml\SpMetadata;
use Throwable;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * The three URLs single sign-on needs: start a login, take a SAML assertion back, take an OIDC
 * code back.
 *
 * DELIBERATELY A TRANSLATOR AND NOTHING ELSE. Every question with an answer worth arguing about
 * was decided before this file runs: LoginFlow says "redirect here, set this cookie" or "refuse,
 * and here is the reason code", and CraftSignIn carries out the provisioning decision. What is
 * left here is turning values into a `yii\web\Response`. That is the whole reason this class is
 * not covered by `php bin/test.php` - testing it would mean booting a CMS, and there is nothing
 * in it a CMS would reveal. The rules that USED to live in a class like this one live in
 * Core\Login (the refusal codes and the start guard), Adapter\CraftCookie (the cookie mapping),
 * Adapter\SsoLoginButton (when the button appears) and Adapter\CraftSignIn (the account write).
 *
 * ------------------------------------------------------------------------------------------
 * THE NAME, AND WHY IT IS NOT src/Controllers/LoginController.php
 * ------------------------------------------------------------------------------------------
 *
 * `craft\base\Plugin::__construct()` derives the controller namespace from the plugin class as
 * `<Namespace>\controllers` - lower-cased, not `Controllers` - so on a case-sensitive filesystem
 * with PSR-4 the directory has to be `src/controllers/`. The controller ID follows from the
 * class name: `SsoController` is `sso`, which makes the action routes `keyway-sso/sso/start`,
 * `keyway-sso/sso/acs` and `keyway-sso/sso/callback`. Those are the addresses the rest of this
 * plugin already assumed - the ACS URL in the settings screen's examples and in the test
 * fixtures - and changing them now would break every configuration written against them.
 *
 * ------------------------------------------------------------------------------------------
 * ANONYMOUS ACCESS AND CSRF - DECIDED PER ACTION, NOT IN ONE SWEEP
 * ------------------------------------------------------------------------------------------
 *
 * All three actions are anonymous, LIVE and OFFLINE both. The offline half is not an oversight:
 * an administrator who takes the system offline still has to be able to sign in to bring it
 * back, and Craft's own login actions carry exactly the same pair (`UsersController`).
 *
 * CSRF is a different question for each:
 *
 *  - `start` KEEPS CSRF validation on. It is a GET link, so Yii never validates a token for it
 *    anyway; leaving the flag alone means that if somebody ever POSTs to it, the check is there.
 *    Turning it off "to match the callbacks" would weaken an action that has no reason to be
 *    weakened.
 *  - `callback` (OIDC) KEEPS CSRF validation on, for the same reason: it is a top-level GET
 *    redirect, which Yii does not validate, and the flag costs nothing.
 *  - `acs` (SAML) TURNS CSRF VALIDATION OFF, and it has to. An HTTP-POST binding assertion is a
 *    cross-site POST submitted by a form on the identity provider's own domain; that form cannot
 *    contain this site's CSRF token, and there is no version of this flow in which it could.
 *    Craft's own SSO controller does the same (`craft\controllers\SsoController`).
 *
 * WHY THAT IS NOT A HOLE, which is the part worth writing down. A CSRF token answers "did this
 * request come from a page of ours". This callback answers the same question three times over,
 * with stronger evidence: the assertion is SIGNED by the identity provider and checked against
 * the configured certificate; the RelayState is a single-use, unguessable, short-lived token this
 * site issued minutes ago and burns on use; and the browser binding requires the browser posting
 * the assertion to be the one that started the login (a 32-byte secret in a cookie, compared with
 * `hash_equals` against a SHA-256 in the state). An attacker who could forge all three does not
 * need a CSRF token. What the CSRF check would actually stop here - a login-CSRF, where the
 * attacker holds a valid response and wants a victim's browser to submit it - is what the
 * browser binding exists for, and it stays on whether or not CSRF validation is enabled.
 */
class SsoController extends Controller
{
    /**
     * Where a login may be sent back to, if the caller asks. The value is not trusted: the core's
     * RedirectGuard is what decides whether it survives into the login state.
     */
    public const RETURN_URL_PARAM = 'return';

    /**
     * @inheritdoc
     */
    protected array|bool|int $allowAnonymous = [
        'start' => self::ALLOW_ANONYMOUS_LIVE | self::ALLOW_ANONYMOUS_OFFLINE,
        'acs' => self::ALLOW_ANONYMOUS_LIVE | self::ALLOW_ANONYMOUS_OFFLINE,
        'callback' => self::ALLOW_ANONYMOUS_LIVE | self::ALLOW_ANONYMOUS_OFFLINE,
        'metadata' => self::ALLOW_ANONYMOUS_LIVE | self::ALLOW_ANONYMOUS_OFFLINE,
        // Anonymous because the browser arriving here has already been logged out by the IdP, or
        // belongs to somebody with no session at all. A logout endpoint behind a login is an
        // endpoint that can never answer the one message it exists for.
        'slo' => self::ALLOW_ANONYMOUS_LIVE | self::ALLOW_ANONYMOUS_OFFLINE,
    ];

    /**
     * @inheritdoc
     */
    public function beforeAction($action): bool
    {
        if ($action->id === 'acs' || $action->id === 'slo') {
            // Only here, and only because the identity provider's own message cannot carry our
            // token - `acs` is a cross-site POST from the IdP's form, `slo` a redirect the IdP
            // sends the browser. What stands in place of the token is stronger in both cases: a
            // signature over the message, checked against the configured certificate. For `slo`
            // it is also a single-use id (the replay guard), a pinned Destination and a time
            // window - and, crucially, the subject match in InboundLogoutFlow, which is what
            // makes a forged request unable to end anybody's session even if it arrived.
            $this->enableCsrfValidation = false;
        }

        return parent::beforeAction($action);
    }

    /**
     * Sends the visitor to the identity provider.
     */
    public function actionStart(): Response
    {
        $flow = Plugin::getInstance()->loginRuntime()->loginFlow();

        if ($flow === null) {
            return $this->refuse();
        }

        $start = $flow->begin(self::stringOrNull($this->request->getParam(self::RETURN_URL_PARAM)));

        if (!$start->started) {
            // `publicMessage()`, never `message`: the reason is already on the diagnostics
            // timeline, and the wording a visitor sees must not vary with the cause.
            return $this->refuse();
        }

        if ($start->cookie !== null) {
            // THE COOKIE GOES ON FIRST, ON THE SAME RESPONSE AS THE REDIRECT. Both statements
            // write to `$this->response`, and `redirect()` returns that same object, so the
            // browser receives one response carrying both. A redirect sent before the cookie is
            // a login that starts unbound and fails at the callback with `binding_cookie_missing`
            // - which reads like a proxy stripping cookies and is not.
            $this->response->getCookies()->add(CraftCookie::from($start->cookie, new SystemClock()));
        }

        return $this->redirect((string)$start->redirectUrl);
    }

    /**
     * SAML HTTP-POST binding: the assertion consumer service.
     */
    public function actionAcs(): Response
    {
        return $this->finish($this->request->getBodyParams());
    }

    /**
     * OIDC redirect URI: the authorization code comes back in the query string.
     */
    public function actionCallback(): Response
    {
        return $this->finish($this->request->getQueryParams());
    }

    /**
     * The SP metadata document, as a file an administrator can upload into their identity
     * provider - or a 404 when this site has nothing to publish.
     *
     * ANONYMOUS, AND THAT IS THE POINT rather than an oversight. SAML metadata is a public
     * document by design: it carries the entity id, the ACS address and (when a site has one)
     * the SP certificate - every one of them a value the identity provider is going to be told
     * anyway, and none of them a secret. Several providers fetch it themselves on a schedule,
     * with no session; behind a login it would be a URL that only ever returns the login screen.
     * What it deliberately does NOT carry is any part of the configuration an attacker could use:
     * no IdP certificate, no private key, no attribute or group rules, no diagnostics.
     *
     * 404 AND NOT AN EMPTY DOCUMENT when SAML is off or half-configured. `spMetadata()` returns
     * null rather than a document naming a blank entity id (see SettingsTranslator::spMetadata),
     * and the honest HTTP answer for "this site is not a SAML service provider" is that the
     * address does not exist. An empty-but-valid document would be worse than silence: an IdP
     * would accept it and be configured against endpoints that never match.
     */
    public function actionMetadata(): Response
    {
        $metadata = Plugin::getInstance()->getSettings()->spMetadata(null, Plugin::sloUrl());

        if ($metadata === null) {
            throw new NotFoundHttpException('This site does not publish SAML service provider metadata.');
        }

        // `application/samlmetadata+xml` is the media type SAML 2.0 Metadata section 4.1
        // registers for this document; providers that sniff the type expect it, and the ones
        // that do not are happy with any XML.
        $this->response->format = Response::FORMAT_RAW;
        $this->response->data = $metadata->toXml();
        $this->response->getHeaders()
            ->set('Content-Type', 'application/samlmetadata+xml; charset=UTF-8')
            ->set(
                'Content-Disposition',
                sprintf('attachment; filename="%s"', SpMetadata::fileName($metadata->entityId()))
            );

        return $this->response;
    }

    /**
     * SAML HTTP-Redirect binding: the identity provider's LogoutRequest.
     *
     * A TRANSLATOR, like the rest of this class. Reading and verifying the message is
     * SamlLogoutRequestReader's job, deciding whose session may be ended is InboundLogoutFlow's,
     * and phrasing the answer is SamlLogoutResponse's. What is left here is a query string in
     * and a redirect out.
     *
     * HTTP-Redirect AND NOTHING ELSE. A POST-bound LogoutRequest is a differently shaped
     * verification (canonicalisation, pinning the Reference, the XSW surface) and adding it
     * without tests would be adding an untested entrance to session termination. The metadata
     * document advertises only this binding, so a correctly behaving IdP never tries the other.
     *
     * THE RAW QUERY STRING, never `getQueryParams()`: the signature covers the octets exactly as
     * they were sent, and PHP's parser re-encodes them. SamlLogoutMessageReader says so at
     * length and refuses to work from an array.
     */
    public function actionSlo(): Response
    {
        $plugin = Plugin::getInstance();

        // INSIDE the try, all of it. logoutFlow() is not a bare `new`: it reads Craft's user
        // component, its session and the diagnostics runtime, and any of the three can throw on
        // a broken install. Assembled above the try it would produce the exact failure the try
        // exists to prevent - HTTP 500 on a public URL, with a stack trace whenever devMode is
        // on - and it would do it before a single line of our own code had run.
        $flow = null;

        try {
            $flow = $plugin->logoutFlow();
            $request = $plugin->logoutReader()->read((string)($_SERVER['QUERY_STRING'] ?? ''));
            $decision = $flow->apply($request);
        } catch (Throwable $error) {
            // WITHOUT THIS, a rotated certificate or a malformed query is an uncaught exception
            // on a public URL. The mapping to a reason code and a diagnostics line lives in the
            // flow, where it is tested.
            //
            // `?->` because the flow is what may have failed to build: when the diagnostics
            // runtime itself is the fault there is nowhere to write the note, and the visitor
            // still gets an ordinary refusal rather than a stack trace.
            $flow?->refused($error);

            return $this->refuse();
        }

        try {
            $answer = $plugin->logoutAnswer();

            $redirect = match ($decision->answer) {
                LogoutDecision::ANSWER_SUCCESS => $answer->success($request),
                LogoutDecision::ANSWER_PARTIAL => $answer->partialLogout($request),
                LogoutDecision::ANSWER_UNKNOWN_PRINCIPAL => $answer->unknownPrincipal($request),
                default => $answer->responderError($request),
            };
        } catch (Throwable $error) {
            // The session may already be gone at this point, so there is nothing to undo - but
            // the operator still has to see why the IdP never got an answer.
            $flow->refused($error);

            return $this->refuse();
        }

        return $this->redirect($redirect->url());
    }

    /**
     * @param array<string, mixed> $callback Raw callback input, exactly as it arrived.
     */
    private function finish(array $callback): Response
    {
        $runtime = Plugin::getInstance()->loginRuntime();
        $flow = $runtime->loginFlow();

        if ($flow === null) {
            return $this->refuse();
        }

        // Read through the cookie collection, never `$_COOKIE`: Craft signs cookies on the way
        // out and validates them on the way in, and a raw read would see the signature and
        // compare it against the binding hash.
        $completion = $flow->complete(
            $callback,
            self::stringOrNull($this->request->getCookies()->getValue(BrowserBinding::COOKIE_NAME))
        );

        // BEFORE ANYTHING CAN RETURN. The binding cookie is worthless the moment the state is
        // burnt, and one left on the browser is one that arrives at the next login, where it can
        // only be wrong. LoginCompletion::$clearBinding is non-nullable for exactly this reason -
        // so that "did this path need it?" is never a judgement call made here. What the
        // controller CANNOT guarantee is that the browser honours it: a deletion only removes a
        // cookie stored under the same path, and LoginFlow::clearTargetConnection() explains the
        // one case (several connections, unidentifiable callback) where that path is a guess.
        $this->response->getCookies()->add(CraftCookie::from($completion->clearBinding, new SystemClock()));

        if (!$completion->allowed) {
            return $this->refuse();
        }

        $decision = $completion->decision();
        $protocol = $completion->event?->protocol ?? 'unknown';

        if ($decision === null) {
            // Unreachable: LoginCompletion::allow() is only built from a decision. Kept because
            // the alternative to a refusal here is signing somebody in with no decision behind it.
            $runtime->diagnostics()->recordFailure(
                $protocol,
                DiagnosticEvent::STAGE_SESSION,
                LoginRefusal::DECISION_MISSING,
                'A login was allowed without a provisioning decision behind it and was refused.'
            );

            return $this->refuse();
        }

        $result = Plugin::getInstance()->signIn()->signIn($decision);

        foreach ($result->notes() as $note) {
            $runtime->diagnostics()->recordNotice(
                $protocol,
                DiagnosticEvent::STAGE_PROVISIONING,
                LoginRefusal::PROVISIONING_INCOMPLETE,
                $note
            );
        }

        if (!$result->ok) {
            $runtime->diagnostics()->recordFailure(
                $protocol,
                DiagnosticEvent::STAGE_SESSION,
                $result->reasonCode,
                $result->message
            );

            return $this->refuse();
        }

        // The subject of THIS session, written down for single logout to match against later -
        // the same two values the identity link is written from, so both sides of that later
        // comparison share one normalisation.
        //
        // THE try IS AROUND THE CONSTRUCTION, NOT THE WRITE. `remember()` never throws by the
        // port's contract, but `logoutSession()` builds the adapter out of two Craft components
        // and that contract says nothing about them. The person is signed in at this point: a
        // bookkeeping fault here must cost them a future logout match, never the session they
        // just legitimately obtained.
        if ($completion->subject !== null && $completion->subject !== '') {
            try {
                Plugin::getInstance()->logoutSession()->remember(
                    new SessionSubject($completion->subject, $completion->sessionIndex)
                );
            } catch (Throwable) {
                // Deliberately silent and deliberately last-resort: the diagnostics runtime is
                // one of the things that could have failed. current() answers null afterwards,
                // so a later LogoutRequest gets an honest unknownPrincipal.
            }
        }

        // THE ACCOUNT'S ORIGIN IS WRITTEN DOWN HERE, AND ONLY HERE, because this is the first
        // moment it can be: the link needs Craft's user id, which does not exist until the
        // account has been created a few lines above. IdentityLink owns the rule for when a
        // link may be written (created, not merely linked) - a rule with security weight has no
        // business living in a file nobody can test without booting a CMS. Without this call
        // the next login for this person is refused with `linking_disabled`, which is the bug
        // measured against a live Craft with Okta on 2026-09-15.
        $link = IdentityLink::afterSignIn($completion, $result->userId);

        if ($link !== null) {
            // Never throws by contract (IdentityLinkStoreInterface), because the person is
            // already signed in at this point and a failed bookkeeping write must not take
            // their session away.
            Plugin::getInstance()->identityLinks()->remember($link->userId, $link->issuer, $link->subject);
        }

        // The login state's return URL wins: it was captured when the login started and has
        // already been through RedirectGuard, which never hands back null - it substitutes its
        // own default path for anything it will not follow. Craft's own stored URL is the
        // fallback for the empty edge, and it is never empty either.
        $returnUrl = (string)($completion->returnUrl ?? '');

        return $this->redirect($returnUrl !== '' ? $returnUrl : (string)$result->returnUrl);
    }

    /**
     * The one page a refused visitor ever sees.
     */
    private function refuse(): Response
    {
        $this->response->setStatusCode(403);

        return $this->renderTemplate(
            'keyway-sso/_message.twig',
            ['message' => LoginRefusal::PUBLIC_MESSAGE],
            View::TEMPLATE_MODE_CP
        );
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
