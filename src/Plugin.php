<?php

declare(strict_types=1);

namespace Keyway\Sso;

use Craft;
use craft\base\Model;
use craft\base\Plugin as BasePlugin;
use craft\controllers\UsersController;
use craft\elements\User;
use craft\enums\CmsEdition;
use craft\events\AuthenticateUserEvent;
use craft\events\LoginFailureEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\helpers\UrlHelper;
use craft\web\Request as WebRequest;
use craft\web\UrlManager;
use craft\web\View;
use Keyway\Sso\Adapter\CraftDbDiagnosticsSink;
use Keyway\Sso\Adapter\CraftDbIdentityLinkStore;
use Keyway\Sso\Adapter\CraftKeyValueCache;
use Keyway\Sso\Adapter\CraftLoginRuntime;
use Keyway\Sso\Adapter\CraftLogoutSession;
use Keyway\Sso\Adapter\CraftReplayGuard;
use Keyway\Sso\Adapter\SingleUseKeys;
use Keyway\Sso\Adapter\CraftLogDiagnosticsSink;
use Keyway\Sso\Adapter\CraftSignIn;
use Keyway\Sso\Adapter\CraftUserSnapshot;
use Keyway\Sso\Adapter\SsoLoginButton;
use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Core\Access\AdminFallback;
use Keyway\Sso\Core\Access\PasswordLoginGate;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Config\EndpointMatch;
use Keyway\Sso\controllers\SsoController;
use Keyway\Sso\Core\Logout\InboundLogoutFlow;
use Keyway\Sso\Core\Port\DiagnosticsReaderInterface;
use Keyway\Sso\Core\Support\RandomSource;
use Keyway\Sso\Core\Support\SystemClock;
use Keyway\Sso\Protocol\Saml\SamlLogoutRequestReader;
use Keyway\Sso\Protocol\Saml\SamlLogoutResponse;
use Keyway\Sso\Models\Settings;
use yii\base\Event;

/**
 * Keyway SSO - SAML 2.0 and OIDC single sign-on for the Craft control panel.
 *
 * The class `composer.json` points at through `extra.class`, and it stays as close to empty as
 * a Craft plugin can be. Everything with a rule in it is somewhere Craft is not required:
 *
 *   Craft  ->  Keyway\Sso\Config  ->  Keyway\Sso\Core  +  Keyway\Sso\Protocol
 *
 * and never the other way round. `Core\` has no Composer dependency at all, which is what lets
 * `php bin/test.php` verify the security-critical half of this plugin on a host with no
 * `vendor/` directory, no database and no Craft installation.
 *
 * This file therefore only DECLARES and WIRES: the settings model, the settings screen, the
 * control-panel routes, the login-screen hook, and the two assemblies (CraftLoginRuntime,
 * CraftSignIn) that need Craft's services. It owns no rule of its own. The sign-in controller,
 * the button markup, the cookie mapping and every decision behind them are separate classes,
 * because a plugin class that owns behaviour is a plugin class that can only be tested by
 * booting a CMS.
 *
 * The one rule the wiring below follows: `Craft::$app` is read HERE and nowhere deeper.
 * CraftLoginRuntime takes its collaborators as arguments precisely so that the assembly can be
 * inspected without an application, and a `Craft::$app` call inside it would quietly undo that.
 *
 * @method Settings getSettings()
 * @property-read Settings $settings
 */
class Plugin extends BasePlugin
{
    /**
     * Bump this whenever a versioned migration is added - `craft up` runs nothing without it.
     *
     * 1.0.0 -> 1.1.0 (2026-09-16, m260916_101500_add_identity_links_table): the `keyway_sso_links`
     * table. The earlier docblock here argued that versioned migrations were unnecessary because
     * "nobody has this plugin, so Install.php covers the whole population". THAT WAS FALSE AND IT
     * COST A BUG: the installation the missing-link fault was measured on is a live Craft with
     * Okta that has had this plugin installed for weeks. On it, Install.php had already run,
     * `craft up` compared 1.0.0 with 1.0.0, did nothing, and the table the fix depends on was
     * never created - so the fix did not reach the only site that needed it.
     *
     * The rule, stated as it should have been: an installed plugin only ever receives schema
     * changes through a versioned migration plus this number. `Install.php` is for NEW
     * installations; every table it gains must also arrive as an `m*` migration for the ones
     * that already exist.
     */
    public string $schemaVersion = '1.1.0';

    /**
     * Craft Team: Solo cannot hold the accounts this plugin creates - and NOT Pro, even though
     * one feature of the plugin does need Pro.
     *
     * Measured in Craft 5 rather than assumed, because the default of this property is `Solo`
     * and a plugin that provisions accounts must not inherit it. Method names below, deliberately
     * without line numbers: they are somebody else's file, shipped to customers who upgrade Craft
     * on their own schedule, and a stale line number reads as a lie.
     *
     *  - SOLO IS OUT. `Users::getMaxUsers()` allows one account on Solo and `User::beforeSave()`
     *    refuses to create another past that ceiling, so just-in-time provisioning has nowhere to
     *    provision. Single sign-on for a single account is not a product.
     *  - TEAM WORKS, checked feature by feature rather than inferred from the one limit below.
     *    Sign-in, just-in-time accounts (up to Team's five), attribute mapping, the
     *    refuse-unless-mapped rule and the admin rule all run there. The refusal rule compares
     *    PROVIDER groups against the mapping configured on our own settings screen and never
     *    touches Craft's group table; admin is a plain column on the user that Craft gates on no
     *    edition at all. Team additionally answers `accessCp` for every account
     *    (`UserPermissions::doesUserHavePermission()`) and puts each saved account into its single
     *    built-in group (`User::afterSave()`).
     *  - ONE FEATURE NEEDS PRO: writing Craft group memberships. Below Pro there is nothing to map
     *    provider groups ONTO - `UserGroups::saveGroup()` refuses every group but the one built-in
     *    Team group, `UserGroups::getAllGroups()` returns that one (none on Solo), and on the
     *    account itself `User::getGroups()` returns `[]` while `isInGroup()` answers false.
     *    CraftSignIn is told about this and leaves membership untouched rather than writing an
     *    empty set, and the settings screen says so when a mapping is configured.
     *
     * Declaring `Pro` here would overstate the requirement and turn away buyers for whom
     * everything but one feature works. `Team` states the real floor; the degradation is said
     * next to the feature, which is where somebody will actually read it.
     *
     * WHAT THIS VALUE ACTUALLY DOES, since it is easy to over-read: Craft turns it into a
     * control-panel alert - "Keyway SSO requires Craft CMS Team edition" (`craft\helpers\Cp`) -
     * and nothing else. It does not block installation, which is exactly why the plugin raises
     * its own, narrower warning about group mapping. It has to be right BEFORE a release is
     * tagged: afterwards it can only be changed by tagging another one.
     */
    public CmsEdition $minCmsEdition = CmsEdition::Team;

    /**
     * The one place Craft's control-panel login screen lets anything else in
     * (`_special/login.twig`). See loginButtonHtml() for why nothing else works.
     */
    public const LOGIN_BUTTON_HOOK = 'cp.login.alternative-login-methods';

    /**
     * The settings screen is the whole product for a site owner: certificate, mapping, and the
     * switch that decides whether a password still works.
     */
    public bool $hasCpSettings = true;

    /**
     * No nav item. The diagnostics panel will live under Settings, next to the configuration it
     * explains, rather than taking a slot in the global navigation of every install.
     */
    public bool $hasCpSection = false;

    /**
     * The control-panel URLs this plugin answers on, as `<path> => <route>`.
     *
     * TWO THINGS ARE LOAD-BEARING HERE AND NEITHER IS OBVIOUS.
     *
     * FIRST, the paths do NOT start with the plugin handle, and that is not a naming preference.
     * `craft\web\Application::handleRequest()` intercepts any non-action control-panel request
     * whose first segment matches an installed plugin handle and, for a guest, answers
     * `loginRequired()` before routing ever happens (Craft 5, the `!$request->getIsActionRequest()`
     * branch). A callback at `/<cp>/keyway-sso/acs` would therefore bounce the identity
     * provider's POST to the login screen instead of reaching this plugin - the one request that
     * is guaranteed to arrive with no session.
     *
     * SECOND, these are aliases, not the only way in. Every route below is also reachable as an
     * action URL (`/actions/keyway-sso/sso/acs`), and THAT is the address to hand an identity
     * provider: a control-panel path contains the site's `cpTrigger`, which the site owner can
     * change, and a changed ACS URL is a SAML configuration that stops validating.
     *
     * The settings screen now SHOWS those action addresses, ready to copy, and derives them
     * from this very constant (see canonicalEndpointUrl() below), so a renamed route changes the
     * address on screen in the same commit. It also compares them with what the administrator
     * typed into the ACS URL / redirect URI fields - EndpointMatch - because both protocols
     * check that value character for character and a one-character difference fails the login
     * with a message that reads like a certificate problem.
     *
     * @var array<string, string>
     */
    private const START_PATH = 'sso/start';

    /**
     * The diagnostics screen. A control-panel path and NOT an action URL, which is the opposite
     * of the callbacks above and for the opposite reason: no identity provider ever types this
     * address, a human does, and a human arrives with a session. `cpTrigger` moving is then
     * harmless - the link is built from this constant, not remembered by anybody.
     */
    private const DIAGNOSTICS_PATH = 'sso/diagnostics';

    private const METADATA_PATH = 'sso/metadata';

    /**
     * Where the identity provider sends its LogoutRequests, and where its answers come back.
     *
     * An action URL like the callbacks and the metadata document, for the same reason: the IdP
     * is configured with this address once and holds it for years, and a control-panel path
     * breaks silently the day somebody renames `cpTrigger`.
     */
    private const SLO_PATH = 'sso/slo';

    private const CP_ROUTES = [
        self::START_PATH => 'keyway-sso/sso/start',
        'sso/acs' => 'keyway-sso/sso/acs',
        'sso/callback' => 'keyway-sso/sso/callback',
        self::METADATA_PATH => 'keyway-sso/sso/metadata',
        self::SLO_PATH => 'keyway-sso/sso/slo',
        self::DIAGNOSTICS_PATH => 'keyway-sso/diagnostics/index',
    ];

    private ?CraftLoginRuntime $loginRuntime = null;

    private ?InboundLogoutFlow $logoutFlow = null;

    private ?CraftLogoutSession $logoutSession = null;

    private ?CraftDbDiagnosticsSink $diagnosticsSink = null;

    private ?CraftDbIdentityLinkStore $identityLinks = null;

    private ?CraftSignIn $signIn = null;

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();

        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            static function (RegisterUrlRulesEvent $event): void {
                $event->rules = array_merge($event->rules, self::CP_ROUTES);
            }
        );

        // The password fallback, enforced. Registered class-level and unconditionally - NOT
        // inside the control-panel branch below - because the narrowing is a decision, and a
        // decision expressed by skipping the registration is a decision no test can see.
        // PasswordLoginGate is told whether this is a control-panel request and answers; this
        // file only reports facts.
        Event::on(
            User::class,
            User::EVENT_BEFORE_AUTHENTICATE,
            // `Event`, not `AuthenticateUserEvent`, deliberately. A TypeError raised while BINDING
            // the argument happens before the closure body runs, so it would escape the handler's
            // own try/catch and take down every login on the site - the one failure mode this
            // feature may not have. The narrowing is done inside, where it can fail open.
            function (Event $event): void {
                $this->enforcePasswordFallback($event);
            }
        );

        // The other half: Craft would otherwise report a refusal here as "Invalid username or
        // password", which is false and is what an administrator would take to support.
        Event::on(
            UsersController::class,
            UsersController::EVENT_LOGIN_FAILURE,
            static function (LoginFailureEvent $event): void {
                self::explainPasswordRefusal($event);
            }
        );

        // Class-level, and registered from init() rather than lazily, because both the URL rules
        // and the template hook are collected while the request is being set up: a handler
        // attached later is a handler that misses the request that needed it.
        if (Craft::$app->getRequest()->getIsCpRequest()) {
            Craft::$app->getView()->hook(
                self::LOGIN_BUTTON_HOOK,
                fn (array $context): string => $this->loginButtonHtml($context)
            );
        }
    }

    /**
     * Refuses a control-panel password login when the settings say single sign-on is the only
     * way in - the enforcement that makes the five "Password fallback" switches mean something.
     *
     * WHERE THIS SITS IN CRAFT, measured rather than assumed. `EVENT_BEFORE_AUTHENTICATE` fires
     * inside `craft\elements\User::authenticate()`, which immediately afterwards returns false
     * if a handler set `$authError` (vendor/craftcms/cms/src/elements/User.php, the
     * `hasEventHandlers` block). In the whole CMS only two callers reach `authenticate()`:
     * `UsersController::actionLogin()` and `web\Application::authenticate()` for Basic HTTP auth
     * (off unless `enableBasicHttpAuth` is set). Notably NOT the elevated-session check -
     * `UsersController::_verifyExistingPassword()` calls `getSecurity()->validatePassword()`
     * directly - so an administrator already signed in through single sign-on can still confirm
     * their identity with a password to change a setting. That path staying open is deliberate:
     * blocking it would be a lockout wearing a different hat.
     *
     * A REFUSAL HERE COSTS THE ACCOUNT NOTHING. `authenticate()` returns before
     * `handleInvalidLoginParam()`, so a refused attempt is not counted as a bad password and
     * cannot drive the account into Craft's lockout or cooldown. An administrator who tries a
     * password a dozen times during an outage still finds the account healthy when they reach
     * the emergency switch.
     *
     * THE WHOLE BODY IS WRAPPED. PasswordLoginGate already fails open for anything that goes
     * wrong while deciding; this second net covers the two reads it cannot - the request object
     * and the sender - because an exception thrown out of here does not just skip the gate, it
     * takes down `authenticate()` itself and with it every login on the site.
     */
    private function enforcePasswordFallback(Event $event): void
    {
        // `try` FIRST, before the event is even narrowed or `Craft::$app` is touched. Every read
        // below can fail on some installation, and an exception leaving this method does not
        // merely skip the gate - it propagates out of `User::authenticate()` and breaks every
        // login on the site, front end included. Pinned by craft_layer_test.php, which checks
        // this line comes before the first `Craft::$app` and the first `$event` read: moving it
        // down by two lines is an invisible change that costs the client their CMS.
        try {
            if (!$event instanceof AuthenticateUserEvent) {
                return;
            }

            $account = $event->sender;

            if (!$account instanceof User) {
                return;
            }

            $request = Craft::$app->getRequest();

            $decision = PasswordLoginGate::decide(
                $request->getIsCpRequest(),
                // Craft documents this as "the password that was submitted, or null if a passkey
                // is being used" - authenticateWithPasskey() fires the very same event.
                $event->password !== null,
                self::submittedLoginName($request),
                fn (): AdminFallback => new AdminFallback(
                    $this->getSettings()->adminFallback(),
                    new SystemClock()
                ),
                // The one mapping the rest of the plugin uses (see CraftUserDirectory), not a
                // second one written for this call site: two mappings drift, and the fields
                // being read here are the ones that decide who gets in.
                static fn (): ?ExistingUser => CraftUserSnapshot::map(
                    $account->id,
                    $account->email,
                    $account->username,
                    $account->admin,
                    $account->getStatus(),
                    $account->locked
                )
            );

            if (!$decision->allowed) {
                // Through authError(), never the constant: Craft publishes this value as
                // `errorCode` in the JSON failure response, so on an installation that asked for
                // `preventUserEnumeration` it has to be Craft's generic code. Silencing the
                // message alone would leave the oracle wide open one field over.
                $account->authError = PasswordLoginGate::authError(
                    Craft::$app->getConfig()->getGeneral()->preventUserEnumeration
                );
            }
        } catch (\Throwable) {
            // Fail open, for the same reason the gate does: the plugin refusing a password is a
            // feature, the plugin locking a client out of their own CMS is not.
        }
    }

    /**
     * What was typed into the login form, or '' when this request has no such field.
     *
     * `loginName` is the field `actionLogin()` requires, and the key Craft's own login script
     * posts (`Craft.sendActionRequest('POST', 'users/login', {data: {loginName, ...}})`) even
     * though the input on screen is named `username`. It is read as a plain string and anything
     * else - an array from a hand-made request, a missing field on a Basic HTTP auth request -
     * becomes '', which AdminFallbackSettings::isEmergencyAccount() already treats as no match.
     *
     * Asked at all because the emergency list may name an account this installation cannot
     * resolve, which is precisely when somebody needs it most.
     */
    private static function submittedLoginName(mixed $request): string
    {
        if (!$request instanceof WebRequest) {
            return '';
        }

        $loginName = $request->getBodyParam('loginName');

        return is_string($loginName) ? $loginName : '';
    }

    /**
     * Replaces "Invalid username or password" when the password was in fact fine and this plugin
     * was the one that said no.
     *
     * Craft hands the message back out of `EVENT_LOGIN_FAILURE` and uses whatever it finds, so
     * this is the supported way to say something true. Everything about WHETHER to say it -
     * including honouring `preventUserEnumeration`, because a distinct message is only ever
     * reached for an account that exists - is PasswordLoginGate's decision, not this file's.
     */
    private static function explainPasswordRefusal(LoginFailureEvent $event): void
    {
        try {
            $message = PasswordLoginGate::failureMessage(
                $event->authError,
                Craft::$app->getConfig()->getGeneral()->preventUserEnumeration
            );

            if ($message !== null) {
                $event->message = Craft::t('keyway-sso', $message);
            }
        } catch (\Throwable) {
            // A login that already failed is not worth a second failure; the generic message
            // Craft prepared is still in $event->message.
        }
    }

    /**
     * @inheritdoc
     */
    protected function createSettingsModel(): ?Model
    {
        return Craft::createObject(Settings::class);
    }

    /**
     * @inheritdoc
     */
    protected function settingsHtml(): ?string
    {
        $settings = $this->getSettings();
        $acsUrl = self::canonicalEndpointUrl('sso/acs');

        // https forced for OIDC and only for OIDC: OidcConnectionConfig refuses a redirect URI
        // that is not https, so on a site reached over http the screen would otherwise offer a
        // value its own validator rejects. SAML has no such rule (SamlConnectionConfig accepts
        // http), so the ACS URL stays whatever this install really answers on.
        $callbackUrl = self::canonicalEndpointUrl('sso/callback', 'https');
        $installBaseUrls = self::installBaseUrls();

        return Craft::$app->getView()->renderTemplate(
            'keyway-sso/_settings.twig',
            [
                'plugin' => $this,
                'settings' => $settings,
                'protocolOptions' => self::protocolOptions(),
                'warnings' => $settings->warnings(self::craftKeepsUserGroups()),
                'ready' => $settings->isReadyToSignIn(),
                'acsUrl' => $acsUrl,
                'acsMatch' => EndpointMatch::compare($acsUrl, $settings->samlAcsUrl, $installBaseUrls),
                'callbackUrl' => $callbackUrl,
                'callbackMatch' => EndpointMatch::compare(
                    $callbackUrl,
                    $settings->oidcRedirectUri,
                    $installBaseUrls
                ),
                'spEntityId' => self::siteIdentifier(),
                'metadataUrl' => self::metadataUrl(),
                'sloUrl' => self::sloUrl(),
                'sloReady' => self::sloReady($settings),
                'metadataReady' => $settings->spMetadata() !== null,
                'diagnosticsUrl' => self::diagnosticsUrl(),
            ],
            View::TEMPLATE_MODE_CP
        );
    }

    /**
     * The absolute address an identity provider should be given for one of this plugin's
     * callbacks - the value the settings screen offers to copy.
     *
     * NOT `UrlHelper::actionUrl()`, and that is measured rather than assumed. In Craft 5 that
     * helper prepends the control-panel trigger whenever the CURRENT request is a control-panel
     * request (`headlessMode || $request->getIsCpRequest()`), and the settings screen is always
     * one - so it would hand out `https://site/admin/actions/keyway-sso/sso/acs`: an address
     * that works only until somebody changes `cpTrigger`, which is exactly the failure
     * CP_ROUTES exists to avoid. `siteUrl()` builds the same path off the site's own base URL
     * instead, and `craft\web\Request` routes it: an action request is anything whose first
     * segment is the action trigger, control panel or not.
     *
     * WHAT COMES OUT IS NOT ALWAYS A TIDY PATH, and whoever reads this should know before they
     * are surprised by it. On a DEFAULT Craft (`omitScriptNameInUrls` false, `usePathInfo`
     * false, `pathParam` 'p') `UrlHelper::_createUrl()` takes the branch that puts the path in
     * the query string, so this returns `https://host/index.php?p=actions/keyway-sso/sso/acs` -
     * with the host from `UrlHelper::host()`, which on a control-panel request resolves through
     * `baseUrl()` to `baseCpUrl()`. That address ROUTES (the action trigger is still the first
     * path segment Craft sees), and it is the honest answer for such an install, but a
     * `redirect_uri` carrying a query string is rejected outright by some providers, Google
     * among them - which is why the screen says so next to the OIDC value. An install with
     * `omitScriptNameInUrls` on gets the clean `https://host/actions/...` instead.
     *
     * On a multi-site install this is the CURRENT site's base URL, so it follows the site the
     * administrator has selected - see installBaseUrls() for why the comparison then has to
     * know about the others.
     *
     * @param string $cpPath a key of CP_ROUTES, so the displayed address cannot drift from the
     *                       routes that are actually registered.
     * @param string|null $scheme forced scheme, or null to keep the one this site is served on.
     */
    private static function canonicalEndpointUrl(string $cpPath, ?string $scheme = null): string
    {
        return UrlHelper::siteUrl(
            Craft::$app->getConfig()->getGeneral()->actionTrigger . '/' . self::CP_ROUTES[$cpPath],
            null,
            $scheme
        );
    }

    /**
     * The address to hand an identity provider that wants to CONFIGURE ITSELF from our metadata,
     * and the address behind the download button on the settings screen.
     *
     * An action URL and not a control-panel path, which puts it with the callbacks rather than
     * with the diagnostics screen, and for the same reason: some identity providers fetch this
     * document themselves, periodically, with no session and no knowledge of this site's
     * `cpTrigger`. A control-panel address would be an address that breaks the day somebody
     * renames the control panel - and it would break silently, months after the administrator
     * pasted it in.
     */
    public static function metadataUrl(): string
    {
        return self::canonicalEndpointUrl(self::METADATA_PATH);
    }

    /**
     * This site's SingleLogoutService address: the value an administrator pastes into their IdP,
     * the Destination an inbound LogoutRequest is pinned against, and the Location published in
     * metadata. One source for all three, derived from the registered route.
     */
    public static function sloUrl(): string
    {
        return self::canonicalEndpointUrl(self::SLO_PATH);
    }

    /**
     * Whether the screen may tell the administrator that single logout is on.
     *
     * Swallows the connection's own validation error on purpose: a half-written SAML form is the
     * NORMAL state of this screen, and a settings page that throws while somebody is filling it
     * in is a page nobody can finish filling in.
     */
    private static function sloReady(Settings $settings): bool
    {
        try {
            return $settings->samlConnection(self::sloUrl())->canLogout();
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * The Craft half of single logout, assembled where `Craft::$app` may be read.
     *
     * The DECISION is not here and must not be: InboundLogoutFlow owns which session may be
     * ended and what the identity provider is told, because that is the part worth testing, and
     * this method is the part that cannot be.
     */
    public function logoutFlow(): InboundLogoutFlow
    {
        if ($this->logoutFlow === null) {
            $this->logoutFlow = new InboundLogoutFlow(
                new CraftLogoutSession(Craft::$app->getUser(), Craft::$app->getSession()),
                $this->loginRuntime()->diagnostics()
            );
        }

        return $this->logoutFlow;
    }

    /**
     * The verifier for an inbound LogoutRequest, assembled with the same replay guard the login
     * path uses - one cache, one mutex, one single-use store.
     *
     * Built HERE because it needs `Craft::$app` (cache and mutex), which is allowed in this file
     * and nowhere deeper. Throws InvalidArgumentException when the connection is unusable; the
     * caller turns that into an ordinary refusal.
     */
    public function logoutReader(): SamlLogoutRequestReader
    {
        $clock = new SystemClock();

        return new SamlLogoutRequestReader(
            $this->getSettings()->samlConnection(self::sloUrl()),
            $clock,
            new CraftReplayGuard(
                new SingleUseKeys(Craft::$app->getCache(), Craft::$app->getMutex()),
                $clock
            )
        );
    }

    /** The writer for our answer to it. Same connection, same clock. */
    public function logoutAnswer(): SamlLogoutResponse
    {
        return new SamlLogoutResponse(
            $this->getSettings()->samlConnection(self::sloUrl()),
            new SystemClock(),
            new RandomSource()
        );
    }

    /**
     * The session record single logout matches against, for the controller to write at login.
     */
    public function logoutSession(): CraftLogoutSession
    {
        if ($this->logoutSession === null) {
            $this->logoutSession = new CraftLogoutSession(
                Craft::$app->getUser(),
                Craft::$app->getSession()
            );
        }

        return $this->logoutSession;
    }

    /**
     * Every base URL this installation answers on: the control panel's, and one per site.
     *
     * Collected for one reason. Plugin settings are GLOBAL - a single ACS URL for the whole
     * install - while the address offered on the screen can only be built from one site at a
     * time. On a multi-site install with a domain per site, a correct ACS URL therefore often
     * points at a site other than the one currently selected, and without this list the screen
     * would tell an administrator that a working configuration will never receive a response.
     * That warning costs more than silence: it gets a working login taken apart.
     *
     * Raw strings, not hosts, because parsing them is EndpointMatch's business - this method
     * exists so that the rule can be told what this install answers on without ever asking
     * Craft itself.
     *
     * @return list<string>
     */
    private static function installBaseUrls(): array
    {
        $urls = [UrlHelper::baseCpUrl(), UrlHelper::baseSiteUrl()];

        foreach (Craft::$app->getSites()->getAllSites() as $site) {
            $urls[] = (string)$site->getBaseUrl();
        }

        return array_values(array_unique(array_filter($urls)));
    }

    /**
     * A suggested SP entity ID: this site's base URL, without a trailing slash.
     *
     * A suggestion and nothing more, which is why no EndpointMatch is computed for it. An entity
     * ID is an identifier, not an address - anything both sides agree on is correct, the reader
     * only compares the assertion's Audience with whatever is stored - and a site URL is simply
     * the convention most identity providers expect to see.
     */
    private static function siteIdentifier(): string
    {
        return rtrim(UrlHelper::baseSiteUrl(), '/') ?: rtrim(UrlHelper::host(), '/');
    }

    /**
     * The assembled login flow, or null when this site is not configured to sign anybody in.
     *
     * Built once per request and cached on the plugin instance, because the runtime holds the
     * state store and the OIDC discovery cache: two of these in one request would mean two
     * discovery fetches and, worse, two objects each believing they own the single-use claim.
     *
     * `controllers\SsoController` reaches it through this accessor rather than assembling its
     * own, which is what makes "one runtime per request" true in practice and not just intended.
     */
    public function loginRuntime(): CraftLoginRuntime
    {
        if ($this->loginRuntime === null) {
            $this->loginRuntime = new CraftLoginRuntime(
                $this->getSettings(),
                Craft::$app->getCache(),
                Craft::$app->getMutex(),
                Craft::$app->getUsers(),
                $this->diagnosticsSink(),
                $this->identityLinks()
            );
        }

        return $this->loginRuntime;
    }

    /**
     * The diagnostics destination: the plugin's own table, with Craft's log behind it.
     *
     * ONE OBJECT, TWO ROLES, AND THAT IS DELIBERATE. The same instance is handed to
     * CraftLoginRuntime as a DiagnosticsSinkInterface (the write side, during a login) and to
     * diagnosticsReader() as a DiagnosticsReaderInterface (the read side, on the panel). They are
     * separate interfaces so that neither half can reach the other's methods by accident, and one
     * instance so that the memoised "is the table usable" answer is not worked out twice per
     * request - on an install that never ran `craft up`, that answer costs a failed query.
     *
     * THE FALLBACK IS THE POINT. CraftLogDiagnosticsSink sits underneath, so a database that
     * refuses the insert - missing table, full disk, revoked grant - loses the panel, not the
     * diagnostics, and above all not the login. That ordering was the rule the whole module was
     * built to: a plugin whose support screen can take down sign-in is worse than one with no
     * support screen.
     */
    public function diagnosticsSink(): CraftDbDiagnosticsSink
    {
        return $this->diagnosticsSink ??= new CraftDbDiagnosticsSink(
            new CraftLogDiagnosticsSink(),
            new CraftKeyValueCache(Craft::$app->getCache()),
            new SystemClock()
        );
    }

    /**
     * The record of which accounts single sign-on created, and for which issuer.
     *
     * One instance per request for the same reason the sink is: it memoises "does my table
     * exist", and on an install that has not run `craft up` that answer costs a failed query -
     * once, not once per lookup.
     *
     * Built here rather than inside CraftLoginRuntime because this is the only class allowed to
     * read `Craft::$app`, and because the controller needs the same object after the flow has
     * finished: the link can only be written once Craft has created the account and produced an
     * id, which happens after complete() has returned.
     */
    public function identityLinks(): CraftDbIdentityLinkStore
    {
        return $this->identityLinks ??= new CraftDbIdentityLinkStore();
    }

    /**
     * What the diagnostics screen reads. Narrowed to the read interface on purpose - the
     * controller has no business recording events.
     */
    public function diagnosticsReader(): DiagnosticsReaderInterface
    {
        return $this->diagnosticsSink();
    }

    /**
     * The control-panel address of the diagnostics screen, built from the registered route so a
     * renamed route moves the link in the same commit.
     */
    public static function diagnosticsUrl(): string
    {
        return UrlHelper::cpUrl(self::DIAGNOSTICS_PATH);
    }

    /**
     * Carries out an allowed provisioning decision and starts the session.
     *
     * Built here and not inside the controller for the same reason the login runtime is: this is
     * where `Craft::$app` is allowed to be read, and an object that fetches its own collaborators
     * cannot be assembled in a test.
     */
    public function signIn(): CraftSignIn
    {
        if ($this->signIn === null) {
            $this->signIn = new CraftSignIn(
                Craft::$app->getUser(),
                Craft::$app->getUsers(),
                Craft::$app->getUserGroups(),
                Craft::$app->getElements(),
                Craft::$app->getConfig()->getGeneral()->userSessionDuration,
                Craft::$app->getIsLive(),
                // Whether this edition stores group memberships at all. Read here, where the
                // application may be read, and handed over as a fact - CraftSignIn has no way to
                // ask, and must not grow one.
                self::craftKeepsUserGroups()
            );
        }

        return $this->signIn;
    }

    /**
     * Whether this installation's Craft edition stores user group memberships at all.
     *
     * False below Craft Pro, where `UserGroups::saveGroup()` refuses to create any group but the
     * single built-in one and `User::getGroups()` answers `[]` regardless of what the account is
     * in. ONE method with TWO callers on purpose: the sign-in path, which must not write an empty
     * group set on such an edition, and the settings screen, which has to warn about exactly the
     * same situation. Two copies of this condition would be two chances to warn about something
     * the login does not actually do.
     */
    private static function craftKeepsUserGroups(): bool
    {
        return Craft::$app->edition->value >= CmsEdition::Pro->value;
    }

    /**
     * The SSO button, or an empty string when the login screen must look untouched.
     *
     * WHY A TEMPLATE HOOK AND NOT ONE OF THE VIEW EVENTS, measured in Craft 5 rather than
     * assumed. `login.twig` does not put the sign-in form in the page at all: it renders the form
     * into a Twig variable and emits it client-side with `document.write({{ formHtml|json_encode
     * |raw }})` after a cookie test (lines 49-69). At the moment `EVENT_AFTER_RENDER_PAGE_TEMPLATE`
     * fires, or `EVENT_END_BODY`, or anything else that appends to the finished document, the
     * form exists only as a JSON string literal inside a `<script>` - so markup added by those
     * routes lands outside `.login-container`, and Craft's own `LoginForm` script then leaves the
     * `.alternative-login-methods` container hidden, because it only un-hides it when the
     * container has a direct `.btn:not(.hidden)` child. The hook `cp.login.alternative-login-
     * methods` lives inside `_special/login.twig`, which is rendered SERVER-SIDE into that
     * variable, so its output ends up inside the written form, in the right container, where the
     * script can find it.
     *
     * @param array<string, mixed> $context The Twig context, which is how this tells the sign-in
     *                                      screen apart from the "confirm your identity" modal
     *                                      that includes the same partial.
     */
    private function loginButtonHtml(array $context): string
    {
        $settings = $this->getSettings();

        if (!SsoLoginButton::shouldRender($settings->isReadyToSignIn(), $context)) {
            return '';
        }

        // Craft's own idea of where this person was heading, carried through the login so they
        // land there afterwards instead of on the site root (see SsoLoginButton::returnTarget()).
        // It is a hint, not a decision: RedirectGuard in the core still has the last word.
        $target = SsoLoginButton::returnTarget(Craft::$app->getUser()->getReturnUrl());

        return SsoLoginButton::html(
            $settings->buttonLabel,
            UrlHelper::cpUrl(
                self::START_PATH,
                $target === null ? [] : [SsoController::RETURN_URL_PARAM => $target]
            )
        );
    }

    /**
     * Options for the protocol dropdown, in the order an administrator meets them.
     *
     * @return list<array{label: string, value: string}>
     */
    public static function protocolOptions(): array
    {
        return [
            ['label' => 'Disabled (password login only)', 'value' => AuthProtocol::Disabled->value],
            ['label' => 'SAML 2.0', 'value' => AuthProtocol::Saml->value],
            ['label' => 'OpenID Connect', 'value' => AuthProtocol::Oidc->value],
        ];
    }
}
