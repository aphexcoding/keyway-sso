<?php

declare(strict_types=1);

use Keyway\Sso\Core\Attribute\AttributeMap;
use Keyway\Sso\Core\Attribute\AttributeMapper;
use Keyway\Sso\Core\Attribute\AttributeRule;
use Keyway\Sso\Core\Attribute\MultiValueStrategy;
use Keyway\Sso\Core\Attribute\UserField;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Diagnostics\DiagnosticsRecorder;
use Keyway\Sso\Core\Diagnostics\LoginOutcome;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Core\Login\IdentityLink;
use Keyway\Sso\Core\Login\LoginConnection;
use Keyway\Sso\Core\Login\LoginFlow;
use Keyway\Sso\Core\Login\LoginRefusal;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Core\Provisioning\ProvisioningAction;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;
use Keyway\Sso\Core\Provisioning\ProvisioningPolicy;
use Keyway\Sso\Core\Provisioning\ProvisioningSettings;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CollectingSink;
use Keyway\Sso\Test\Support\FakeAuthenticationStarter;
use Keyway\Sso\Test\Support\FakeIdentityReader;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\FailingIdentityLinkStore;
use Keyway\Sso\Test\Support\InMemoryIdentityLinkStore;
use Keyway\Sso\Test\Support\InMemoryStateStorage;
use Keyway\Sso\Test\Support\SequenceRandomSource;
use Keyway\Sso\Test\Support\StubUserDirectory;

/**
 * The login round trip as a set of rules, run with no HTTP, no XML, no database and no CMS.
 *
 * The doubles are deliberately faithful about the one thing that shapes this class: the protocol
 * readers CONSUME THE LOGIN STATE THEMSELVES (SamlResponseReader::consumeLoginState, and the
 * same inside OidcTokenReader), because they need the SAML request id, the OIDC nonce and the
 * PKCE verifier out of it. That is why the flow inspects the state without burning it, and why
 * it checks afterwards that the reader really did burn it - both behaviours are pinned below.
 *
 * The two cases this suite exists for, everything else is scaffolding around them:
 *
 *  - a state with no `connection` is REFUSED, never resolved to the configured connection;
 *  - a login the state says was bound is refused when the cookie is absent or wrong, while a
 *    login the state says was never bound proceeds and leaves a visible diagnostic trail.
 */

/** @var callable(array<string, mixed>): array<string, mixed> $build */
$build = static function (array $options = []): array {
    $storage = new InMemoryStateStorage();
    $clock = new FixedClock(1_000_000);
    $random = new SequenceRandomSource();
    $stateStore = new StateStore($storage, $clock, $random, new RedirectGuard([], '/admin'));
    $sink = new CollectingSink();
    $directory = new StubUserDirectory();
    $links = $options['links'] ?? new InMemoryIdentityLinkStore();

    $provisioning = new ProvisioningPolicy($options['provisioning'] ?? new ProvisioningSettings(
        true,
        true,
        false,
        UserMatchKey::Email,
        [],
        true,
        false
    ));

    $connections = [];
    $readers = [];
    $starters = [];

    foreach ($options['connections'] ?? [['oidc', 'state', CallbackStyle::TopLevelRedirect]] as $spec) {
        [$handle, $parameter, $style] = $spec;
        $url = $spec[3] ?? 'https://site.example.com/actions/keyway-sso/' . $handle;

        $reader = new FakeIdentityReader($handle, $parameter, $stateStore);
        $starter = ($spec[4] ?? true) ? new FakeAuthenticationStarter($handle, $stateStore) : null;

        $readers[$handle] = $reader;
        $starters[$handle] = $starter;
        $connections[] = new LoginConnection($reader, $starter, $style, $url, $parameter);
    }

    $flow = new LoginFlow(
        $stateStore,
        new BrowserBinding($random),
        new AttributeMapper($options['attributeMap'] ?? AttributeMap::defaults()),
        new GroupMapper($options['groupMap'] ?? new GroupMap()),
        $provisioning,
        $directory,
        $links,
        new DiagnosticsRecorder($sink, $clock, $random),
        $connections,
        array_key_exists('active', $options) ? $options['active'] : 'oidc'
    );

    return compact(
        'flow',
        'stateStore',
        'storage',
        'clock',
        'sink',
        'directory',
        'links',
        'readers',
        'starters'
    );
};

/**
 * Starts a login and returns [state token, binding cookie value or null].
 *
 * @return array{0: string, 1: string|null}
 */
$roundTrip = static function (array $kit, ?string $returnUrl = '/admin/entries'): array {
    $start = $kit['flow']->begin($returnUrl);
    Assert::true($start->started, 'the login must start for this case to mean anything');

    parse_str((string)parse_url((string)$start->redirectUrl, PHP_URL_QUERY), $query);

    return [(string)($query['state'] ?? ''), $start->cookie?->value];
};

$payload = static fn (string $email = 'person@example.com'): IdentityPayload => new IdentityPayload(
    'subject-1',
    ['email' => [$email], 'groups' => ['editors']],
    'https://idp.example.com'
);

return [
    // ---------------------------------------------------------------------------------
    // begin()
    // ---------------------------------------------------------------------------------

    'begin issues a state, a cookie and a redirect' => static function () use ($build): void {
        $kit = $build();
        $start = $kit['flow']->begin('/admin/entries');

        Assert::true($start->started);
        Assert::notNull($start->redirectUrl);
        Assert::notNull($start->cookie);
        Assert::same(BrowserBinding::COOKIE_NAME, $start->cookie?->name);
        Assert::false($start->isUnbound());
        Assert::same(1, $kit['storage']->count(), 'exactly one state issued');
    },

    'begin writes the connection handle and the binding decision into the state'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$token] = $roundTrip($kit);

            $context = $kit['stateStore']->inspect($token)->context();

            Assert::same('oidc', $context['connection']);
            Assert::same(BrowserBinding::MODE_BOUND, $context[BrowserBinding::CONTEXT_MODE]);
            Assert::same(64, strlen($context[BrowserBinding::CONTEXT_HASH]));
        },

    'the state keeps only the hash; the secret exists in the cookie alone'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$token, $cookie] = $roundTrip($kit);

            $context = $kit['stateStore']->inspect($token)->context();

            Assert::notNull($cookie);
            Assert::same(hash('sha256', (string)$cookie), $context[BrowserBinding::CONTEXT_HASH]);
            Assert::notContains((string)$cookie, json_encode($context, JSON_THROW_ON_ERROR));
        },

    'begin refuses when single sign-on is not configured' => static function () use ($build): void {
        $start = $build(['active' => null])['flow']->begin('/admin');

        Assert::false($start->started);
        Assert::same(LoginRefusal::NOT_CONFIGURED, $start->reasonCode);
        Assert::null($start->cookie);
        Assert::same(LoginRefusal::PUBLIC_MESSAGE, $start->publicMessage());
    },

    'begin refuses a connection that can read a response but cannot build a request'
        => static function () use ($build): void {
            $start = $build([
                'connections' => [['saml2', 'RelayState', CallbackStyle::CrossSitePost, null, false]],
                'active' => 'saml2',
            ])['flow']->begin('/admin');

            Assert::false($start->started);
            Assert::same(LoginRefusal::CONNECTION_CANNOT_START, $start->reasonCode);
        },

    // A SAML callback over plain HTTP is the one degradation decision O6 accepts - and it has to
    // be loud on the way out, not discovered on the way back.
    'a login that cannot be bound starts anyway and records a notice'
        => static function () use ($build): void {
            $kit = $build([
                'connections' => [[
                    'saml2',
                    'RelayState',
                    CallbackStyle::CrossSitePost,
                    'http://site.example.com/actions/keyway-sso/saml2',
                ]],
                'active' => 'saml2',
            ]);

            $start = $kit['flow']->begin('/admin');

            Assert::true($start->started);
            Assert::null($start->cookie);
            Assert::true($start->isUnbound());

            $event = $kit['sink']->last();
            Assert::same(LoginOutcome::Notice, $event?->outcome, 'not an error - the login works');
            Assert::same(LoginRefusal::BINDING_NOT_ISSUED, $event?->reasonCode);
            Assert::contains('HTTPS', (string)$event?->message);
        },

    'a starter that drops the context is caught at the start, not at the callback'
        => static function () use ($build): void {
            $kit = $build();
            $kit['starters']['oidc']->dropContext = true;

            $start = $kit['flow']->begin('/admin');

            Assert::false($start->started);
            Assert::same(LoginRefusal::STATE_CONTEXT_LOST, $start->reasonCode);
            Assert::same(LoginOutcome::Error, $kit['sink']->last()?->outcome);
        },

    // The two cases below exist because the autocheck in begin() is a two-part condition, and a
    // starter that drops the WHOLE context proves only that the pair fires - either half alone
    // would still catch it. Each case loses exactly one key, so each half is pinned on its own.
    'a starter that keeps the binding decision but loses the connection handle is refused'
        => static function () use ($build): void {
            $kit = $build();
            $kit['starters']['oidc']->dropContext = true;
            $kit['starters']['oidc']->ownContext = [
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_BOUND,
            ];

            $start = $kit['flow']->begin('/admin');

            Assert::false($start->started, 'the binding decision alone is not enough to continue');
            Assert::same(LoginRefusal::STATE_CONTEXT_LOST, $start->reasonCode);
            Assert::same(LoginOutcome::Error, $kit['sink']->last()?->outcome);
            Assert::same(DiagnosticEvent::STAGE_STATE, $kit['sink']->last()?->stage);
        },

    'a starter that keeps the connection handle but loses the binding decision is refused'
        => static function () use ($build): void {
            $kit = $build();
            $kit['starters']['oidc']->dropContext = true;
            $kit['starters']['oidc']->ownContext = ['connection' => 'oidc'];

            $start = $kit['flow']->begin('/admin');

            Assert::false($start->started, 'the connection handle alone is not enough to continue');
            Assert::same(LoginRefusal::STATE_CONTEXT_LOST, $start->reasonCode);
            Assert::same(LoginOutcome::Error, $kit['sink']->last()?->outcome);
            Assert::same(DiagnosticEvent::STAGE_STATE, $kit['sink']->last()?->stage);
        },

    // ---------------------------------------------------------------------------------
    // begin() when the identity provider is unreachable
    //
    // The most likely fault on a live site, and the one that must NOT become a 500 on the
    // login screen: OidcAuthorizationRequest::start() fetches the discovery document before it
    // can build a URL, and IdentityReaderException (a RuntimeException) comes back from every
    // failed fetch; SamlAuthnRequest throws a plain RuntimeException when DEFLATE fails. Both
    // shapes are exercised, because catching only the plugin's own exception type would leave
    // the SAML half uncovered.
    // ---------------------------------------------------------------------------------

    'begin refuses instead of throwing when the discovery fetch fails' => static function () use ($build): void {
        $kit = $build();
        $kit['starters']['oidc']->throw = new IdentityReaderException(
            IdentityReaderException::DISCOVERY_FAILED,
            'Discovery document could not be fetched: connection refused.'
        );

        $start = null;
        Assert::doesNotThrow(static function () use ($kit, &$start): void {
            $start = $kit['flow']->begin('/admin');
        }, 'an unreachable identity provider must not reach the error handler');

        Assert::false($start?->started ?? true);
        Assert::same(LoginRefusal::START_FAILED, $start?->reasonCode);
        Assert::same(LoginRefusal::PUBLIC_MESSAGE, $start?->publicMessage());
        Assert::null($start?->redirectUrl);
        Assert::null($start?->cookie, 'no binding cookie is set for a login that never left');
    },

    'the refused start is on the diagnostics timeline, with the provider reason code' =>
        static function () use ($build): void {
            $kit = $build();
            $kit['starters']['oidc']->throw = new IdentityReaderException(
                IdentityReaderException::DISCOVERY_FAILED,
                'Discovery endpoint answered with HTTP 503.'
            );

            $start = $kit['flow']->begin('/admin');

            Assert::notNull($start->event, 'an administrator has to be able to see why');
            Assert::same(LoginOutcome::Error, $kit['sink']->last()?->outcome);
            Assert::same(DiagnosticEvent::STAGE_PROTOCOL, $kit['sink']->last()?->stage);
            Assert::same(LoginRefusal::START_FAILED, $kit['sink']->last()?->reasonCode);
            Assert::contains('HTTP 503', (string)$kit['sink']->last()?->message);
            Assert::contains(
                IdentityReaderException::DISCOVERY_FAILED,
                (string)$kit['sink']->last()?->message,
                'discovery_failed and issuer_mismatch send an administrator to different places'
            );
        },

    'a plain RuntimeException from the SAML request builder is caught too' =>
        static function () use ($build): void {
            $kit = $build();
            $kit['starters']['oidc']->throw = new RuntimeException(
                'Could not DEFLATE the SAML request; ext-zlib is broken.'
            );

            $start = $kit['flow']->begin('/admin');

            Assert::false($start->started);
            Assert::same(LoginRefusal::START_FAILED, $start->reasonCode);
            Assert::contains('ext-zlib', (string)$kit['sink']->last()?->message);
        },

    // A browser keys a cookie on (name, domain, PATH). A deletion issued for "/" does not
    // remove one stored under the callback path, so a callback that never identified its
    // connection - every scanner, every retry with a mangled state - would leave the binding
    // secret in the browser for the rest of its TTL.
    'an unidentifiable callback still deletes the binding on the path it was set on' =>
        static function () use ($build): void {
            $kit = $build();

            $issued = $kit['flow']->begin('/admin');
            Assert::same(
                '/actions/keyway-sso/oidc',
                $issued->cookie?->path,
                'this is the path the binding was stored under'
            );

            foreach ([[], ['state' => '   '], ['state' => 'not-a-token']] as $callback) {
                $completion = $kit['flow']->complete($callback, null);

                Assert::false($completion->allowed);
                Assert::true($completion->clearBinding->isDeletion());
                Assert::same(
                    '/actions/keyway-sso/oidc',
                    $completion->clearBinding->path,
                    'a deletion on "/" would not remove the cookie'
                );
            }
        },

    'a starter cannot be paired with a reader for another connection' => static function () use ($build): void {
        $kit = $build();

        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new LoginConnection(
                $kit['readers']['oidc'],
                new FakeAuthenticationStarter('saml2', $kit['stateStore']),
                CallbackStyle::TopLevelRedirect,
                'https://site.example.com/cb',
                'state'
            )
        );
    },

    // ---------------------------------------------------------------------------------
    // complete() - the happy path
    // ---------------------------------------------------------------------------------

    'a bound round trip signs an existing user in' => static function () use ($build, $roundTrip): void {
        $kit = $build();
        $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
            '17',
            'person@example.com',
            'person',
            false,
            AccountStatus::Active,
            false
        );

        [$token, $cookie] = $roundTrip($kit);
        $result = $kit['flow']->complete(['state' => $token, 'code' => 'abc'], $cookie);

        Assert::true($result->allowed);
        Assert::true($result->bindingVerified);
        Assert::same(ProvisioningAction::Update, $result->decision()?->action);
        Assert::same('17', $result->decision()?->userId);
        Assert::same('/admin/entries', $result->returnUrl, 'the return URL survives the round trip');
        Assert::same(LoginOutcome::Success, $result->event?->outcome);
        Assert::true($result->clearBinding->isDeletion(), 'the cookie always comes off');
    },

    'an unknown identity is created just in time' => static function () use ($build, $roundTrip): void {
        $kit = $build();
        [$token, $cookie] = $roundTrip($kit);

        $result = $kit['flow']->complete(['state' => $token], $cookie);

        Assert::true($result->allowed);
        Assert::same(ProvisioningAction::Create, $result->decision()?->action);
        Assert::same('person@example.com', $result->decision()?->matchValue);
    },

    // ------------------------------------------------------------------------------------
    // The second login. Measured on a live Craft with Okta on 2026-09-15: the first login
    // created the account and the second was refused, because nothing recorded that this
    // connection had created it. These cases run the WHOLE cycle - create, record,
    // come back - on stock settings, which is where the bug lived.
    // ------------------------------------------------------------------------------------

    'the same person signs in twice: created first, let in second' =>
        static function () use ($build, $roundTrip): void {
            // Stock settings: JIT on, linking to existing accounts OFF. The builder's default
            // turns linking on, which is exactly the configuration that HID this bug.
            $kit = $build(['provisioning' => new ProvisioningSettings()]);

            [$first, $firstCookie] = $roundTrip($kit);
            $created = $kit['flow']->complete(['state' => $first], $firstCookie);

            Assert::true($created->allowed);
            Assert::same(ProvisioningAction::Create, $created->decision()?->action);
            Assert::same('https://idp.example.com', $created->issuer, 'unmasked, for the link');
            Assert::same('subject-1', $created->subject);

            // What the Craft layer does next: it creates the account, gets an id back, and
            // writes the link. IdentityLink owns the rule; the controller only carries it out.
            $link = IdentityLink::afterSignIn($created, 17);
            Assert::notNull($link);
            $kit['links']->remember((string)$link?->userId, (string)$link?->issuer, (string)$link?->subject);

            Assert::same(
                [['userId' => '17', 'issuer' => 'https://idp.example.com', 'subject' => 'subject-1']],
                $kit['links']->written
            );

            // ... and the account now exists, as it would on the second visit.
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Active,
                false
            );

            [$second, $secondCookie] = $roundTrip($kit);
            $returning = $kit['flow']->complete(['state' => $second], $secondCookie);

            Assert::true($returning->allowed, 'the second login is the one that used to fail');
            Assert::notSame(ProvisioningDecision::LINKING_DISABLED, $returning->reasonCode);
            Assert::same(ProvisioningAction::Update, $returning->decision()?->action);
            Assert::same('17', $returning->decision()?->userId);
            Assert::same(LoginOutcome::Success, $returning->event?->outcome);
        },

    'without the recorded link the second login is refused, which is the bug this fixes' =>
        static function () use ($build, $roundTrip): void {
            $kit = $build(['provisioning' => new ProvisioningSettings()]);
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Active,
                false
            );

            [$token, $cookie] = $roundTrip($kit);
            $refused = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($refused->allowed);
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $refused->reasonCode);
            Assert::null($refused->issuer, 'a refusal carries nothing anything could be written from');
            Assert::null($refused->subject);
            Assert::null(IdentityLink::afterSignIn($refused, 17), 'and nothing may be recorded');
        },

    'a link belongs to one issuer and does not travel to another' =>
        static function () use ($build, $roundTrip): void {
            $kit = $build(['provisioning' => new ProvisioningSettings()]);
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Active,
                false
            );

            // The account was created by our own identity provider...
            $kit['links']->plant('17', 'https://idp.example.com');

            // ... and this response comes from a different one. Same address, same username,
            // same everything the matcher looks at - and it must not be enough.
            $kit['readers']['oidc']->payload = new IdentityPayload(
                'subject-1',
                ['email' => ['person@example.com'], 'groups' => ['editors']],
                'https://other-idp.example.com'
            );

            [$token, $cookie] = $roundTrip($kit);
            $refused = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($refused->allowed);
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $refused->reasonCode);

            // An assertion with no issuer at all is the same answer, for the same reason.
            $kit['readers']['oidc']->payload = new IdentityPayload(
                'subject-1',
                ['email' => ['person@example.com'], 'groups' => ['editors']]
            );

            [$blank, $blankCookie] = $roundTrip($kit);

            Assert::same(
                ProvisioningDecision::LINKING_DISABLED,
                $kit['flow']->complete(['state' => $blank], $blankCookie)->reasonCode
            );

            // The control that makes the two refusals mean something: with the issuer the link
            // was recorded for, the very same login goes through.
            $kit['readers']['oidc']->payload = new IdentityPayload(
                'subject-1',
                ['email' => ['person@example.com'], 'groups' => ['editors']],
                'https://idp.example.com'
            );

            [$ours, $oursCookie] = $roundTrip($kit);

            Assert::true($kit['flow']->complete(['state' => $ours], $oursCookie)->allowed);
        },

    // THE SECOND TAKEOVER PATH, measured on stock settings before the fix: an attacker with an
    // account at the SAME identity provider - a colleague, a contractor, anybody in the same
    // directory - who puts the victim's address in their own profile matched the victim's Craft
    // account and was signed into it with `update_on_login`, on a site whose owner had left
    // `linkExistingAccounts` OFF. A link keyed on (account, issuer) said "this issuer created
    // this account" and never asked WHO at that issuer it was created for.
    //
    // The link is therefore about a person and not only about a directory, and the cost (a
    // re-issued name id locks somebody out until an administrator acts) was accepted with it.
    'another subject at the same issuer does not inherit the link' =>
        static function () use ($build, $roundTrip): void {
            $kit = $build(['provisioning' => new ProvisioningSettings()]);

            // Alice's account, created by this plugin for Alice.
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Active,
                false
            );
            $kit['links']->plant('17', 'https://idp.example.com', 'alice-sub');

            // Mallory, same directory, same trusted issuer, her own subject - and Alice's
            // address in the profile the identity provider releases.
            $kit['readers']['oidc']->payload = new IdentityPayload(
                'mallory-sub',
                ['email' => ['person@example.com'], 'groups' => ['editors']],
                'https://idp.example.com'
            );

            [$token, $cookie] = $roundTrip($kit);
            $refused = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($refused->allowed, 'this used to sign Mallory into Alice\'s account');
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $refused->reasonCode);

            // The control: Alice herself, same issuer, same address, her own subject.
            $kit['readers']['oidc']->payload = new IdentityPayload(
                'alice-sub',
                ['email' => ['person@example.com'], 'groups' => ['editors']],
                'https://idp.example.com'
            );

            [$hers, $hersCookie] = $roundTrip($kit);

            Assert::true($kit['flow']->complete(['state' => $hers], $hersCookie)->allowed);
        },

    // THE MIGRATION THAT HAS NOT RUN. The shipped adapter never throws, so a missing table is
    // not an exception anywhere - it is a truthful "not linked" that reaches the administrator
    // as `linking_disabled`, whose advice is to switch linking on for every account on the site.
    // The refusal stays (fail closed); what changes is that the panel says which one it is.
    'a link store with no table says so instead of looking like a setting mistake' =>
        static function () use ($build, $roundTrip): void {
            $kit = $build(['provisioning' => new ProvisioningSettings()]);
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Active,
                false
            );

            // The account WAS created here - the link is planted - but the site is running with
            // `craft up` not yet applied, so nothing can be read back.
            $kit['links']->plant('17', 'https://idp.example.com');
            $kit['links']->ready = false;

            [$token, $cookie] = $roundTrip($kit);
            $refused = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($refused->allowed, 'fail closed: unreadable is not "linked"');
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $refused->reasonCode);

            $notice = null;
            foreach ($kit['sink']->events as $event) {
                if ($event->reasonCode === LoginRefusal::IDENTITY_LINK_UNAVAILABLE) {
                    $notice = $event;
                }
            }

            Assert::notNull($notice, 'a silent degradation is an unsolvable support ticket');
            Assert::same(LoginOutcome::Notice, $notice?->outcome);
            Assert::same('oidc', $notice?->protocol, 'the same protocol the decision row carries');
            Assert::contains('craft up', (string)$notice?->message);

            // The control: with the table readable, the very same login goes through.
            $kit['links']->ready = true;

            [$ready, $readyCookie] = $roundTrip($kit);

            Assert::true($kit['flow']->complete(['state' => $ready], $readyCookie)->allowed);
        },

    'a link store that cannot answer refuses the login instead of breaking it' =>
        static function () use ($build, $roundTrip): void {
            // The shipped adapter swallows its own database faults, so this double throws -
            // the contract has to hold even for an implementation that breaks it, because the
            // alternative is a 500 on the callback.
            $kit = $build([
                'provisioning' => new ProvisioningSettings(),
                'links' => new FailingIdentityLinkStore(),
            ]);
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Active,
                false
            );

            [$token, $cookie] = $roundTrip($kit);
            $refused = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($refused->allowed, 'fail closed: unreadable is not "linked"');
            Assert::same(ProvisioningDecision::LINKING_DISABLED, $refused->reasonCode);

            // And the administrator is told WHY it looks like a configuration mistake, on the
            // same timeline as the refusal.
            $notice = null;
            foreach ($kit['sink']->events as $event) {
                if ($event->reasonCode === LoginRefusal::IDENTITY_LINK_UNAVAILABLE) {
                    $notice = $event;
                }
            }

            Assert::notNull($notice, 'a silent degradation is an unsolvable support ticket');
            Assert::same(LoginOutcome::Notice, $notice?->outcome);
            Assert::contains('craft up', (string)$notice?->message);

            // AND THE EXCEPTION'S OWN TEXT STAYS OUT OF IT. DiagnosticEvent length-caps the
            // message field but does not mask it, and a Yii database exception carries the
            // statement - so copying getMessage() in here would store SQL in a table the
            // support panel prints. The class name is what identifies the fault instead.
            Assert::notContains(FailingIdentityLinkStore::MESSAGE, (string)$notice?->message);
            Assert::notContains('SQLSTATE', (string)$notice?->message);
            Assert::contains('RuntimeException', (string)$notice?->message);
        },

    'the lookup uses the column the connection matches on' => static function () use ($build, $roundTrip): void {
        $kit = $build([
            'attributeMap' => new AttributeMap([
                new AttributeRule('email', UserField::EMAIL, MultiValueStrategy::First, true),
                AttributeRule::optional('username', UserField::USERNAME),
            ]),
            'provisioning' => new ProvisioningSettings(
                true,
                true,
                false,
                UserMatchKey::Username,
                [],
                true,
                false
            ),
        ]);

        $kit['readers']['oidc']->payload = new IdentityPayload('subject-1', [
            'email' => ['person@example.com'],
            'username' => ['person'],
        ]);

        [$token, $cookie] = $roundTrip($kit);
        $kit['flow']->complete(['state' => $token], $cookie);

        Assert::sameList(['username:person'], $kit['directory']->asked);
    },

    // ---------------------------------------------------------------------------------
    // complete() - the state
    // ---------------------------------------------------------------------------------

    'a callback with no state is refused with its own reason' => static function () use ($build): void {
        $kit = $build();
        $result = $kit['flow']->complete(['code' => 'abc'], null);

        Assert::false($result->allowed);
        Assert::same(LoginRefusal::STATE_MISSING, $result->reasonCode);
        Assert::same(LoginRefusal::PUBLIC_MESSAGE, $result->publicMessage());
        Assert::same(0, count($kit['readers']['oidc']->calls), 'the reader never ran');
    },

    'two connections\' state fields at once is refused rather than guessed'
        => static function () use ($build): void {
            $kit = $build([
                'connections' => [
                    ['oidc', 'state', CallbackStyle::TopLevelRedirect],
                    ['saml2', 'RelayState', CallbackStyle::CrossSitePost],
                ],
            ]);

            $result = $kit['flow']->complete(['state' => 'a.b', 'RelayState' => 'c.d'], null);

            Assert::same(LoginRefusal::STATE_AMBIGUOUS, $result->reasonCode);
        },

    'an unknown, expired or replayed state is refused before anything else runs'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$token, $cookie] = $roundTrip($kit);

            Assert::true($kit['flow']->complete(['state' => $token], $cookie)->allowed);

            $replay = $kit['flow']->complete(['state' => $token], $cookie);
            Assert::false($replay->allowed);
            Assert::same(LoginRefusal::STATE_REJECTED, $replay->reasonCode);
            Assert::contains('already_used', $replay->message);

            $unknown = $kit['flow']->complete(['state' => 'aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb'], $cookie);
            Assert::same(LoginRefusal::STATE_REJECTED, $unknown->reasonCode);
            Assert::contains('unknown', $unknown->message);
        },

    'inspecting a state does not burn it' => static function () use ($build, $roundTrip): void {
        $kit = $build();
        [$token, $cookie] = $roundTrip($kit);

        // Reading it twice must leave the real consumption to the reader.
        Assert::true($kit['stateStore']->inspect($token)->valid);
        Assert::true($kit['stateStore']->inspect($token)->valid);
        Assert::false($kit['stateStore']->wasConsumed((string)$kit['stateStore']->inspect($token)->id));

        Assert::true($kit['flow']->complete(['state' => $token], $cookie)->allowed);
    },

    // The guard that makes the non-burning inspection safe.
    'a reader that returns an identity without burning the state is refused'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            $kit['readers']['oidc']->burns = false;

            [$token, $cookie] = $roundTrip($kit);
            $result = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($result->allowed, 'a replayable state cannot end in a signed-in session');
            Assert::same(LoginRefusal::STATE_NOT_BURNT, $result->reasonCode);
        },

    // ---------------------------------------------------------------------------------
    // complete() - `connection`, the hard requirement carried over from turn 6
    // ---------------------------------------------------------------------------------

    'a state with no connection is refused, never resolved to the configured one'
        => static function () use ($build): void {
            $kit = $build();

            // A state that never learned which connection it belongs to - the shape produced by
            // a context filtered on the way in, or by a starter that rebuilt it.
            $token = $kit['stateStore']->issue('/admin/entries', [
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
            ]);

            $result = $kit['flow']->complete(['state' => $token->value], null);

            Assert::false($result->allowed);
            Assert::same(LoginRefusal::CONNECTION_MISSING, $result->reasonCode);
            Assert::same(0, count($kit['readers']['oidc']->calls), 'no reader was picked at all');
            Assert::false($kit['stateStore']->wasConsumed($token->id), 'nothing was consumed');
        },

    'an empty or whitespace connection handle counts as missing' => static function () use ($build): void {
        foreach (['', '   '] as $handle) {
            $kit = $build();
            $token = $kit['stateStore']->issue('/admin', [
                'connection' => $handle,
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
            ]);

            Assert::same(
                LoginRefusal::CONNECTION_MISSING,
                $kit['flow']->complete(['state' => $token->value], null)->reasonCode
            );
        }
    },

    'a state naming a connection this site no longer has is refused' => static function () use ($build): void {
        $kit = $build();
        $token = $kit['stateStore']->issue('/admin', [
            'connection' => 'saml2',
            BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
        ]);

        $result = $kit['flow']->complete(['state' => $token->value], null);

        Assert::same(LoginRefusal::CONNECTION_UNKNOWN, $result->reasonCode);
        Assert::same(0, count($kit['readers']['oidc']->calls));
    },

    // The other half of the requirement: the context decides, not the current settings.
    'the connection in the state chooses the reader, not the active connection'
        => static function () use ($build): void {
            $kit = $build([
                'connections' => [
                    ['oidc', 'state', CallbackStyle::TopLevelRedirect],
                    ['saml2', 'RelayState', CallbackStyle::CrossSitePost],
                ],
                'active' => 'oidc',
            ]);

            // Issued under SAML while OIDC is the connection the site would start a login with.
            $token = $kit['stateStore']->issue('/admin', [
                'connection' => 'saml2',
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
            ]);

            $result = $kit['flow']->complete(['RelayState' => $token->value], null);

            Assert::true($result->allowed);
            Assert::same(1, count($kit['readers']['saml2']->calls), 'the SAML reader ran');
            Assert::same(0, count($kit['readers']['oidc']->calls), 'the active connection did not');
        },

    'a state that comes back through the wrong protocol\'s field is refused'
        => static function () use ($build): void {
            $kit = $build([
                'connections' => [
                    ['oidc', 'state', CallbackStyle::TopLevelRedirect],
                    ['saml2', 'RelayState', CallbackStyle::CrossSitePost],
                ],
            ]);

            $token = $kit['stateStore']->issue('/admin', [
                'connection' => 'saml2',
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
            ]);

            // A SAML state posted into the OIDC callback field.
            $result = $kit['flow']->complete(['state' => $token->value], null);

            Assert::same(LoginRefusal::CONNECTION_MISMATCH, $result->reasonCode);
            Assert::same(0, count($kit['readers']['saml2']->calls));
        },

    'two connections cannot share a handle' => static function () use ($build): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => $build([
                'connections' => [
                    ['oidc', 'state', CallbackStyle::TopLevelRedirect],
                    ['oidc', 'RelayState', CallbackStyle::CrossSitePost],
                ],
            ])
        );
    },

    'the active connection has to be one of the registered ones' => static function () use ($build): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => $build(['active' => 'entra'])
        );
    },

    // ---------------------------------------------------------------------------------
    // complete() - the browser binding (decision O6)
    // ---------------------------------------------------------------------------------

    'a bound login with no cookie is refused with its own reason code'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$token] = $roundTrip($kit);

            $result = $kit['flow']->complete(['state' => $token], null);

            Assert::false($result->allowed);
            Assert::same(LoginRefusal::BINDING_COOKIE_MISSING, $result->reasonCode);
            Assert::notSame(LoginRefusal::STATE_REJECTED, $result->reasonCode, 'support can tell them apart');
            Assert::same(0, count($kit['readers']['oidc']->calls), 'nothing costly ran');
            Assert::false($kit['stateStore']->wasConsumed((string)$kit['stateStore']->inspect($token)->id));
        },

    'a cookie from another login is refused as a mismatch, not as a missing cookie'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$victim] = $roundTrip($kit);
            [, $attackerCookie] = $roundTrip($kit);

            $result = $kit['flow']->complete(['state' => $victim], $attackerCookie);

            Assert::same(LoginRefusal::BINDING_MISMATCH, $result->reasonCode);
            Assert::false($result->bindingVerified);
        },

    // Login-CSRF in one case: the attacker holds a perfectly valid state, because they started
    // the login. The cookie is the only thing that says whose browser this is.
    'a state spliced into another browser does not sign anybody in'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$attackerToken] = $roundTrip($kit);

            // The victim's browser posts the attacker's state and carries no binding cookie.
            $result = $kit['flow']->complete(['state' => $attackerToken, 'code' => 'x'], null);

            Assert::false($result->allowed);
            Assert::same(LoginRefusal::BINDING_COOKIE_MISSING, $result->reasonCode);
        },

    'a state with no binding decision at all is refused' => static function () use ($build): void {
        $kit = $build();
        $token = $kit['stateStore']->issue('/admin', ['connection' => 'oidc']);

        $result = $kit['flow']->complete(['state' => $token->value], 'anything');

        Assert::same(LoginRefusal::BINDING_UNDECLARED, $result->reasonCode);
        Assert::same(0, count($kit['readers']['oidc']->calls));
    },

    'a state that claims to be bound but carries no hash is refused' => static function () use ($build): void {
        $kit = $build();
        $token = $kit['stateStore']->issue('/admin', [
            'connection' => 'oidc',
            BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_BOUND,
        ]);

        $result = $kit['flow']->complete(['state' => $token->value], 'anything');

        Assert::same(LoginRefusal::BINDING_INCONSISTENT, $result->reasonCode);
    },

    'a login that was never bound completes, and the degradation is recorded'
        => static function () use ($build): void {
            $kit = $build();
            $token = $kit['stateStore']->issue('/admin', [
                'connection' => 'oidc',
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
            ]);

            $result = $kit['flow']->complete(['state' => $token->value], null);

            Assert::true($result->allowed);
            Assert::false($result->bindingVerified, 'allowed is not the same as verified');

            $reasons = array_map(
                static fn (DiagnosticEvent $event): string => $event->reasonCode,
                $kit['sink']->events
            );
            Assert::true(
                in_array(LoginRefusal::BINDING_NOT_ISSUED, $reasons, true),
                'the unbound login leaves a trail'
            );
        },

    // ---------------------------------------------------------------------------------
    // complete() - the protocol and the policy
    // ---------------------------------------------------------------------------------

    'a rejected response keeps the reader\'s own reason code in the diagnostics'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            $kit['readers']['oidc']->failure = new IdentityReaderException(
                IdentityReaderException::SIGNATURE_INVALID,
                'We could not verify the sign-in response from your identity provider.'
            );

            [$token, $cookie] = $roundTrip($kit);
            $result = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($result->allowed);
            Assert::same(LoginRefusal::IDENTITY_REJECTED, $result->reasonCode);
            Assert::contains(IdentityReaderException::SIGNATURE_INVALID, $result->message);
            Assert::same(DiagnosticEvent::STAGE_PROTOCOL, $kit['sink']->last()?->stage);
        },

    'a missing required attribute is refused at the mapping stage' => static function () use ($build, $roundTrip): void {
        $kit = $build();
        $kit['readers']['oidc']->payload = new IdentityPayload('subject-1', ['groups' => ['editors']]);

        [$token, $cookie] = $roundTrip($kit);
        $result = $kit['flow']->complete(['state' => $token], $cookie);

        Assert::false($result->allowed);
        Assert::same(LoginRefusal::ATTRIBUTES_REJECTED, $result->reasonCode);
        Assert::same(DiagnosticEvent::STAGE_ATTRIBUTES, $kit['sink']->last()?->stage);
    },

    'a policy denial is passed through with the policy\'s own reason' => static function () use ($build, $roundTrip): void {
        $kit = $build([
            'provisioning' => new ProvisioningSettings(
                false,
                true,
                false,
                UserMatchKey::Email,
                [],
                true,
                false
            ),
        ]);

        [$token, $cookie] = $roundTrip($kit);
        $result = $kit['flow']->complete(['state' => $token], $cookie);

        Assert::false($result->allowed);
        Assert::same(ProvisioningDecision::JIT_DISABLED, $result->reasonCode);
        Assert::same(LoginOutcome::Denied, $result->event?->outcome);
        Assert::same(LoginRefusal::PUBLIC_MESSAGE, $result->publicMessage());
        Assert::notSame($result->message, $result->publicMessage(), 'the admin message never leaks');
    },

    'a suspended account is not signed in, and the visitor is told nothing about it'
        => static function () use ($build, $roundTrip, $payload): void {
            $kit = $build();
            $kit['directory']->byEmail['person@example.com'] = new ExistingUser(
                '17',
                'person@example.com',
                'person',
                false,
                AccountStatus::Suspended,
                false
            );
            $kit['readers']['oidc']->payload = $payload();

            [$token, $cookie] = $roundTrip($kit);
            $result = $kit['flow']->complete(['state' => $token], $cookie);

            Assert::false($result->allowed);
            Assert::same(ProvisioningDecision::ACCOUNT_SUSPENDED, $result->reasonCode);
            Assert::notContains('suspend', strtolower($result->publicMessage()));
        },

    'every refusal returns a cookie deletion' => static function () use ($build, $roundTrip): void {
        $kit = $build();

        $noState = $kit['flow']->complete([], null);
        Assert::true($noState->clearBinding->isDeletion());

        [$token] = $roundTrip($kit);
        $noCookie = $kit['flow']->complete(['state' => $token], null);
        Assert::true($noCookie->clearBinding->isDeletion());
        Assert::same(BrowserBinding::COOKIE_NAME, $noCookie->clearBinding->name);
    },

    'each refusal reason is distinct, so the panel can tell the causes apart'
        => static function () use ($build, $roundTrip): void {
            $kit = $build();
            [$bound] = $roundTrip($kit);

            $unbound = $kit['stateStore']->issue('/admin', ['connection' => 'oidc']);
            $noConnection = $kit['stateStore']->issue('/admin', [
                BrowserBinding::CONTEXT_MODE => BrowserBinding::MODE_UNBOUND,
            ]);

            $reasons = [
                $kit['flow']->complete([], null)->reasonCode,
                $kit['flow']->complete(['state' => $bound], null)->reasonCode,
                $kit['flow']->complete(['state' => $unbound->value], 'x')->reasonCode,
                $kit['flow']->complete(['state' => $noConnection->value], null)->reasonCode,
                $kit['flow']->complete(['state' => 'aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb'], null)->reasonCode,
            ];

            Assert::same(count($reasons), count(array_unique($reasons)), 'no two causes share a code');
        },
];
