<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use craft\services\Users;
use InvalidArgumentException;
use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Core\Attribute\AttributeMapper;
use Keyway\Sso\Core\Diagnostics\DiagnosticsRecorder;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Login\BrowserBinding;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Core\Login\LoginConnection;
use Keyway\Sso\Core\Login\LoginFlow;
use Keyway\Sso\Core\Port\DiagnosticsSinkInterface;
use Keyway\Sso\Core\Port\IdentityLinkStoreInterface;
use Keyway\Sso\Core\Provisioning\ProvisioningPolicy;
use Keyway\Sso\Core\State\RedirectGuard;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Core\Support\RandomSource;
use Keyway\Sso\Core\Support\SystemClock;
use Keyway\Sso\Models\Settings;
use Keyway\Sso\Protocol\Oidc\CurlHttpClient;
use Keyway\Sso\Protocol\Oidc\JwksKeyStore;
use Keyway\Sso\Protocol\Oidc\OidcAuthorizationRequest;
use Keyway\Sso\Protocol\Oidc\OidcDiscovery;
use Keyway\Sso\Protocol\Oidc\OidcTokenReader;
use Keyway\Sso\Protocol\Oidc\RejectionDetail;
use Keyway\Sso\Protocol\Saml\SamlAuthnRequest;
use Keyway\Sso\Protocol\Saml\SamlResponseReader;
use yii\caching\CacheInterface;
use yii\mutex\Mutex;

/**
 * The composition root: the one place where settings and Craft's services become a LoginFlow.
 *
 * Every other class in this plugin receives what it needs. This one goes and gets it, which is
 * why it is the only class allowed to know that a StateStore is backed by the cache, that the
 * replay guard and the state share a mutex, and which reader belongs to which protocol. Wiring
 * spread across a controller, a plugin class and a service is wiring that drifts; there is
 * exactly one assembly and it is here.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: reach for `Craft::$app`. The cache, the mutex and the user
 * service arrive as arguments, so the whole assembly can be built and inspected in a test
 * without an application, a database or a request - which is the only way the wiring rules below
 * (one cache for the record and its burn marker, the mutex actually reaching the storage, the
 * callback style matching the protocol) get checked more than once.
 *
 * WHAT IT REFUSES TO BUILD, and why refusing is the right answer: when the protocol is disabled
 * or the configuration would not survive being turned into objects, loginFlow() returns null.
 * The login screen then behaves exactly as it did before the plugin was installed. A half-built
 * flow that throws on the first click would break the page people use to get in.
 */
final class CraftLoginRuntime
{
    /**
     * Both halves of the SAML round trip travel over Craft's own request, so the ACS URL is the
     * cookie path and the "RelayState" field is where the state comes back.
     */
    private const SAML_STATE_PARAMETER = 'RelayState';
    private const OIDC_STATE_PARAMETER = 'state';

    private Settings $settings;
    private CacheInterface $cache;
    private ?Mutex $mutex;
    private Users $users;
    private DiagnosticsSinkInterface $sink;
    private IdentityLinkStoreInterface $links;

    private ?LoginFlow $flow = null;
    private bool $built = false;
    private ?DiagnosticsRecorder $recorder = null;

    /**
     * @param Mutex|null $mutex Craft's `mutex` component. Nullable and with NO default, for the
     *                          reason SingleUseKeys spells out: passing null downgrades the
     *                          single-use guarantee to a read-then-write on the default file
     *                          cache, so it has to be something somebody typed.
     * @param IdentityLinkStoreInterface $links Where "this connection created this account" is
     *                          recorded. Required and with no default, like everything else
     *                          here: a flow assembled without it would refuse every second
     *                          just-in-time login, which is the bug this argument exists to fix.
     */
    public function __construct(
        Settings $settings,
        CacheInterface $cache,
        ?Mutex $mutex,
        Users $users,
        DiagnosticsSinkInterface $sink,
        IdentityLinkStoreInterface $links
    ) {
        $this->settings = $settings;
        $this->cache = $cache;
        $this->mutex = $mutex;
        $this->users = $users;
        $this->sink = $sink;
        $this->links = $links;
    }

    /**
     * The assembled flow, or null when this site is not configured to sign anybody in with it.
     */
    public function loginFlow(): ?LoginFlow
    {
        if (!$this->built) {
            $this->built = true;
            $this->flow = $this->build();
        }

        return $this->flow;
    }

    /**
     * The recorder the flow writes with.
     *
     * Handed out because the LAST step of a login - writing the account and starting the session
     * - happens in the Craft layer, after LoginFlow has said its piece, and a failure there
     * ("Craft would not save the user", "this account cannot reach the control panel") has to
     * land on the same diagnostics timeline as everything before it. It is the same instance the
     * flow uses, so the rows come from one sequence rather than two that interleave by luck.
     *
     * It hands out a recorder and not a sink: the recorder is what masks the payload.
     */
    public function diagnostics(): DiagnosticsRecorder
    {
        return $this->recorder ??= new DiagnosticsRecorder(
            $this->sink,
            new SystemClock(),
            new RandomSource()
        );
    }

    private function build(): ?LoginFlow
    {
        $protocol = $this->settings->protocol();

        if (!$protocol->isEnabled() || !$this->settings->isReadyToSignIn()) {
            return null;
        }

        $clock = new SystemClock();
        $random = new RandomSource();

        // One cache handle for the state and for the marker that burns it - CraftStateStorage
        // explains why asking for two would be a fail-open hole.
        $stateStore = new StateStore(
            new CraftStateStorage($this->cache, $this->mutex),
            $clock,
            $random,
            new RedirectGuard()
        );

        $replayGuard = new CraftReplayGuard(new SingleUseKeys($this->cache, $this->mutex), $clock);

        try {
            $connection = $protocol === AuthProtocol::Saml
                ? $this->samlConnection($stateStore, $replayGuard, $clock, $random)
                : $this->oidcConnection($stateStore, $replayGuard, $clock, $random);
        } catch (InvalidArgumentException) {
            // isReadyToSignIn() already asked the same question; this is the answer to "what if
            // the two ever disagree", and the answer is that the login screen keeps working.
            return null;
        }

        return new LoginFlow(
            $stateStore,
            new BrowserBinding($random),
            new AttributeMapper($this->settings->attributeMap()),
            new GroupMapper($this->settings->groupMap()),
            new ProvisioningPolicy($this->settings->provisioning()),
            new CraftUserDirectory($this->users),
            $this->links,
            $this->diagnostics(),
            [$connection],
            $connection->handle
        );
    }

    private function samlConnection(
        StateStore $stateStore,
        CraftReplayGuard $replayGuard,
        SystemClock $clock,
        RandomSource $random
    ): LoginConnection {
        $config = $this->settings->samlConnection();

        return new LoginConnection(
            new SamlResponseReader($config, $clock, $stateStore, $replayGuard),
            new SamlAuthnRequest($config, $stateStore, $clock, $random),
            CallbackStyle::CrossSitePost,
            $config->acsUrl,
            self::SAML_STATE_PARAMETER
        );
    }

    private function oidcConnection(
        StateStore $stateStore,
        CraftReplayGuard $replayGuard,
        SystemClock $clock,
        RandomSource $random
    ): LoginConnection {
        $config = $this->settings->oidcConnection();
        $detail = new RejectionDetail();
        $http = new CurlHttpClient();

        // The site cache, not a per-request array: contract C5's "at most one JWKS refresh per
        // rejected kid, rate limited" is only a limit if it survives the request.
        $documents = new CraftKeyValueCache($this->cache);

        $discovery = new OidcDiscovery($config, $http, $documents, $clock, $detail);
        $keys = new JwksKeyStore($config, $discovery, $http, $documents, $clock, $detail);

        return new LoginConnection(
            new OidcTokenReader(
                $config,
                $discovery,
                $keys,
                $clock,
                $stateStore,
                $replayGuard,
                $http,
                $detail
            ),
            new OidcAuthorizationRequest($config, $discovery, $stateStore, $random),
            CallbackStyle::TopLevelRedirect,
            $config->redirectUri,
            self::OIDC_STATE_PARAMETER
        );
    }
}
