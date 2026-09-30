<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

use InvalidArgumentException;
use Keyway\Sso\Core\Attribute\AttributeMapper;
use Keyway\Sso\Core\Attribute\AttributeMappingException;
use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Diagnostics\DiagnosticsRecorder;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Identity\IdentityReaderException;
use Keyway\Sso\Core\Port\IdentityLinkStoreInterface;
use Keyway\Sso\Core\Port\RejectionDetailInterface;
use Keyway\Sso\Core\Port\UserDirectoryInterface;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Core\Provisioning\ProvisioningPolicy;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Core\State\StateStore;
use Keyway\Sso\Core\Support\Ascii;
use RuntimeException;
use Throwable;

/**
 * The whole login round trip as one framework-free object: begin() sends somebody to their
 * identity provider, complete() decides what happens when they come back.
 *
 * NOTHING HERE PERFORMS ANYTHING. begin() returns "redirect there, set this cookie" and
 * complete() returns "sign this person in / create them first / refuse, and here is why". The
 * Craft controller turns those values into a response. That is the same split ProvisioningDecision
 * already made for user writes, extended to the rest of the flow, and it is what lets every rule
 * below be tested with no database, no HTTP and no CMS.
 *
 * ------------------------------------------------------------------------------------------
 * THE ORDER OF THE GATES IN complete(), which is the security design and not a style choice
 * ------------------------------------------------------------------------------------------
 *
 *  1. Find the state field. Cheap, and it fails closed when two connections' fields arrive at
 *     once instead of guessing which login this is.
 *  2. INSPECT the state - verified, not burnt (Core\State\StateInspection explains why the burn
 *     cannot happen here).
 *  3. `connection` from the state chooses the reader. Never the current settings: see below.
 *  4. Browser binding. Fails closed, with a distinct reason per cause (BindingStatus).
 *  5. Only now the reader runs - and the reader burns the state before it touches the network.
 *  6. Verify the state really was burnt, which is what makes step 2's non-burning read safe.
 *  7. Mapping, groups, provisioning. These read the user table, so they come last.
 *
 * Nothing before step 5 makes a network call or a database query, so a callback carrying a bad
 * state or a bad binding costs one cache read.
 *
 * ------------------------------------------------------------------------------------------
 * WHY `connection` MISSING IS A REFUSAL AND NEVER "USE THE DEFAULT ONE"
 * ------------------------------------------------------------------------------------------
 *
 * The handle in the state answers "which identity provider's certificate validates this
 * response". It can go missing for two reasons that look identical from here - the storage
 * layer filtered it on the way in, or the starter rebuilt the context on the way out - and
 * neither is visible at the callback. Falling back to the configured connection would turn a
 * dropped key into a choice of security configuration made from data that is not there; with a
 * second connection configured, that is one provider's assertion validated against another
 * provider's trust anchor. So it is refused, loudly, with its own reason code.
 *
 * The same reasoning gives the browser binding its own explicit MODE_UNBOUND marker rather than
 * letting "no hash in the context" mean "no binding was issued".
 */
final class LoginFlow
{
    /** Upper bound on a reader's detail inside a diagnostics message (which is capped at 1024). */
    private const MAX_DETAIL_BYTES = 400;

    private StateStore $stateStore;
    private BrowserBinding $binding;
    private AttributeMapper $attributes;
    private GroupMapper $groups;
    private ProvisioningPolicy $provisioning;
    private UserDirectoryInterface $directory;
    private IdentityLinkStoreInterface $links;
    private DiagnosticsRecorder $diagnostics;

    /** @var array<string, LoginConnection> */
    private array $connections = [];

    private ?string $activeConnection;

    /**
     * @param list<LoginConnection> $connections
     * @param string|null $activeConnection Handle begin() starts a login with. Null means single
     *                                      sign-on is configured but not usable, and begin()
     *                                      refuses; complete() still works, so a login that was
     *                                      already in flight when the settings changed gets a
     *                                      diagnosable refusal instead of a blank page.
     */
    public function __construct(
        StateStore $stateStore,
        BrowserBinding $binding,
        AttributeMapper $attributes,
        GroupMapper $groups,
        ProvisioningPolicy $provisioning,
        UserDirectoryInterface $directory,
        IdentityLinkStoreInterface $links,
        DiagnosticsRecorder $diagnostics,
        array $connections,
        ?string $activeConnection
    ) {
        foreach ($connections as $connection) {
            if (!$connection instanceof LoginConnection) {
                throw new InvalidArgumentException('Every connection must be a LoginConnection.');
            }

            if (isset($this->connections[$connection->handle])) {
                throw new InvalidArgumentException(sprintf(
                    'Connection handle "%s" is registered twice; the callback could not tell '
                    . 'them apart.',
                    $connection->handle
                ));
            }

            $this->connections[$connection->handle] = $connection;
        }

        if ($activeConnection !== null && !isset($this->connections[$activeConnection])) {
            throw new InvalidArgumentException(sprintf(
                'Active connection "%s" is not among the registered ones.',
                $activeConnection
            ));
        }

        $this->stateStore = $stateStore;
        $this->binding = $binding;
        $this->attributes = $attributes;
        $this->groups = $groups;
        $this->provisioning = $provisioning;
        $this->directory = $directory;
        $this->links = $links;
        $this->diagnostics = $diagnostics;
        $this->activeConnection = $activeConnection;
    }

    /**
     * Starts a login: mints the browser binding, has the protocol layer issue the state and
     * build the request, and hands back where to go and what to set.
     */
    public function begin(?string $returnUrl = null): LoginStart
    {
        if ($this->activeConnection === null) {
            return LoginStart::refused(
                LoginRefusal::NOT_CONFIGURED,
                'Single sign-on is not configured, or the configuration is not usable as saved.'
            );
        }

        $connection = $this->connections[$this->activeConnection];

        if (!$connection->canStart()) {
            return LoginStart::refused(
                LoginRefusal::CONNECTION_CANNOT_START,
                sprintf(
                    'Connection "%s" can validate a response but cannot build a request yet, so '
                    . 'a login cannot be started with it.',
                    $connection->handle
                )
            );
        }

        $issued = $this->binding->issue(
            $connection->callbackUrl,
            $connection->callbackStyle,
            $this->stateStore->ttl()
        );

        try {
            $start = $connection->starter()?->start($returnUrl, array_merge(
                $issued->context(),
                ['connection' => $connection->handle]
            ));
        } catch (RuntimeException $error) {
            // THE CATCH THAT KEEPS THE LOGIN SCREEN A LOGIN SCREEN. Building a request talks to
            // the outside world: OidcAuthorizationRequest::start() fetches the discovery
            // document first and IdentityReaderException (a RuntimeException) comes back from
            // every failed fetch, and SamlAuthnRequest throws when DEFLATE fails. Letting either
            // escape would turn "the identity provider is down" - the single most likely fault
            // on a live site - into a 500 on the page the administrator needs in order to fix
            // it. It is caught HERE rather than in the controller because it is a decision
            // (which refusal, which diagnostic row), and decisions in a controller are decisions
            // nobody can test; begin() already returns a refusal for every other way a login can
            // fail to start, and a value-returning API that sometimes throws instead is the trap.
            $event = $this->diagnostics->recordFailure(
                $connection->handle,
                DiagnosticEvent::STAGE_PROTOCOL,
                LoginRefusal::START_FAILED,
                self::startFailure($error, $connection)
            );

            return LoginStart::refused(
                LoginRefusal::START_FAILED,
                'The authentication request could not be built. ' . $error->getMessage(),
                $event
            );
        }

        if ($start === null) {
            // Unreachable while canStart() guards the call; kept because "unreachable" is a
            // property of today's code, and the alternative to a refusal here is a null deref.
            return LoginStart::refused(
                LoginRefusal::CONNECTION_CANNOT_START,
                'The connection produced no authentication request.'
            );
        }

        // Read our own state back before the browser leaves. A starter that rebuilt the context
        // instead of merging it has just made the callback impossible to verify, and this is the
        // only moment where that failure can still point at its cause.
        $written = $this->stateStore->inspect($start->state()->value)->context();

        if (($written['connection'] ?? '') !== $connection->handle
            || !isset($written[BrowserBinding::CONTEXT_MODE])
        ) {
            $event = $this->diagnostics->recordFailure(
                $connection->handle,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::STATE_CONTEXT_LOST,
                'The login state was issued without the connection handle or the browser-binding '
                . 'decision, so the callback could never verify it. The authentication request '
                . 'builder for this connection is not passing the context through.'
            );

            return LoginStart::refused(
                LoginRefusal::STATE_CONTEXT_LOST,
                'The login state was issued without the bookkeeping the callback needs.',
                $event
            );
        }

        if (!$issued->bound) {
            $this->diagnostics->recordNotice(
                $connection->handle,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::BINDING_NOT_ISSUED,
                'This login is running WITHOUT a browser binding: the callback for this '
                . 'connection is a cross-site POST, which needs a SameSite=None cookie, and a '
                . 'browser only accepts one of those over HTTPS. Serve the callback URL over '
                . 'HTTPS to close the login-CSRF gap.'
            );
        }

        return LoginStart::go($start->url(), $issued->cookie);
    }

    /**
     * Finishes a login. See the class docblock for why the gates run in this order.
     *
     * @param array<string, mixed> $request        Raw callback input: POST fields or query
     *                                             string, exactly as IdentityReaderInterface
     *                                             takes it.
     * @param string|null          $bindingCookie  Value of BrowserBinding::COOKIE_NAME, or null
     *                                             when the browser sent none.
     */
    public function complete(array $request, ?string $bindingCookie): LoginCompletion
    {
        [$token, $parameter] = $this->findStateToken($request);

        if ($parameter === null) {
            return $this->refuse(
                null,
                DiagnosticEvent::STAGE_STATE,
                $token === '' ? LoginRefusal::STATE_MISSING : LoginRefusal::STATE_AMBIGUOUS,
                $token === ''
                    ? 'The callback carries no login state, so it cannot be matched to a login '
                        . 'this site started.'
                    : 'The callback carries state fields for more than one connection at once.'
            );
        }

        $inspection = $this->stateStore->inspect($token);

        if (!$inspection->valid) {
            return $this->refuse(
                null,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::STATE_REJECTED,
                $inspection->message() . ' (' . $inspection->reasonCode . ')'
            );
        }

        $context = $inspection->context();
        $handle = Ascii::trim($context['connection'] ?? '');

        if ($handle === '') {
            return $this->refuse(
                null,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::CONNECTION_MISSING,
                'The login state does not say which connection it belongs to, so there is no '
                . 'way to know whose certificate should validate this response. Refused rather '
                . 'than validated against the currently configured connection.'
            );
        }

        $connection = $this->connections[$handle] ?? null;

        if ($connection === null) {
            return $this->refuse(
                null,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::CONNECTION_UNKNOWN,
                sprintf(
                    'The login state was issued for connection "%s", which this site no longer '
                    . 'has configured. It was most likely changed while this login was in flight.',
                    $handle
                )
            );
        }

        if ($connection->stateParameter !== $parameter) {
            return $this->refuse(
                $connection,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::CONNECTION_MISMATCH,
                sprintf(
                    'The login state for connection "%s" came back in the "%s" field, which '
                    . 'belongs to a different protocol.',
                    $handle,
                    $parameter
                )
            );
        }

        $status = $this->binding->verify($context, $bindingCookie);

        if (!$status->allowsLogin()) {
            return $this->refuse(
                $connection,
                DiagnosticEvent::STAGE_STATE,
                self::bindingReason($status),
                self::bindingMessage($status)
            );
        }

        if ($status === BindingStatus::NotIssued) {
            $this->diagnostics->recordNotice(
                $connection->handle,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::BINDING_NOT_ISSUED,
                'This login was accepted without a browser binding, because none could be issued '
                . 'when it started. Serve the callback URL over HTTPS to close the login-CSRF gap.'
            );
        }

        try {
            $payload = $connection->reader()->read($request);
        } catch (IdentityReaderException $error) {
            return $this->refuse(
                $connection,
                DiagnosticEvent::STAGE_PROTOCOL,
                LoginRefusal::IDENTITY_REJECTED,
                $error->getMessage() . ' (' . $error->reasonCode() . ')' . self::detailOf($connection),
                $status
            );
        }

        // The reader owns the burn (it needs the state's contents first). If it returned an
        // identity without burning, the state is still replayable, and an accepted login is the
        // one outcome we cannot allow that to have.
        if (!$this->stateStore->wasConsumed((string)$inspection->id)) {
            return $this->refuse(
                $connection,
                DiagnosticEvent::STAGE_STATE,
                LoginRefusal::STATE_NOT_BURNT,
                'The response verified but the login state was not marked as used, so it could '
                . 'be replayed. Refused.',
                $status,
                $payload
            );
        }

        try {
            $mapped = $this->attributes->map($payload);
        } catch (AttributeMappingException $error) {
            return $this->refuse(
                $connection,
                DiagnosticEvent::STAGE_ATTRIBUTES,
                LoginRefusal::ATTRIBUTES_REJECTED,
                $error->getMessage(),
                $status,
                $payload
            );
        }

        $assignment = $this->groups->map($payload);
        $user = $this->lookup($mapped);
        $decision = $this->provisioning->decide(
            $mapped,
            $assignment,
            $user,
            $this->identityOwnsAccount($connection, $user, $payload)
        );

        $event = $this->diagnostics->recordDecision($connection->reader()->protocol(), $payload, $decision);
        $clear = $this->binding->clear($connection->callbackUrl, $connection->callbackStyle);

        if ($decision->isDenied()) {
            return LoginCompletion::refuse(
                $decision->reasonCode,
                $decision->message,
                $clear,
                $decision,
                $event,
                $status === BindingStatus::Verified
            );
        }

        return LoginCompletion::allow(
            $decision,
            $inspection->returnUrl,
            $clear,
            $event,
            $status === BindingStatus::Verified,
            // Unmasked, and taken from the payload rather than from the event: this is what the
            // Craft layer writes the identity link from once the account has an id, and a masked
            // issuer would match nothing on the next login. See LoginCompletion.
            $payload->issuer(),
            // EXACTLY the value the reader settled on as the subject - the same string the
            // identity link is written from a few lines later in the controller. Single logout
            // compares this byte for byte against what the IdP sends, so both sides of that
            // comparison have to come out of the same normalisation step; re-deriving it from
            // the raw assertion here would compare one normalisation against another and turn a
            // correct LogoutRequest into a silent unknownPrincipal.
            $payload->nameId(),
            $payload->sessionIndex()
        );
    }

    /**
     * Which registered connection's state field this callback carries.
     *
     * Returning the field name rather than taking it from the route is what lets the controller
     * stay a translator: the route says nothing about which connection this is, and anything the
     * route DID say would be attacker-controlled, whereas the state's own contents are not.
     *
     * @param array<string, mixed> $request
     * @return array{0: string, 1: string|null} [token or '' , field name or null when unusable]
     */
    private function findStateToken(array $request): array
    {
        $found = [];

        foreach ($this->connections as $connection) {
            $value = $request[$connection->stateParameter] ?? null;

            if (is_string($value) && Ascii::trim($value) !== '') {
                $found[$connection->stateParameter] = Ascii::trim($value);
            }
        }

        if ($found === []) {
            return ['', null];
        }

        if (count($found) > 1) {
            return ['ambiguous', null];
        }

        $parameter = array_key_first($found);

        return [$found[$parameter], $parameter];
    }

    private function lookup(MappedAttributes $mapped): ?ExistingUser
    {
        $key = $this->provisioning->lookupKeyFor($mapped);

        if ($key === null) {
            // The policy denies on a missing match key with its own reason code; looking nobody
            // up is the honest input to that decision.
            return null;
        }

        return $this->provisioning->matchBy() === UserMatchKey::Email
            ? $this->directory->findByEmail($key)
            : $this->directory->findByUsername($key);
    }

    /**
     * Did THIS issuer create THIS account FOR THIS PERSON? The fact step 4a of the provisioning
     * policy was missing until 2026-09-15, when a live Craft with Okta refused every second
     * login.
     *
     * THE SUBJECT IS PART OF THE QUESTION, and it is what makes this a question about a person
     * rather than about a directory: (account, issuer) alone is satisfied by anybody else at the
     * same identity provider who puts this address in their own profile. The site owner took
     * that decision knowing what it costs - an administrator has to step in whenever an identity
     * provider re-issues a name id - and accepted that price deliberately.
     *
     * FAILS CLOSED, THREE TIMES OVER. No account, no issuer, no subject, a store that is not
     * ready, or a store that cannot answer all produce false, and false means the policy treats
     * the account as one this connection did not create - a refusal, never an unguarded link.
     * IdentityLinkStoreInterface already requires its implementations not to throw; the catch
     * here is the second layer, because the cost of being wrong about that is a 500 on the login
     * screen rather than a refused login, and a core class that can be broken by an adapter is a
     * core class that is not framework-free.
     *
     * AND IT SAYS SO OUT LOUD when the record is unavailable. A missing table is otherwise a
     * SILENT fault: the shipped adapter swallows its own database errors, so nothing throws, the
     * answer is a truthful "not linked", and the administrator reads `linking_disabled` - whose
     * advice is to switch linking on for every account on the site. The notice below is the
     * difference between "run `craft up`" and "open the door".
     */
    private function identityOwnsAccount(
        LoginConnection $connection,
        ?ExistingUser $user,
        IdentityPayload $payload
    ): bool {
        $issuer = Ascii::trim($payload->issuer());
        $subject = Ascii::trim($payload->nameId());

        if ($user === null || $issuer === '' || $subject === '' || $user->id === '') {
            return false;
        }

        try {
            if (!$this->links->isReady()) {
                $this->noticeLinkStoreUnavailable(
                    $connection,
                    'The record of which accounts single sign-on created is not available - the '
                    . 'plugin\'s table is missing.'
                );

                return false;
            }

            return $this->links->isLinkedTo($user->id, $issuer, $subject);
        } catch (Throwable $error) {
            // The exception's own message is deliberately NOT copied into the notice: a Yii
            // database exception carries the statement, and DiagnosticEvent length-caps the
            // message field without masking it, so the SQL would be stored and shown in the
            // support panel. The class name says what kind of fault it was and carries no data.
            $this->noticeLinkStoreUnavailable(
                $connection,
                sprintf(
                    'The record of which accounts single sign-on created could not be read (%s).',
                    self::shortClass($error)
                )
            );

            return false;
        }
    }

    /**
     * The one wording for "the link record is unavailable", in both directions of the failure.
     *
     * The protocol is taken from the reader, the same way the decision row on this login takes
     * it, so a support session filtering by protocol sees the notice and the refusal together.
     */
    private function noticeLinkStoreUnavailable(LoginConnection $connection, string $what): void
    {
        $this->diagnostics->recordNotice(
            $connection->reader()->protocol(),
            DiagnosticEvent::STAGE_PROVISIONING,
            LoginRefusal::IDENTITY_LINK_UNAVAILABLE,
            $what . ' This login was decided as if the account had not been created here, which '
            . 'refuses accounts that were. Check that the plugin\'s migrations have run '
            . '(`craft up`).'
        );
    }

    /** Class name without its namespace: enough to tell a database fault from a type error. */
    private static function shortClass(Throwable $error): string
    {
        $name = $error::class;
        $position = strrpos($name, '\\');

        return $position === false ? $name : substr($name, $position + 1);
    }

    private function refuse(
        ?LoginConnection $connection,
        string $stage,
        string $reasonCode,
        string $message,
        ?BindingStatus $status = null,
        ?IdentityPayload $payload = null
    ): LoginCompletion {
        $protocol = $connection?->handle ?? 'unknown';

        $event = $this->diagnostics->recordFailure($protocol, $stage, $reasonCode, $message, $payload);

        // The cookie comes off even when the state never said which connection this was - and
        // it has to come off ON THE PATH IT WAS SET ON. A browser keys a cookie on (name,
        // domain, PATH), so a deletion issued for "/" does NOT remove one stored under
        // "/actions/keyway-sso/sso/acs": every callback with a missing or mangled state - which
        // is every scanner and every retry - would otherwise leave the binding secret in the
        // browser until its TTL ran out. So an unidentified callback falls back to the
        // connection this site would start a login with, which is the one that set the cookie.
        $target = $connection ?? $this->clearTargetConnection();

        $clear = $target === null
            ? $this->binding->clear('', CallbackStyle::TopLevelRedirect)
            : $this->binding->clear($target->callbackUrl, $target->callbackStyle);

        return LoginCompletion::refuse(
            $reasonCode,
            $message,
            $clear,
            null,
            $event,
            $status === BindingStatus::Verified
        );
    }

    /**
     * Administrator-facing text for a start that threw.
     *
     * The reader's own reason code is appended when there is one, exactly as complete() does for
     * a rejected response: `discovery_failed` and `issuer_mismatch` send an administrator to two
     * different places, and the sentence alone does not always separate them.
     */
    private static function startFailure(RuntimeException $error, LoginConnection $connection): string
    {
        $message = 'The authentication request could not be built. ' . $error->getMessage();

        return $error instanceof IdentityReaderException
            ? $message . ' (' . $error->reasonCode() . ')' . self::detailOf($connection)
            : $message;
    }

    /**
     * What the reader kept aside about the rejection it has just thrown, ready to append.
     *
     * The reason code names the class of failure; this is the sentence that separates two
     * failures of the same class. A wrong OIDC client secret and a token endpoint answering
     * with a login page are both `malformed_response`, and without the detail the diagnostics
     * panel - the reason somebody bought this plugin - says the same thing for both.
     *
     * ONLY EVER CALLED RIGHT AFTER CATCHING AN IdentityReaderException from this connection.
     * The detail is "the last rejection", so asked at any other moment it could describe an
     * earlier one.
     *
     * THE TEXT IS NOT OURS: it quotes the identity provider and the callback (see
     * RejectionDetailInterface). It is cut down to printable ASCII and bounded here, goes only
     * to the diagnostics record and the log, and never into anything a visitor is shown -
     * LoginCompletion::publicMessage() and LoginStart::publicMessage() do not read `message`.
     */
    private static function detailOf(LoginConnection $connection): string
    {
        $reader = $connection->reader();

        if (!$reader instanceof RejectionDetailInterface) {
            return '';
        }

        $detail = Ascii::trim(Ascii::printable($reader->detail(), self::MAX_DETAIL_BYTES));

        return $detail === '' ? '' : ' Detail: ' . $detail;
    }

    /**
     * Whose cookie attributes to use when the callback never told us which connection it is.
     *
     * The active connection first, then a sole registered one. With SEVERAL connections
     * configured and no way to tell them apart, there is no honest answer - the callback could
     * have come from any of them - so it returns null and the caller deletes on "/". That
     * remaining case is the one place the deletion can miss, and it is stated rather than
     * papered over: today the composition root registers exactly one connection, so it is
     * unreachable in this product.
     */
    private function clearTargetConnection(): ?LoginConnection
    {
        if ($this->activeConnection !== null) {
            return $this->connections[$this->activeConnection];
        }

        return count($this->connections) === 1
            ? $this->connections[array_key_first($this->connections)]
            : null;
    }

    private static function bindingReason(BindingStatus $status): string
    {
        return match ($status) {
            BindingStatus::CookieMissing => LoginRefusal::BINDING_COOKIE_MISSING,
            BindingStatus::Mismatch => LoginRefusal::BINDING_MISMATCH,
            BindingStatus::Undeclared => LoginRefusal::BINDING_UNDECLARED,
            BindingStatus::Inconsistent => LoginRefusal::BINDING_INCONSISTENT,
            // Both remaining cases allow the login, so they never reach here; match() without a
            // default is what makes a new BindingStatus a fatal error instead of a silent pass.
            BindingStatus::Verified, BindingStatus::NotIssued => LoginRefusal::BINDING_UNDECLARED,
        };
    }

    private static function bindingMessage(BindingStatus $status): string
    {
        return match ($status) {
            BindingStatus::CookieMissing =>
                'This login was tied to the browser that started it, and the browser sent no '
                . 'binding cookie back. Either the response arrived in a different browser - '
                . 'which is what this check exists to stop - or something between the browser '
                . 'and this site strips cookies from the callback.',
            BindingStatus::Mismatch =>
                'The binding cookie the browser sent belongs to a different login. A response '
                . 'from the identity provider was presented to a browser that did not start it.',
            BindingStatus::Undeclared =>
                'The login state carries no record of whether a browser binding was issued. '
                . 'Refused: a binding that is inferred from a missing value can be switched off '
                . 'by sending nothing.',
            BindingStatus::Inconsistent =>
                'The login state says it was bound to a browser but carries no value to compare '
                . 'against.',
            BindingStatus::Verified, BindingStatus::NotIssued => 'Browser binding accepted.',
        };
    }
}
