<?php

declare(strict_types=1);

namespace Keyway\Sso\Models;

use craft\base\Model;
use craft\helpers\App;
use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Config\SettingsTranslator;
use Keyway\Sso\Core\Access\AdminFallbackSettings;
use Keyway\Sso\Core\Attribute\AttributeMap;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Provisioning\ProvisioningSettings;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Core\Support\SystemClock;
use Keyway\Sso\Protocol\Oidc\OidcConnectionConfig;
use Keyway\Sso\Protocol\Saml\SamlConnectionConfig;
use Keyway\Sso\Protocol\Saml\SpMetadata;

/**
 * Plugin settings, stored by Craft in project config.
 *
 * Deliberately dumb: public scalars and arrays, nothing else. Every rule about what these values
 * mean lives in SettingsTranslator, which has no Craft dependency and is covered by
 * `test/settings_translator_test.php`. This class only declares the shape, hands validation to
 * the translator and exposes typed accessors so the rest of the plugin never reads a raw
 * settings array.
 *
 * Two shapes of value are worth noting, because both are what Craft's own form controls hand
 * back and neither is a sign of sloppiness:
 *
 *  - `attributeRules`, `groupRules` and `adminRules` are lists of associative arrays, the format
 *    of an `editableTable` field;
 *  - `allowedDomains`, `emergencyAccounts`, `groupSourceAttributes` and `oidcScopes` accept
 *    either a list or a newline-separated textarea string, because that is what the settings
 *    screen posts.
 *
 * Secrets (`samlSpPrivateKey`, `oidcClientSecret`) are plain properties here, and the settings
 * screen writes them as environment-variable references (`$KEYWAY_OIDC_SECRET`). Craft parses
 * those on read, which keeps the secret out of project config and out of version control.
 */
class Settings extends Model
{
    // -- Which protocol -------------------------------------------------------------------

    /** @var string One of AuthProtocol: disabled, saml, oidc. */
    public string $protocol = AuthProtocol::Disabled->value;

    /** @var string Shown on the SSO button on the login screen. */
    public string $buttonLabel = 'Sign in with SSO';

    // -- SAML connection ------------------------------------------------------------------

    public string $samlIdpEntityId = '';

    /** @var string PEM or base64 X.509. A fingerprint is rejected; see SamlConnectionConfig. */
    public string $samlIdpCertificate = '';

    /** @var string The IdP's HTTP-Redirect SSO endpoint: where the AuthnRequest is sent. */
    public string $samlIdpSsoUrl = '';

    /**
     * Where the IdP receives LogoutRequests, and the address its own LogoutRequests come from.
     *
     * Optional, and single logout is off while it is empty: SamlConnectionConfig::canLogout()
     * wants this, our own SLO endpoint and a signing key together, because an SLO advertised
     * without all three is an endpoint that answers with checks that were never configured.
     */
    public string $samlIdpSloUrl = '';

    public string $samlSpEntityId = '';
    public string $samlAcsUrl = '';

    /** @var string|null Only needed for encrypted assertions. Store as an env reference. */
    public ?string $samlSpPrivateKey = null;

    public int $samlClockSkew = 60;

    // -- OIDC connection ------------------------------------------------------------------

    public string $oidcIssuer = '';
    public string $oidcClientId = '';

    /** @var string|null Null means a public client; PKCE is mandatory either way. */
    public ?string $oidcClientSecret = null;

    public string $oidcRedirectUri = '';

    /** @var list<string>|string */
    public $oidcScopes = ['openid', 'profile', 'email'];

    public int $oidcClockSkew = 60;
    public bool $oidcFetchUserinfo = false;

    // -- Attribute mapping ----------------------------------------------------------------

    /**
     * Rows of: source, target, strategy, required, defaultValue, transform, separator.
     * An empty table means "use the shipped defaults", not "map nothing".
     *
     * @var list<array<string, mixed>>
     */
    public array $attributeRules = [];

    // -- Group mapping --------------------------------------------------------------------

    /** @var list<array<string, mixed>> Rows of: matchType, pattern, targetGroup. */
    public array $groupRules = [];

    /** @var list<array<string, mixed>> Rows of: matchType, pattern. Grants Craft admin. */
    public array $adminRules = [];

    public ?string $defaultGroup = null;

    /** @var list<string>|string */
    public $groupSourceAttributes = ['groups'];

    /** @var string One of GroupSyncMode. */
    public string $groupSyncMode = GroupSyncMode::Append->value;

    public bool $groupMatchCaseSensitive = false;
    public bool $allowAdminEscalation = false;
    public bool $revokeAdminWhenUnmatched = false;

    // -- JIT provisioning -----------------------------------------------------------------

    public bool $allowJit = true;
    public bool $updateOnLogin = true;
    public bool $denyIfNoGroupMatch = false;

    /** @var string One of UserMatchKey: email, username. */
    public string $matchBy = UserMatchKey::Email->value;

    /** @var list<string>|string Empty means any domain. */
    public $allowedDomains = [];

    public bool $linkExistingAccounts = false;
    public bool $linkAdminAccounts = false;

    // -- Lockout safety net ---------------------------------------------------------------

    public bool $ssoOnly = false;
    public bool $allowPasswordForAdmins = true;

    /** @var list<string>|string E-mail addresses or usernames that may always use a password. */
    public $emergencyAccounts = [];

    public bool $breakGlassEnabled = false;

    /** @var int|null Unix timestamp; capped at AdminFallbackSettings::BREAK_GLASS_MAX_TTL. */
    public ?int $breakGlassExpiresAt = null;

    /**
     * Fields the settings screen offers as environment variables (`suggestEnvVars: true`).
     *
     * @var list<string>
     */
    private const ENV_AWARE = ['samlSpPrivateKey', 'oidcClientSecret'];

    /**
     * Settings as the translator should see them: env references resolved to their values.
     *
     * This is the only place in the plugin that knows environment variables exist. The
     * translator and the core read a plain array and must keep working without Craft, so the
     * expansion happens here, on the boundary, and not one layer deeper.
     *
     * An unresolved reference (`$KEYWAY_SP_KEY` with nothing behind it) never reaches the
     * translator as the literal `$KEYWAY_SP_KEY`, because a dollar sign is not a key: the
     * plugin would report that it can decrypt assertions and then fail inside OpenSSL on the
     * first encrypted one. It arrives as an empty value, which the translator reads as "no
     * secret", and `unresolvedEnvReferences()` separately stops the configuration from
     * counting as ready - being silently treated as "no secret" is exactly the other half of
     * the bug for OIDC, where it downgrades a confidential client to a public one.
     *
     * @return array<string, mixed>
     */
    private function resolvedAttributes(?string $spSloUrl = null): array
    {
        $attributes = $this->getAttributes();

        // Not a declared property and deliberately not one - see samlConnection(). Empty string
        // reads as "no single logout" to the translator's nullableStr(), which is what an absent
        // argument must mean.
        $attributes['samlSpSloUrl'] = $spSloUrl ?? '';

        foreach (self::ENV_AWARE as $name) {
            $raw = $attributes[$name] ?? null;
            if (!is_string($raw) || $raw === '') {
                continue;
            }

            $parsed = App::parseEnv($raw);
            if (is_bool($parsed)) {
                $parsed = $parsed ? 'true' : 'false';
            }

            $attributes[$name] = $parsed ?? '';
        }

        return $attributes;
    }

    /**
     * Env-aware fields holding a reference to a variable that is not set, or is empty.
     *
     * @return list<string>
     */
    private function unresolvedEnvReferences(): array
    {
        $unresolved = [];

        foreach (self::ENV_AWARE as $name) {
            $raw = $this->$name;
            if (is_string($raw) && $raw !== '' && str_contains($raw, '$') && App::parseEnv($raw) === null) {
                $unresolved[] = $name;
            }
        }

        return $unresolved;
    }

    /**
     * Says which variable is missing, rather than letting the empty-secret rejection speak.
     *
     * @param string $attribute the env-aware field being validated.
     */
    public function validateEnvReference(string $attribute): void
    {
        if (!in_array($attribute, $this->unresolvedEnvReferences(), true)) {
            return;
        }

        $this->addError($attribute, sprintf(
            'Environment variable %s is not set, or is empty. Set it, or clear this field.',
            (string)$this->$attribute
        ));
    }

    /**
     * @inheritdoc
     */
    protected function defineRules(): array
    {
        return [
            [['protocol'], 'in', 'range' => AuthProtocol::values()],
            [['groupSyncMode'], 'in', 'range' => array_column(GroupSyncMode::cases(), 'value')],
            [['matchBy'], 'in', 'range' => array_column(UserMatchKey::cases(), 'value')],
            [
                ['samlClockSkew'],
                'integer',
                'min' => 0,
                'max' => SamlConnectionConfig::MAX_CLOCK_SKEW,
            ],
            [
                ['oidcClockSkew'],
                'integer',
                'min' => 0,
                'max' => OidcConnectionConfig::MAX_CLOCK_SKEW,
            ],
            [['buttonLabel'], 'string', 'max' => 120],
            [['samlSpPrivateKey', 'oidcClientSecret'], 'validateEnvReference'],
            [['protocol'], 'validateConfiguration'],
        ];
    }

    /**
     * Runs every core object builder and reports whatever refused to be built.
     *
     * The validation lives in the objects that enforce the rule, not in a second copy of it
     * here: if SamlConnectionConfig will not accept a fingerprint in place of a certificate,
     * the settings screen says so in the same words, and the two cannot drift apart.
     *
     * @param string $attribute unused; errors are attached per offending field.
     */
    public function validateConfiguration(string $attribute): void
    {
        foreach (SettingsTranslator::problems($this->resolvedAttributes(), (new SystemClock())->now()) as [$field, $message]) {
            $this->addError($this->hasProperty($field) ? $field : $attribute, $message);
        }
    }

    public function protocol(): AuthProtocol
    {
        return SettingsTranslator::protocol($this->resolvedAttributes());
    }

    public function attributeMap(): AttributeMap
    {
        return SettingsTranslator::attributeMap($this->resolvedAttributes());
    }

    public function groupMap(): GroupMap
    {
        return SettingsTranslator::groupMap($this->resolvedAttributes());
    }

    public function provisioning(): ProvisioningSettings
    {
        return SettingsTranslator::provisioning($this->resolvedAttributes());
    }

    public function adminFallback(): AdminFallbackSettings
    {
        return SettingsTranslator::adminFallback($this->resolvedAttributes());
    }

    public function samlConnection(?string $spSloUrl = null): SamlConnectionConfig
    {
        // Our own single logout address is DERIVED, never stored: Plugin::sloUrl() builds it
        // from the registered route, the same way the metadata URL is built, so it cannot drift
        // from the endpoint that actually answers. Callers that have no Craft application around
        // them (tests, the settings screen's validation) pass nothing and get a connection with
        // single logout off - the safe half of the branch.
        return SettingsTranslator::samlConnection($this->resolvedAttributes($spSloUrl));
    }

    public function oidcConnection(): OidcConnectionConfig
    {
        return SettingsTranslator::oidcConnection($this->resolvedAttributes());
    }

    /**
     * The SP metadata document for this configuration, or null when there is nothing to publish.
     *
     * `resolvedAttributes()` and not the raw properties, for consistency with every accessor
     * above it - but for these two fields it is a pass-through today, and saying so is the point:
     * `ENV_AWARE` covers only the secrets (`samlSpPrivateKey`, `oidcClientSecret`), and neither
     * `samlSpEntityId` nor `samlAcsUrl` is offered with `suggestEnvVars` on the settings screen.
     * An entity id written as `$KEYWAY_SP_ENTITY_ID` therefore reaches the document verbatim.
     * Whether those two fields SHOULD accept an environment reference is a product decision that
     * touches the screen and project config, not something to infer from this line.
     */
    public function spMetadata(?int $validUntil = null, ?string $spSloUrl = null): ?SpMetadata
    {
        return SettingsTranslator::spMetadata($this->resolvedAttributes($spSloUrl), $validUntil);
    }

    /**
     * True when this configuration could actually sign somebody in right now.
     *
     * The login screen asks this before it renders the SSO button: a button that leads to a
     * configuration error is worse than no button, because the person clicking it is usually
     * the one who cannot get in.
     */
    public function isReadyToSignIn(): bool
    {
        if ($this->unresolvedEnvReferences() !== []) {
            return false;
        }

        return SettingsTranslator::isReadyToSignIn($this->resolvedAttributes());
    }

    /**
     * @return list<string>
     */
    public function warnings(): array
    {
        $warnings = [];

        // Named, not merely counted. isReadyToSignIn() already fails closed on an unresolved
        // reference, so the screen shows "not usable yet" - but the fields below look filled in
        // (they hold `$KEYWAY_OIDC_SECRET`), the error sits on a field the administrator may not
        // have scrolled to, and the actual fault is in the server environment, not on this page.
        // Whoever has to fix it needs the variable name, so it goes at the top of the screen.
        foreach ($this->unresolvedEnvReferences() as $name) {
            $warnings[] = sprintf(
                'The %s field points at environment variable %s, which is not set, or is set to '
                . 'an empty value. Set it on the server, or clear the field - single sign-on '
                . 'stays off until it resolves.',
                $name,
                (string)$this->$name
            );
        }

        return array_merge(
            $warnings,
            SettingsTranslator::warnings($this->resolvedAttributes(), (new SystemClock())->now())
        );
    }
}
