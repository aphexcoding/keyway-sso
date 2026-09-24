<?php

declare(strict_types=1);

namespace Keyway\Sso\Config;

use InvalidArgumentException;
use Keyway\Sso\Core\Access\AdminFallbackSettings;
use Keyway\Sso\Core\Attribute\AttributeMap;
use Keyway\Sso\Core\Attribute\AttributeRule;
use Keyway\Sso\Core\Attribute\AttributeTransform;
use Keyway\Sso\Core\Attribute\MultiValueStrategy;
use Keyway\Sso\Core\Group\AdminRule;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupMatchType;
use Keyway\Sso\Core\Group\GroupRule;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Provisioning\ProvisioningSettings;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Core\Support\Ascii;
use Keyway\Sso\Protocol\Oidc\OidcConnectionConfig;
use Keyway\Sso\Protocol\Saml\IdpCertificate;
use Keyway\Sso\Protocol\Saml\SamlConnectionConfig;
use Keyway\Sso\Protocol\Saml\SpMetadata;

/**
 * Turns the flat, stringly-typed settings of a Craft plugin into the typed objects the core and
 * the protocol readers accept.
 *
 * This class is the whole reason the Craft layer can stay thin, and it lives outside both
 * `Core\` and `Protocol\` on purpose:
 *
 *  - it is NOT in `Core\`, because it builds SamlConnectionConfig and OidcConnectionConfig, and
 *    the core must never depend on a protocol implementation - the dependency runs
 *    Craft -> Config -> {Core, Protocol}, never back;
 *  - it is NOT in the Craft layer, because everything here is a rule (what counts as an empty
 *    row, which value wins when a field is blank, what makes a configuration invalid) and a
 *    rule that can only be exercised by booting a CMS is a rule nobody re-tests.
 *
 * There is therefore not a single `use craft\...` or `use yii\...` in this file, and
 * `test/settings_translator_test.php` runs against it with no vendor directory at all.
 *
 * Input is an associative array - exactly what `craft\base\Model::getAttributes()` returns -
 * read defensively, because project config is a YAML file a human can hand-edit.
 */
final class SettingsTranslator
{
    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $settings
     */
    public static function protocol(array $settings): AuthProtocol
    {
        return AuthProtocol::fromValue($settings['protocol'] ?? null);
    }

    /**
     * Attribute mapping, falling back to the shipped defaults when no rule survived.
     *
     * An empty table means "the administrator cleared it", and a mapping with no rules cannot
     * produce an e-mail address, so every login would fail with a message about a missing
     * attribute. Defaults (`email`, `firstName`, `lastName`) are the honest answer instead.
     *
     * @param array<string, mixed> $settings
     * @throws InvalidArgumentException when a configured rule is not a legal rule.
     */
    public static function attributeMap(array $settings): AttributeMap
    {
        $rules = [];

        foreach (self::rows($settings['attributeRules'] ?? []) as $row) {
            $source = self::str($row, 'source');
            $target = self::str($row, 'target');

            if ($source === '' && $target === '') {
                continue;
            }

            $required = self::bool($row, 'required', false);
            $default = self::nullableStr($row, 'defaultValue');

            $rules[] = new AttributeRule(
                $source,
                $target,
                self::enum(MultiValueStrategy::class, $row['strategy'] ?? null, MultiValueStrategy::First),
                $required,
                $required ? null : $default,
                self::enum(AttributeTransform::class, $row['transform'] ?? null, AttributeTransform::None),
                self::separator($row)
            );
        }

        if ($rules === []) {
            return AttributeMap::defaults();
        }

        return new AttributeMap($rules);
    }

    /**
     * @param array<string, mixed> $settings
     * @throws InvalidArgumentException when a configured rule is not a legal rule.
     */
    public static function groupMap(array $settings): GroupMap
    {
        $rules = [];
        foreach (self::rows($settings['groupRules'] ?? []) as $row) {
            $pattern = self::str($row, 'pattern');
            $target = self::str($row, 'targetGroup');

            if ($pattern === '' && $target === '') {
                continue;
            }

            $rules[] = new GroupRule(
                self::enum(GroupMatchType::class, $row['matchType'] ?? null, GroupMatchType::Exact),
                $pattern,
                $target
            );
        }

        $adminRules = [];
        foreach (self::rows($settings['adminRules'] ?? []) as $row) {
            $pattern = self::str($row, 'pattern');

            if ($pattern === '') {
                continue;
            }

            $adminRules[] = new AdminRule(
                self::enum(GroupMatchType::class, $row['matchType'] ?? null, GroupMatchType::Exact),
                $pattern
            );
        }

        $sources = self::strings($settings['groupSourceAttributes'] ?? []);
        if ($sources === []) {
            // GroupMap refuses an empty source list, and rightly so; `groups` is the name Okta,
            // Keycloak and Entra ID all use, and it is what the shipped default says.
            $sources = ['groups'];
        }

        return new GroupMap(
            $rules,
            $adminRules,
            self::nullableStr($settings, 'defaultGroup'),
            self::enum(GroupSyncMode::class, $settings['groupSyncMode'] ?? null, GroupSyncMode::Append),
            self::bool($settings, 'groupMatchCaseSensitive', false),
            self::bool($settings, 'allowAdminEscalation', false),
            self::bool($settings, 'revokeAdminWhenUnmatched', false),
            $sources
        );
    }

    /**
     * @param array<string, mixed> $settings
     */
    public static function provisioning(array $settings): ProvisioningSettings
    {
        return new ProvisioningSettings(
            self::bool($settings, 'allowJit', true),
            self::bool($settings, 'updateOnLogin', true),
            self::bool($settings, 'denyIfNoGroupMatch', false),
            self::enum(UserMatchKey::class, $settings['matchBy'] ?? null, UserMatchKey::Email),
            self::strings($settings['allowedDomains'] ?? []),
            self::bool($settings, 'linkExistingAccounts', false),
            self::bool($settings, 'linkAdminAccounts', false)
        );
    }

    /**
     * @param array<string, mixed> $settings
     */
    public static function adminFallback(array $settings): AdminFallbackSettings
    {
        return new AdminFallbackSettings(
            self::bool($settings, 'ssoOnly', false),
            self::bool($settings, 'allowPasswordForAdmins', true),
            self::strings($settings['emergencyAccounts'] ?? []),
            self::bool($settings, 'breakGlassEnabled', false),
            self::nullableInt($settings, 'breakGlassExpiresAt')
        );
    }

    /**
     * Whether single logout is fully configured. Never throws: a half-written SAML connection is
     * an ordinary state of the settings screen, and metadata still has to render for it.
     *
     * @param array<string, mixed> $settings
     */
    private static function canLogout(array $settings): bool
    {
        try {
            return self::samlConnection($settings)->canLogout();
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    /**
     * @param array<string, mixed> $settings
     * @throws InvalidArgumentException when the connection is not usable as configured.
     */
    public static function samlConnection(array $settings): SamlConnectionConfig
    {
        $samlIsOn = self::protocol($settings) === AuthProtocol::Saml;

        return new SamlConnectionConfig(
            self::str($settings, 'samlIdpEntityId'),
            self::str($settings, 'samlIdpCertificate'),
            self::str($settings, 'samlSpEntityId'),
            self::str($settings, 'samlAcsUrl'),
            self::str($settings, 'samlIdpSsoUrl'),
            self::nullableStr($settings, 'samlSpPrivateKey'),
            self::int($settings, 'samlClockSkew', 60),
            // BOTH SLO ADDRESSES ARE GATED ON THE PROTOCOL, and that gate is the whole reason
            // they are read through a variable instead of inline.
            //
            // `sso/slo` ends sessions, and it decides whether it may by asking canLogout() on
            // this object. Nothing else stands in front of it. Without this gate an install
            // whose administrator SWITCHED SAML OFF - protocol `disabled`, or migrated to OIDC,
            // where _settings.twig hides the whole SAML section - would keep a live logout
            // endpoint answering signed requests from the old identity provider and ending the
            // session of whoever is holding the browser. "Disabled" has to disable. It also
            // stops a SAML LogoutRequest from ever being matched against a session that OIDC
            // started, which it otherwise could whenever `sub` happens to equal the NameID.
            //
            // spMetadata() already asks the same question first and returns null - so before
            // this gate the plugin answered "there is no SLO here" in metadata and ended
            // sessions anyway. One answer now, in one place.
            //
            // Empty means "no single logout", never an empty URL: SamlConnectionConfig validates
            // any non-null value as an absolute http(s) URL and would refuse ''.
            //
            // `samlSpSloUrl` is NOT a stored property, and deliberately not one: our own SLO
            // address is derived from the registered route the same way the metadata URL is
            // (Plugin::sloUrl()), so that it cannot drift from the endpoint that actually
            // answers. The Craft layer injects it into the attribute array before calling this;
            // absent it, canLogout() is false and single logout stays off - the safe half.
            $samlIsOn ? self::nullableStr($settings, 'samlIdpSloUrl') : null,
            $samlIsOn ? self::nullableStr($settings, 'samlSpSloUrl') : null
        );
    }

    /**
     * The SP metadata document this site would hand an identity provider, or null when there is
     * nothing honest to publish.
     *
     * NULL, NOT A HALF-FILLED DOCUMENT, and that is the whole rule this method exists for.
     * Metadata is a promise: it tells the IdP which entity id will appear in the AuthnRequest's
     * Issuer and which address the assertion may be posted to. Publishing it from blank settings
     * would produce a document naming an endpoint this site does not compare against - the
     * administrator would configure the IdP from it, the login would then fail on the audience
     * or the ACS check, and the error would read like a certificate problem. So:
     *
     *  - protocol other than SAML -> null. An OIDC install has no SP metadata, and an install
     *    with SSO switched off has nothing to say at all.
     *  - SP entity id or ACS URL missing or malformed -> null. SpMetadata itself refuses those
     *    (empty id, non-absolute URL), and the exception is caught here rather than allowed to
     *    surface, because a settings screen and a public endpoint both need "not yet", not a
     *    stack trace.
     *
     * WHAT IT DELIBERATELY DOES NOT CARRY, so the gap is named rather than discovered:
     *
     *  - no KeyDescriptor. The plugin stores an SP PRIVATE key (`samlSpPrivateKey`, for
     *    decrypting assertions) and no SP CERTIFICATE, and metadata can only publish the latter -
     *    an X509Certificate element takes a certificate, not a public key. A site using encrypted
     *    assertions therefore still hands its certificate to the IdP out of band. Closing that
     *    means a new setting, which is a change to the settings screen and to project config, not
     *    a change here.
     *  - SingleLogoutService ONLY when samlConnection()->canLogout() is true - the IdP endpoint,
     *    our own endpoint and a signing key all present, on a connection whose protocol is
     *    actually SAML. Anything less publishes nothing, because advertising the element would
     *    make every IdP that reads this document send logout requests to an address that refuses
     *    them. The binding is HTTP-Redirect and only that: it is the one binding sso/slo can
     *    verify (see SsoController::actionSlo).
     *  - no validUntil by default. The document is normally DOWNLOADED and uploaded into the IdP
     *    by hand, often days later; an expiry stamped at download time is an expiry that has
     *    passed by the time it is used, and a strict IdP refuses the file outright. The argument
     *    exists for a caller that serves the document live and wants one.
     *
     * @param array<string, mixed> $settings
     * @param int|null $validUntil unix timestamp, or null to publish no expiry.
     */
    public static function spMetadata(array $settings, ?int $validUntil = null): ?SpMetadata
    {
        if (self::protocol($settings) !== AuthProtocol::Saml) {
            return null;
        }

        try {
            return new SpMetadata(
                self::str($settings, 'samlSpEntityId'),
                self::str($settings, 'samlAcsUrl'),
                null,
                // ONLY when the connection can really carry out a logout. canLogout() wants the
                // IdP endpoint, our own endpoint and a signing key together; advertising a
                // SingleLogoutService without all three points the IdP at an address that
                // refuses everything it sends, which looks to an administrator like a fault in
                // their IdP. The binding is HTTP-Redirect and only that - see SpMetadata.
                self::canLogout($settings) ? self::nullableStr($settings, 'samlSpSloUrl') : null,
                $validUntil
            );
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /**
     * @param array<string, mixed> $settings
     * @throws InvalidArgumentException when the connection is not usable as configured.
     */
    public static function oidcConnection(array $settings): OidcConnectionConfig
    {
        $scopes = self::strings($settings['oidcScopes'] ?? []);
        if ($scopes === []) {
            $scopes = ['openid', 'profile', 'email'];
        }

        return new OidcConnectionConfig(
            self::str($settings, 'oidcIssuer'),
            self::str($settings, 'oidcClientId'),
            self::nullableStr($settings, 'oidcClientSecret'),
            self::str($settings, 'oidcRedirectUri'),
            $scopes,
            self::int($settings, 'oidcClockSkew', 60),
            self::bool($settings, 'oidcFetchUserinfo', false)
        );
    }

    /**
     * Everything wrong with this configuration, as "attribute => message" pairs for the
     * settings screen.
     *
     * Only the selected protocol is validated. Half-filled SAML fields left behind after a
     * switch to OIDC are not errors - refusing to save because of a connection the site does
     * not use is how an administrator ends up deleting their fallback configuration to get past
     * a validation message.
     *
     * @param array<string, mixed> $settings
     * @return list<array{0: string, 1: string}>
     */
    public static function problems(array $settings, int $now): array
    {
        $problems = [];
        $protocol = self::protocol($settings);

        if (is_string($settings['protocol'] ?? null)
            && AuthProtocol::tryFrom(strtolower(trim($settings['protocol']))) === null
        ) {
            $problems[] = ['protocol', sprintf(
                'Unknown protocol "%s". Choose one of: %s.',
                (string)$settings['protocol'],
                implode(', ', AuthProtocol::values())
            )];
        }

        $collect = static function (string $attribute, callable $build) use (&$problems): void {
            try {
                $build();
            } catch (InvalidArgumentException $error) {
                $problems[] = [$attribute, $error->getMessage()];
            }
        };

        if ($protocol === AuthProtocol::Saml) {
            $before = count($problems);

            $collect('samlIdpEntityId', static fn() => self::samlConnection($settings));

            // THE SECOND, STRICT LOOK AT THE IDP CERTIFICATE, and only on the screen where
            // somebody is typing it.
            //
            // SamlConnectionConfig accepts any 256-character base64 blob on purpose: its check
            // also runs while a login page is rendering, and it must reject a fingerprint
            // without re-parsing X.509. The cost was paid by the administrator - a private key,
            // a truncated paste or noise SAVED CLEANLY and then failed at the first login, as a
            // signature error that reads like a fault in their identity provider. Here, at save
            // time, openssl gets to decide (IdpCertificate).
            //
            // ONLY WHEN THE CONNECTION ITSELF BUILT. A value that already failed the shape floor
            // - a fingerprint above all - has been refused a line earlier, in words that name
            // the mistake; asking again would put two messages on the screen for one paste, and
            // duplicating the floor here would be a third copy of a rule that already lives in
            // two files. The protocol gate is the surrounding `if`, exactly like samlIdpEntityId:
            // SAML fields left behind after a switch to OIDC are not errors.
            if (count($problems) === $before) {
                $certificate = self::str($settings, 'samlIdpCertificate');

                // Reported on the field that carries the value, not on samlIdpEntityId: the
                // message tells the administrator what they pasted, and it has to appear under
                // the box they pasted it into.
                $collect('samlIdpCertificate', static fn() => IdpCertificate::assertUsable($certificate));
            }
        }

        if ($protocol === AuthProtocol::Oidc) {
            $collect('oidcIssuer', static fn() => self::oidcConnection($settings));
        }

        $collect('attributeRules', static fn() => self::attributeMap($settings));
        $collect('groupRules', static fn() => self::groupMap($settings));
        $collect('allowedDomains', static fn() => self::provisioning($settings));

        // The strict, save-time half of the break-glass rule: the forgiving constructor would
        // quietly close the switch, which is right while rendering a login page and wrong on the
        // screen where somebody just asked for it.
        $collect('breakGlassExpiresAt', static fn() => AdminFallbackSettings::assertBreakGlassWindow(
            self::bool($settings, 'breakGlassEnabled', false),
            self::nullableInt($settings, 'breakGlassExpiresAt'),
            $now
        ));

        return $problems;
    }

    /**
     * Things that are legal but deserve a sentence on the settings screen.
     *
     * Separate from problems() because none of these may block a save: two of them describe a
     * safety net that has already fired, and a guard that prevents you from saving the
     * configuration it just corrected is a guard that locks you out.
     *
     * @param array<string, mixed> $settings
     * @return list<string>
     */
    public static function warnings(array $settings, int $now): array
    {
        $warnings = [];
        $fallback = self::adminFallback($settings);

        if ($fallback->lockoutGuardApplied()) {
            $warnings[] = 'These settings would have left nobody able to reach the control panel '
                . 'if the identity provider failed, so password login for admins was turned back '
                . 'on. Add an emergency account if you want single sign-on only.';
        }

        if ($fallback->breakGlassGuardApplied()) {
            $warnings[] = 'Emergency password login was requested without an expiry time, so it '
                . 'stays off. Give it an end time - a break-glass switch that never closes is a '
                . 'permanent password door.';
        }

        $remaining = $fallback->breakGlassRemaining($now);
        if ($remaining !== null) {
            $warnings[] = sprintf(
                'Emergency password login is active for another %d minute(s).',
                intdiv($remaining, 60)
            );
        }

        if (self::bool($settings, 'linkExistingAccounts', false)) {
            $warnings[] = 'Existing Craft accounts may be linked to an identity from the provider. '
                . 'On a site with public registration, an account registered with somebody else\'s '
                . 'address and never verified can be linked this way - keep the domain allow list '
                . 'filled in.';
        }

        // The runtime decision about browser binding and this warning read the SAME value - the
        // callback URL from settings - on purpose. Core\Login\BrowserBinding derives "can this
        // login be bound" from the scheme of that URL, so a warning derived from anything else
        // (a request object, a site URL) could say one thing while the login does another.
        $callback = self::callbackUrl($settings);
        if ($callback !== null && !str_starts_with(Ascii::lower($callback), 'https://')) {
            $warnings[] = self::protocol($settings) === AuthProtocol::Saml
                ? 'The assertion consumer URL is not HTTPS, so single sign-on runs WITHOUT the '
                    . 'cookie that ties a login to the browser that started it. A SAML response '
                    . 'arrives as a cross-site POST, which needs a SameSite=None cookie, and '
                    . 'browsers only accept one of those over HTTPS. Serve the site over HTTPS to '
                    . 'close that gap.'
                : 'The redirect URI is not HTTPS. The login is still tied to the browser that '
                    . 'started it, but the binding cookie and the authorization code travel in '
                    . 'the clear. Serve the site over HTTPS.';
        }

        if (self::bool($settings, 'allowAdminEscalation', false)) {
            $warnings[] = 'Your identity provider can grant Craft admin status through the admin '
                . 'rules below. Anybody who can edit those groups in the directory can make '
                . 'themselves an admin here.';
        }

        // A private key pasted in alongside the signing certificate. THIS IS A WARNING AND NOT A
        // PROBLEM ON PURPOSE: openssl reads the first structure in the field and so do both SAML
        // readers, so the value works - refusing it would block a save for a configuration that
        // signs in perfectly well. What does not work is leaving somebody's private key in the
        // settings table, in project config and in every backup of either, unmentioned.
        //
        // The protocol gate is the same one problems() puts on samlIdpEntityId and the
        // certificate: a SAML field left behind after a switch to OIDC is not worth a sentence.
        // Which pastes count - and which do not, a chain above all - is decided in one place,
        // IdpCertificate::carriesPrivateKey().
        if (self::protocol($settings) === AuthProtocol::Saml
            && IdpCertificate::carriesPrivateKey(self::str($settings, 'samlIdpCertificate'))
        ) {
            $warnings[] = 'The signing certificate was pasted together with a private key. '
                . 'Sign-in still works, because the reader only takes the certificate, but the '
                . 'key is now saved with the rest of the settings - the database, project config '
                . 'and every backup of them. Paste the certificate on its own; if that key '
                . 'belongs to the identity provider, treat it as exposed and ask the provider to '
                . 'replace it.';
        }

        return $warnings;
    }

    /**
     * The URL the identity provider returns to, for the protocol currently selected.
     *
     * Null when no protocol is selected or the field is empty - there is nothing to warn about
     * on a connection nobody has filled in yet.
     *
     * @param array<string, mixed> $settings
     */
    public static function callbackUrl(array $settings): ?string
    {
        $protocol = self::protocol($settings);

        if ($protocol === AuthProtocol::Saml) {
            return self::nullableStr($settings, 'samlAcsUrl');
        }

        if ($protocol === AuthProtocol::Oidc) {
            return self::nullableStr($settings, 'oidcRedirectUri');
        }

        return null;
    }

    /**
     * @param array<string, mixed> $settings
     */
    public static function isReadyToSignIn(array $settings): bool
    {
        $protocol = self::protocol($settings);

        if (!$protocol->isEnabled()) {
            return false;
        }

        try {
            if ($protocol === AuthProtocol::Saml) {
                self::samlConnection($settings);
            } else {
                self::oidcConnection($settings);
            }

            self::attributeMap($settings);
            self::groupMap($settings);
        } catch (InvalidArgumentException) {
            return false;
        }

        return true;
    }

    /**
     * The join separator, read WITHOUT trimming.
     *
     * The one place where surrounding whitespace is the value: `", "` is the separator somebody
     * types to join two group names readably, and trimming it - which every other field here
     * wants - would silently turn it into `","`.
     *
     * @param array<string, mixed> $row
     */
    private static function separator(array $row): string
    {
        $value = $row['separator'] ?? null;

        if (!is_scalar($value) || is_bool($value)) {
            return ' ';
        }

        return (string)$value === '' ? ' ' : (string)$value;
    }

    /**
     * @param mixed $value
     * @return list<array<string, mixed>>
     */
    private static function rows(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $rows = [];
        foreach ($value as $row) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        return $rows;
    }

    /**
     * A list of non-empty strings, from either a real array or a newline/comma separated
     * textarea - the settings screen uses a textarea, project config may hold a list.
     *
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/[\r\n,]+/', $value) ?: [];
        }

        if (!is_array($value)) {
            return [];
        }

        $out = [];
        foreach ($value as $item) {
            if (is_array($item) || is_object($item)) {
                continue;
            }

            $item = trim((string)$item);
            if ($item !== '' && !in_array($item, $out, true)) {
                $out[] = $item;
            }
        }

        return $out;
    }

    /**
     * @param array<string, mixed> $source
     */
    private static function str(array $source, string $key): string
    {
        $value = $source[$key] ?? null;

        if (is_array($value) || is_object($value) || is_bool($value) || $value === null) {
            return '';
        }

        return trim((string)$value);
    }

    /**
     * @param array<string, mixed> $source
     */
    private static function nullableStr(array $source, string $key): ?string
    {
        $value = self::str($source, $key);

        return $value === '' ? null : $value;
    }

    /**
     * @param array<string, mixed> $source
     */
    private static function bool(array $source, string $key, bool $default): bool
    {
        $value = $source[$key] ?? null;

        if ($value === null || $value === '') {
            return $default;
        }

        if (is_string($value)) {
            return !in_array(strtolower(trim($value)), ['0', 'false', 'no', 'off'], true);
        }

        return (bool)$value;
    }

    /**
     * @param array<string, mixed> $source
     */
    private static function int(array $source, string $key, int $default): int
    {
        $value = $source[$key] ?? null;

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', trim($value)) === 1) {
            return (int)trim($value);
        }

        return $default;
    }

    /**
     * @param array<string, mixed> $source
     */
    private static function nullableInt(array $source, string $key): ?int
    {
        $value = $source[$key] ?? null;

        if ($value === null || $value === '') {
            return null;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', trim($value)) === 1) {
            return (int)trim($value);
        }

        return null;
    }

    /**
     * Backed enum from a settings value, falling back instead of throwing.
     *
     * A misspelled enum in project config is a typo, not a reason to fail a login: every enum
     * used here has a safe default (first value, append, exact, no transform), so the fallback
     * is always the narrower behaviour.
     *
     * @template T of \BackedEnum
     * @param class-string<T> $enum
     * @param T $default
     * @return T
     */
    private static function enum(string $enum, mixed $value, mixed $default): mixed
    {
        if ($value instanceof $enum) {
            return $value;
        }

        if (!is_string($value) || trim($value) === '') {
            return $default;
        }

        return $enum::tryFrom(strtolower(trim($value))) ?? $default;
    }
}
