<?php

declare(strict_types=1);

namespace Keyway\Sso\Config;

/**
 * Whether the callback address an administrator typed into the settings screen is the address
 * this plugin actually answers on.
 *
 * WHY THIS EXISTS. The ACS URL (SAML) and the redirect URI (OIDC) are the two values that have
 * to be identical in three places at once: here, at the identity provider, and in the message
 * that comes back. `SamlResponseReader` compares the assertion's `Destination` and `Recipient`
 * against the configured ACS URL with `!==` - byte for byte - and an OIDC `redirect_uri` is
 * matched by the provider with the same strictness (RFC 6749, simple string comparison). A
 * value that differs by one character does not degrade; it fails the login with a message about
 * a destination mismatch, which reads like a certificate problem to whoever is configuring it.
 * Until now nothing in the product showed the administrator which address to use, so this is the
 * first place that can say "what you typed is not where the assertion will arrive".
 *
 * WHAT IT COMPARES, AND WHAT IT DELIBERATELY DOES NOT. The input is two strings: the address
 * this installation answers on (built in `Plugin::settingsHtml()`, the one place allowed to read
 * `Craft::$app`) and the address stored in the settings. Nothing here knows about Craft, so the
 * rule is testable without an application - the same reason SettingsTranslator lives next door.
 * This does NOT validate the field: `SamlConnectionConfig` and `OidcConnectionConfig` already
 * refuse an empty, relative or non-https value and the screen shows their errors. This answers
 * the different question those cannot: "usable" and "the address the identity provider will
 * actually reach" are not the same sentence.
 *
 * WHICH CASE IS A WARNING AND WHY. Only two of the seven shout, and the split is on certainty,
 * not on severity of consequence:
 *
 *  - `DifferentOrigin` and `Unreadable` are warnings, because a response sent to a host this
 *    installation does not serve - or to something that is not a URL at all - cannot arrive
 *    here by any route.
 *  - `OtherOriginOfThisInstall` exists because that certainty has exactly two holes, and both
 *    of them are CORRECT configurations that the first version of this class painted red:
 *
 *      1. A multi-site install with a domain per site. These settings are global - one ACS URL
 *         for the whole installation - while the address on the screen is built from the
 *         CURRENT site (`UrlHelper::baseSiteUrl()` reads `getSites()->getCurrentSite()`). An
 *         ACS URL pointing at a SIBLING site of the same install is right, works, and would
 *         have been reported as "will not reach this plugin".
 *      2. The same host over a different scheme or port. A control panel reached over http
 *         still needs an https redirect URI, because `OidcConnectionConfig` refuses anything
 *         else; flagging the only acceptable value is worse than saying nothing.
 *
 *    A false alarm here is not a cosmetic defect: the person reading it dismantles a WORKING
 *    single sign-on, at the identity provider too, because the screen told them it was broken.
 *    So an origin whose host this installation is known to serve degrades to a remark that
 *    says what to check, and the red is kept for hosts that are genuinely somewhere else.
 *    Embedded credentials never degrade - `https://user:pass@host/...` is not an address to
 *    register with an identity provider, whoever owns the host.
 *  - `DifferentPath` is a notice, not a warning, and that is a considered choice. The control
 *    panel alias (`/<cpTrigger>/sso/acs`) IS a working address today, and an install behind a
 *    rewrite may legitimately use a third path. We cannot tell a deliberate alias from a typo
 *    without Craft's URL manager, so the line describes both outcomes and names the one thing
 *    that is certain: an address containing `cpTrigger` breaks when `cpTrigger` is changed.
 *  - `NotConfigured` is not a fault at all. It is what every fresh install looks like, and
 *    colouring the first step of configuration red is how a working product looks broken.
 *  - `Equivalent` is a notice too: routing is unaffected, but because both protocols compare
 *    this value literally, the administrator still needs to know that the string they registered
 *    with the provider has to be this one and not the prettier one above it.
 *
 * `Exact` returns no message on purpose. A confirmation on a field that is simply correct is
 * noise on a screen that already carries thirty of them.
 */
enum EndpointMatch: string
{
    /** Empty field: the starting state of every install, not an error. */
    case NotConfigured = 'not_configured';

    /** Character for character the address this site answers on. */
    case Exact = 'exact';

    /** Same endpoint, written differently: trailing slash, letter case in scheme/host, default port. */
    case Equivalent = 'equivalent';

    /** Same origin, other path or query - the control panel alias, or a mistake. */
    case DifferentPath = 'different_path';

    /** Another origin, but on a host this installation serves: a sibling site, or http vs https. */
    case OtherOriginOfThisInstall = 'other_origin_of_this_install';

    /** A host this installation does not serve, or credentials in the URL: nothing arrives here. */
    case DifferentOrigin = 'different_origin';

    /** Not an absolute http(s) URL on at least one side, so the two cannot be compared. */
    case Unreadable = 'unreadable';

    /**
     * Compares the address this plugin answers on with the address that was configured.
     *
     * Both sides are trimmed first, because `SamlConnectionConfig` and `OidcConnectionConfig`
     * trim before they store: a trailing space in the field is not a mismatch anywhere else in
     * this plugin, and reporting one here would send somebody hunting for a difference their
     * editor does not show.
     *
     * @param string $canonical the address this installation receives on, absolute http(s).
     * @param string $configured whatever is in the settings field, including junk.
     * @param list<string> $installBaseUrls every base URL this installation answers on - each
     *        site's, and the control panel's. Passed in rather than looked up, because that
     *        lookup is `Craft::$app->getSites()` and this class stays free of Craft; an empty
     *        list only means the caller knows of no other address, and then the canonical host
     *        is still treated as ours. Anything unparseable in it is ignored.
     */
    public static function compare(string $canonical, string $configured, array $installBaseUrls = []): self
    {
        $canonical = trim($canonical);
        $configured = trim($configured);

        if ($configured === '') {
            return self::NotConfigured;
        }

        if ($configured === $canonical) {
            return self::Exact;
        }

        $left = self::parts($canonical);
        $right = self::parts($configured);

        if ($left === null || $right === null) {
            return self::Unreadable;
        }

        if ($left['origin'] !== $right['origin']) {
            return $right['credentials'] === ''
                && self::servedByThisInstall($right['host'], $left['host'], $installBaseUrls)
                    ? self::OtherOriginOfThisInstall
                    : self::DifferentOrigin;
        }

        if (
            $left['path'] !== $right['path']
            || $left['query'] !== $right['query']
            || $left['fragment'] !== $right['fragment']
        ) {
            return self::DifferentPath;
        }

        return self::Equivalent;
    }

    /**
     * True when the screen should say this in red rather than in passing. See the class docblock
     * for why only these two qualify.
     */
    public function isWarning(): bool
    {
        return $this === self::DifferentOrigin || $this === self::Unreadable;
    }

    /**
     * What the administrator reads, or an empty string when there is nothing worth saying.
     *
     * English source strings, run through `|t('keyway-sso')` by the template like the rest of
     * the screen. They carry no interpolated value: a sentence that says "the address above" is
     * a sentence a translator can move, and the address itself is already on the screen, in a
     * field built to be copied.
     */
    public function message(): string
    {
        return match ($this) {
            self::Exact => '',
            self::NotConfigured =>
                'Not set yet. Copy the address above into this field and register the same '
                . 'value with your identity provider - single sign-on stays off until both '
                . 'sides carry it.',
            self::Equivalent =>
                'This reaches the same endpoint as the address above, but is not written the '
                . 'same way (a trailing slash, letter case in the scheme or host, or a default '
                . 'port). Both protocols compare this value character for character, so the '
                . 'identity provider must have it exactly as it is written here.',
            self::DifferentPath =>
                'This is on this site, but at a different path than the address above. If it is '
                . 'the control panel alias, it works today and stops working the moment this '
                . "site's cpTrigger changes; if it is anything else, the response from the "
                . 'identity provider will not reach this plugin.',
            self::OtherOriginOfThisInstall =>
                'This is not the address above, but it is on a host this installation serves - '
                . 'another site of this install, or the same host over a different scheme or '
                . 'port. That can be exactly right: these settings are shared by every site, and '
                . 'a redirect URI has to be https even where the control panel is reached over '
                . 'http. Check that this is the address the identity provider was given.',
            self::DifferentOrigin =>
                'This points at a host that this installation does not serve, so a response sent '
                . 'there will not reach this plugin. If the site really is published under that '
                . 'address - behind a proxy, under a name Craft does not know - check which '
                . 'address Craft actually receives; otherwise use the address above.',
            self::Unreadable =>
                'This cannot be checked against the address above, because it is not an '
                . 'absolute http or https URL. Paste the address above exactly as shown.',
        };
    }

    /**
     * Splits a URL into the parts that decide whether two addresses are the same endpoint.
     *
     * Normalised, because the URL syntax says they carry no meaning: the scheme and the host are
     * case-insensitive (RFC 3986 §3.1, §3.2.2), a default port is the same as no port, and a
     * trailing slash on the path is not a different resource for Craft's router, which trims it
     * before matching. Everything else is left alone - the path is case-SENSITIVE, and
     * `/Actions/keyway-sso/...` really does not match the action trigger.
     *
     * Any user information (`https://user:pass@host/...`) stays in the origin rather than being
     * dropped, so credentials smuggled into the field can never read as "the same address".
     *
     * @return array{origin: string, host: string, credentials: string, path: string,
     *         query: string, fragment: string}|null
     *         null when this is not an absolute http(s) URL with a host.
     */
    private static function parts(string $url): ?array
    {
        $parsed = parse_url($url);

        if (!is_array($parsed)) {
            return null;
        }

        $scheme = strtolower((string)($parsed['scheme'] ?? ''));

        if ($scheme !== 'http' && $scheme !== 'https') {
            return null;
        }

        $host = strtolower((string)($parsed['host'] ?? ''));

        if ($host === '') {
            return null;
        }

        $port = (int)($parsed['port'] ?? ($scheme === 'https' ? 443 : 80));

        $credentials = isset($parsed['user']) || isset($parsed['pass'])
            ? ((string)($parsed['user'] ?? '') . ':' . (string)($parsed['pass'] ?? '') . '@')
            : '';

        return [
            'origin' => sprintf('%s://%s%s:%d', $scheme, $credentials, $host, $port),
            'host' => $host,
            'credentials' => $credentials,
            'path' => rtrim((string)($parsed['path'] ?? ''), '/'),
            'query' => (string)($parsed['query'] ?? ''),
            'fragment' => (string)($parsed['fragment'] ?? ''),
        ];
    }

    /**
     * Whether this host is one this installation answers on.
     *
     * HOST only - not the origin - and that is the whole point of the check: the two false
     * alarms it exists to stop (a sibling site, and http vs https on the same machine) differ
     * from the canonical address precisely in scheme or port. A host is compared whole, so
     * `site.example.com.evil.test` is not `site.example.com`.
     *
     * @param list<string> $installBaseUrls
     */
    private static function servedByThisInstall(string $host, string $canonicalHost, array $installBaseUrls): bool
    {
        if ($host === $canonicalHost) {
            return true;
        }

        foreach ($installBaseUrls as $baseUrl) {
            $parts = self::parts(trim((string)$baseUrl));

            if ($parts !== null && $parts['host'] === $host) {
                return true;
            }
        }

        return false;
    }
}
