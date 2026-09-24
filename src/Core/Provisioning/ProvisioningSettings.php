<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

use InvalidArgumentException;
use Keyway\Sso\Core\Support\Ascii;

/**
 * Just-in-time provisioning policy, as configured by the site administrator.
 *
 * Defaults are the cautious end of every switch: match on e-mail, create accounts on first
 * login, keep them in sync, no domain restriction, and do not require a group match. An
 * administrator tightening this cannot lock themselves out, because password access is
 * governed separately by AdminFallback.
 *
 * The two switches that are OFF by default, and must stay off by default:
 *
 *  - `linkExistingAccounts` - whether an identity from the IdP may attach itself to an account
 *    that already exists in Craft. Account takeover through this path needs no XML at all: with
 *    `matchBy = Username` the only thing between an IdP-controlled string and somebody else's
 *    account is the IdP's own policy on `preferred_username`, and with `matchBy = Email` the
 *    only brake is the domain allow list, which is empty unless configured. Linking is a real
 *    feature that most installs will want - it is how an existing team keeps its accounts -
 *    but it is a decision the site owner takes, not a default they inherit.
 *  - `linkAdminAccounts` - whether linking may touch an account with `isAdmin`. Separate on
 *    purpose: "let the team sign in with SSO" and "let the identity provider hand out the
 *    owner's account" are not the same sentence, and the second one deserves its own checkbox.
 */
final class ProvisioningSettings
{
    public readonly bool $allowJit;
    public readonly bool $updateOnLogin;
    public readonly bool $denyIfNoGroupMatch;
    public readonly UserMatchKey $matchBy;
    public readonly bool $linkExistingAccounts;
    public readonly bool $linkAdminAccounts;

    /** @var list<string> */
    private array $allowedDomains;

    /**
     * @param list<string> $allowedDomains Empty means "any domain". An entry may be a bare
     *        domain (`example.com`, exact match) or a dotted/wildcard form (`.example.com`,
     *        `*.example.com`) which matches sub-domains only.
     */
    public function __construct(
        bool $allowJit = true,
        bool $updateOnLogin = true,
        bool $denyIfNoGroupMatch = false,
        UserMatchKey $matchBy = UserMatchKey::Email,
        array $allowedDomains = [],
        bool $linkExistingAccounts = false,
        bool $linkAdminAccounts = false
    ) {
        $this->allowJit = $allowJit;
        $this->updateOnLogin = $updateOnLogin;
        $this->denyIfNoGroupMatch = $denyIfNoGroupMatch;
        $this->matchBy = $matchBy;
        $this->allowedDomains = self::normaliseDomains($allowedDomains);
        $this->linkExistingAccounts = $linkExistingAccounts;
        // Linking admins without linking at all is meaningless; keep the pair coherent so the
        // policy never has to reason about a half-enabled state.
        $this->linkAdminAccounts = $linkExistingAccounts && $linkAdminAccounts;
    }

    /**
     * @param array<int, string> $domains
     * @return list<string>
     */
    private static function normaliseDomains(array $domains): array
    {
        $out = [];

        foreach ($domains as $domain) {
            $domain = Ascii::lower(Ascii::trim((string)$domain));
            $domain = ltrim($domain, '@');

            if (str_starts_with($domain, '*.')) {
                $domain = substr($domain, 1);
            }

            if ($domain === '' || $domain === '.') {
                continue;
            }

            if (Ascii::hasControlCharacters($domain) || str_contains($domain, '/')) {
                throw new InvalidArgumentException(sprintf(
                    'Allowed domain "%s" is not a domain name.',
                    $domain
                ));
            }

            if (!in_array($domain, $out, true)) {
                $out[] = $domain;
            }
        }

        return $out;
    }

    /** @return list<string> */
    public function allowedDomains(): array
    {
        return $this->allowedDomains;
    }

    public function restrictsDomains(): bool
    {
        return $this->allowedDomains !== [];
    }

    /**
     * Exact match for bare entries, sub-domain match for entries starting with a dot.
     *
     * `.example.com` matches `eu.example.com` but NOT `example.com` itself, and never
     * `notexample.com` - the leading dot is what stops suffix matching from being a hole.
     */
    public function allowsDomain(?string $domain): bool
    {
        if (!$this->restrictsDomains()) {
            return true;
        }

        if ($domain === null || $domain === '') {
            return false;
        }

        $domain = Ascii::lower($domain);

        foreach ($this->allowedDomains as $allowed) {
            if (str_starts_with($allowed, '.')) {
                if (str_ends_with($domain, $allowed)) {
                    return true;
                }

                continue;
            }

            if ($domain === $allowed) {
                return true;
            }
        }

        return false;
    }
}
