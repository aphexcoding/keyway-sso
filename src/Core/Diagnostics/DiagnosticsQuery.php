<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

use Keyway\Sso\Core\Support\Ascii;

/**
 * The diagnostics panel's filters, validated once, here.
 *
 * Every value in this object arrived as a query-string parameter typed by whoever opened the
 * URL, so it is treated as hostile input rather than as configuration. The rule throughout is
 * the same one AuthProtocol::fromValue() follows: an unusable value COLLAPSES to a safe
 * default, it never throws and it never travels onward. A panel that answers a mistyped
 * `?outcome=succes` with a stack trace is a panel the administrator stops trusting during the
 * incident they opened it for.
 *
 * Collapsing to null rather than to "no results" is chosen on purpose: the filter is a view
 * over the data, and the failure mode of showing everything is a moment's confusion, while the
 * failure mode of showing nothing is an administrator concluding their logins are not being
 * recorded at all.
 *
 * The other reason this class exists is that it is the only thing between the URL bar and a
 * database query. `limit` is clamped so a bookmarked `?limit=100000` cannot ask Craft to
 * hydrate the whole table into one page, and `search` is byte-capped so the LIKE parameter
 * stays a filter rather than a payload.
 *
 * Note this class is intentionally NOT protocol-aware beyond the enum: it does not know which
 * protocol the site has configured, because the panel must still show yesterday's SAML rows on
 * a site that switched to OIDC this morning.
 */
final class DiagnosticsQuery
{
    public const DEFAULT_LIMIT = 50;
    public const MIN_LIMIT = 1;
    public const MAX_LIMIT = 200;
    public const MAX_SEARCH_BYTES = 128;

    /**
     * The protocols a stored row can carry, duplicated from Config\AuthProtocol ON PURPOSE.
     *
     * `Core\` must not import `Config\`: the dependency arrow in this plugin runs
     * Craft -> Config -> Core, and one import the other way is how that stops being true. The
     * duplication is not left to good intentions either - diagnostics_store_test pins this list
     * against AuthProtocol's enabled cases, so adding a third protocol there and forgetting it
     * here fails the suite rather than silently dropping the new protocol's rows out of every
     * filtered view.
     *
     * @var list<string>
     */
    public const PROTOCOLS = ['saml', 'oidc'];

    /**
     * What a stored row's `protocol` column can hold for each filter value above.
     *
     * The two are NOT the same vocabulary, and assuming they were is the bug this map fixes:
     * the filter speaks Config\AuthProtocol (`saml`), while a login row is written with
     * IdentityReaderInterface::protocol(), which for SAML answers `saml2`. Only the logout rows
     * (InboundLogoutFlow::PROTOCOL) say `saml`. A filter that compared the column to `saml`
     * therefore hid every SAML login and showed "No entries match".
     *
     * The mapping lives on the READ side on purpose. Rows already written keep whatever they
     * were written with, so translating here makes old and new rows filter alike, and the
     * writers - whose identifier also names the state record - stay untouched.
     * diagnostics_store_test pins every real writer's value against this map.
     *
     * @var array<string, list<string>>
     */
    public const STORED_PROTOCOLS = [
        'saml' => ['saml', 'saml2'],
        'oidc' => ['oidc'],
    ];

    private ?string $outcome;
    private ?string $protocol;
    private ?string $search;
    private int $limit;
    private int $offset;

    private function __construct(
        ?string $outcome,
        ?string $protocol,
        ?string $search,
        int $limit,
        int $offset
    ) {
        $this->outcome = $outcome;
        $this->protocol = $protocol;
        $this->search = $search;
        $this->limit = $limit;
        $this->offset = $offset;
    }

    /**
     * Builds a query from raw panel input. Nulls mean "parameter absent".
     */
    public static function fromInput(
        ?string $outcome,
        ?string $protocol,
        ?string $search,
        ?int $limit,
        ?int $offset
    ): self {
        return new self(
            self::normaliseOutcome($outcome),
            self::normaliseProtocol($protocol),
            self::normaliseSearch($search),
            self::clampLimit($limit),
            self::clampOffset($offset)
        );
    }

    /**
     * Every filter off: what the panel shows when it is opened without parameters.
     */
    public static function all(int $limit = self::DEFAULT_LIMIT): self
    {
        return self::fromInput(null, null, null, $limit, 0);
    }

    /** Null means "all outcomes". Never a value outside LoginOutcome. */
    public function outcome(): ?string
    {
        return $this->outcome;
    }

    /** Null means "all protocols". Never a value outside AuthProtocol's enabled cases. */
    public function protocol(): ?string
    {
        return $this->protocol;
    }

    /**
     * The `protocol` column values the protocol filter selects; empty means "all protocols".
     * This, not protocol(), is what a storage query must compare the column against.
     *
     * @return list<string>
     */
    public function storedProtocols(): array
    {
        return $this->protocol === null ? [] : self::STORED_PROTOCOLS[$this->protocol];
    }

    /** Trimmed and byte-capped; null when the caller effectively searched for nothing. */
    public function search(): ?string
    {
        return $this->search;
    }

    public function limit(): int
    {
        return $this->limit;
    }

    public function offset(): int
    {
        return $this->offset;
    }

    public function hasFilters(): bool
    {
        return $this->outcome !== null || $this->protocol !== null || $this->search !== null;
    }

    /**
     * The same filters on the next page. Used by the panel's pager; the limit is unchanged, so
     * the result is still clamped by construction.
     */
    public function withOffset(int $offset): self
    {
        return new self(
            $this->outcome,
            $this->protocol,
            $this->search,
            $this->limit,
            self::clampOffset($offset)
        );
    }

    private static function normaliseOutcome(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = Ascii::lower(Ascii::trim($value));

        if ($value === '' || $value === 'all') {
            return null;
        }

        return LoginOutcome::tryFrom($value)?->value;
    }

    private static function normaliseProtocol(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = Ascii::lower(Ascii::trim($value));

        if ($value === '' || $value === 'all') {
            return null;
        }

        // `disabled` is a settings state, not something a login row can carry, so it collapses
        // like any other unusable value rather than becoming a filter that matches nothing.
        return in_array($value, self::PROTOCOLS, true) ? $value : null;
    }

    private static function normaliseSearch(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = Ascii::trim($value);

        if ($value === '') {
            return null;
        }

        // Control characters would travel into a LIKE parameter and, more to the point, into
        // whatever renders the "searching for X" heading. A run of them collapses to one space
        // so that a value pasted out of a log with a CRLF in it still matches.
        $value = (string)preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value);
        $value = Ascii::trim(Ascii::truncateBytes($value, self::MAX_SEARCH_BYTES));

        return $value === '' ? null : $value;
    }

    private static function clampLimit(?int $limit): int
    {
        if ($limit === null) {
            return self::DEFAULT_LIMIT;
        }

        return max(self::MIN_LIMIT, min(self::MAX_LIMIT, $limit));
    }

    private static function clampOffset(?int $offset): int
    {
        return $offset === null ? 0 : max(0, $offset);
    }
}
