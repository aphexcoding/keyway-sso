<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Craft;
use craft\db\Connection;
use craft\db\Query;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use Keyway\Sso\Core\Port\IdentityLinkStoreInterface;
use Keyway\Sso\Core\Support\Ascii;
use Throwable;

/**
 * The table that remembers which Craft accounts this plugin created, for which issuer, and
 * for which subject at that issuer.
 *
 * WHAT IT FIXES, measured: against a live Craft with Okta on default settings (2026-09-15), the
 * same person's second login was refused - `provisioning / denied / linking_disabled`. The first
 * login had created the account just-in-time, and nothing anywhere recorded that fact, so
 * ProvisioningPolicy's step 4a saw an account the site "already had". Every just-in-time
 * account was good for exactly one sign-in unless the owner switched on
 * `linkExistingAccounts`, which is the setting that lets an identity provider walk into accounts
 * it did not create - i.e. the workaround was worse than the bug.
 *
 * SHAPED AFTER CraftDbDiagnosticsSink, and for the same reason rather than out of symmetry: both
 * run INSIDE a login. So the same three rules apply here.
 *
 *  1. A BROKEN TABLE MUST NOT BREAK A LOGIN. Every method catches Throwable - not a database
 *     exception, Throwable - and answers with a value.
 *  2. THE MISSING TABLE IS AN EXPECTED STATE. A site can be running this plugin with `craft up`
 *     not yet run, and the probe is memoised per request so the answer costs one failed query
 *     at most.
 *  3. `Craft::$app` IS NOT TOUCHED IN THE CONSTRUCTOR. The connection is injectable and resolved
 *     lazily, which is what makes the class testable without an application.
 *
 * THE DIRECTION EACH FAILURE FALLS IS NOT THE SAME, and that is the part worth reading. A
 * failed READ answers FALSE, which denies a login that should have been allowed: the opposite
 * default would let an unreadable table open step 4a for every account on the site. A failed
 * WRITE is swallowed, because the person is already signed in by then; the cost is that their
 * NEXT login is refused, and a 500 on a successful login would be worse and would not save
 * the row either.
 *
 * NOT MASKED, and it must not be. The values stored here are compared byte for byte with the
 * ones the next response carries; a masked value would match nothing, ever. That makes this
 * table different from the diagnostics table (whose contents are masked before they arrive) and
 * it is why the columns are the identifiers alone - no attributes, no groups, no e-mail address.
 *
 * WHERE THE COMPARISON HAPPENS, and why it is not in the WHERE clause. The lookup selects by
 * `userId` alone and compares the issuer and the subject IN PHP, with `===`. That is not a
 * stylistic choice: a site's own collation would otherwise decide who is who. MySQL's default
 * (`utf8mb4_0900_ai_ci`, `utf8mb4_general_ci` on older servers) is case- AND accent-insensitive
 * and pads trailing spaces, so `Mallory-Sub` and `mallory-sub` would be one link; PostgreSQL
 * compares exactly, so the same plugin would enforce two different rules on two databases Craft
 * supports. `BINARY`/`COLLATE` fixes are per-engine and per-collation, and the subject is part
 * of the security boundary rather than an audit column. Selecting by `userId` still uses the
 * leading column of the unique index, and one account has as many rows as it has issuers -
 * one, in every deployment that is not a migration in progress.
 */
final class CraftDbIdentityLinkStore implements IdentityLinkStoreInterface
{
    public const TABLE = '{{%keyway_sso_links}}';

    /**
     * Column widths, mirrored from src/migrations/Install.php. Constants rather than a schema
     * round-trip per login, exactly as in CraftDbDiagnosticsSink.
     *
     * THE TWO OVER-LONG VALUES ARE HANDLED DIFFERENTLY, and the asymmetry is the point rather
     * than an oversight.
     *
     * AN ISSUER is truncated, on the way IN and on the way OUT by the same helper, so a site
     * with a 300-byte issuer still matches itself. What it loses is the ability to tell two
     * issuers apart that share their first 255 bytes - and an issuer is not a value an attacker
     * chooses: it is the site's own configuration, verified against it before anything reaches
     * this class. Refusing instead would lock such a site out of every login it has, to defend
     * against a collision that would require the owner to configure the collision themselves.
     *
     * A SUBJECT IS REFUSED, because it is the opposite kind of value: one per person, chosen by
     * the identity provider and carried in the response. Truncating it was measured to merge two
     * people - a row holding 255 x 'a' (cut from `255a.alice`) answered TRUE for a probe of
     * 255 x 'a' + '.mallory'. The subject IS the security boundary here, so an over-long one
     * fails closed: the read answers false, the write is skipped. The cost is a refused login
     * (`linking_disabled`) for a directory that issues name ids past 255 bytes, which is the
     * direction this class falls everywhere else.
     */
    private const WIDTH_USER_ID = 32;
    private const WIDTH_ISSUER = 255;
    private const WIDTH_SUBJECT = 255;

    private ?Connection $db;

    /** Per-request memo of the table probe; null until the first call. */
    private ?bool $tableUsable = null;

    /**
     * @param Connection|null $db Injected for testing; resolved from Craft when null.
     */
    public function __construct(?Connection $db = null)
    {
        $this->db = $db;
    }

    /**
     * True only when a row says this issuer created this account FOR THIS SUBJECT. False
     * whenever we cannot tell.
     *
     * All three values are compared, because two of them are not enough: a colleague at the same
     * identity provider who puts somebody else's address in their own profile satisfies (user,
     * issuer) and is a different person. The site owner chose this shape knowing what it costs -
     * see IdentityLinkStoreInterface for that cost and for what was accepted along with it.
     */
    public function isLinkedTo(string $userId, string $issuer, string $subject): bool
    {
        $userId = Ascii::trim($userId);
        $issuer = Ascii::trim($issuer);
        $subject = Ascii::trim($subject);

        // A blank subject cannot identify anybody, so it may not satisfy the check: an identity
        // provider that sends no name id must not inherit somebody else's link.
        if ($userId === '' || $issuer === '' || $subject === '') {
            return false;
        }

        // An over-long subject is not cut down to something that matches somebody else; see
        // the widths above.
        if (strlen($subject) > self::WIDTH_SUBJECT) {
            return false;
        }

        $issuer = Ascii::truncateBytes($issuer, self::WIDTH_ISSUER);

        foreach ($this->rowsFor($userId) as $row) {
            if ((string)($row['issuer'] ?? '') === $issuer && (string)($row['subject'] ?? '') === $subject) {
                return true;
            }
        }

        return false;
    }

    /**
     * Records the link. Idempotent, and never throws.
     *
     * `subject` is written AS AT CREATION and never refreshed, which is a security property
     * rather than bookkeeping: the stored subject is half of the question `isLinkedTo()` asks,
     * so refreshing it on a later login would mean a login could re-point an existing link at
     * whoever presented it. An identity provider that re-issues a name id therefore breaks the
     * link ON PURPOSE, and an administrator resolves it - the cost that was accepted for this
     * guarantee.
     *
     * A BLANK OR OVER-LONG SUBJECT IS NOT WRITTEN AT ALL - silently, because this method may not
     * throw. Both would produce a row that can never match while permanently occupying the
     * account's only (userId, issuer) slot.
     */
    public function remember(string $userId, string $issuer, string $subject): void
    {
        $userId = Ascii::trim($userId);
        $issuer = Ascii::trim($issuer);
        $subject = Ascii::trim($subject);

        // THE SUBJECT IS GUARDED HERE AND NOT ONLY IN IdentityLink, because this class owns the
        // unique index and has to defend its own invariant. A row with a blank subject matches
        // nobody in isLinkedTo() AND occupies the one (userId, issuer) slot that account has,
        // after which hasRowFor() below skips every later write - the account would be refused
        // `linking_disabled` forever, with no path back but deleting the row by hand.
        //
        // An over-long subject is refused for the reason given at the widths: cutting it to 255
        // bytes was measured to make two people one.
        if ($userId === '' || $issuer === '' || $subject === '' || strlen($subject) > self::WIDTH_SUBJECT) {
            return;
        }

        $userId = Ascii::truncateBytes($userId, self::WIDTH_USER_ID);
        $issuer = Ascii::truncateBytes($issuer, self::WIDTH_ISSUER);

        try {
            $db = $this->connection();

            if (!$this->tableIsUsable($db)) {
                return;
            }

            // Read-then-write, and the unique index on (userId, issuer) is what actually
            // guarantees uniqueness - this check only keeps the ordinary repeat from throwing.
            // The race (two callbacks for one new account at once) ends in a duplicate-key
            // exception, which is caught below and is harmless: the row it collided with is
            // the row this call wanted written.
            //
            // IT ASKS ABOUT (userId, issuer) AND NOT ABOUT THE SUBJECT, unlike the lookup, and
            // the difference is deliberate: the unique index is on the pair, so an existing row
            // with a DIFFERENT subject is a row this INSERT would collide with. Skipping keeps
            // the write out of the duplicate-key path; it also leaves the stale row in place,
            // which is what the administrator's procedure in docs/troubleshooting.md is for.
            if ($this->hasRowFor($userId, $issuer)) {
                return;
            }

            $stamp = gmdate('Y-m-d H:i:s', time());

            Db::insert(self::TABLE, [
                'userId' => $userId,
                'issuer' => $issuer,
                'subject' => $subject,
                // Written explicitly rather than left to craft\db\Command's auto-fill, so the
                // INSERT behaves the same on any connection this class is handed.
                'dateCreated' => $stamp,
                'dateUpdated' => $stamp,
                'uid' => StringHelper::UUID(),
            ], $db);
        } catch (Throwable) {
            // Deliberately swallowed. The sign-in this belongs to has already happened; the
            // person is in. Losing the row costs them their next login, and throwing here would
            // cost them this one as well without saving anything.
        }
    }

    /**
     * True when the plugin's own migration has run. Cheap after the first call.
     *
     * LoginFlow asks this BEFORE the lookup, because the alternative is a silent degradation:
     * with no table, every answer here is a truthful `false` that reaches the administrator as
     * `linking_disabled`, whose printed advice is to switch linking on for everybody. See
     * IdentityLinkStoreInterface.
     */
    public function isReady(): bool
    {
        try {
            return $this->tableIsUsable($this->connection());
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Every link recorded for one account, or an empty list when we cannot read them.
     *
     * Selecting by `userId` alone and filtering in PHP is what makes the comparison exact on
     * MySQL and PostgreSQL alike; see the class docblock. Fails closed by returning nothing.
     *
     * @return list<array<string, mixed>>
     */
    private function rowsFor(string $userId): array
    {
        try {
            $db = $this->connection();

            if (!$this->tableIsUsable($db)) {
                return [];
            }

            /** @var list<array<string, mixed>> $rows */
            $rows = (new Query())
                ->select(['issuer', 'subject'])
                ->from([self::TABLE])
                ->where(['userId' => Ascii::truncateBytes($userId, self::WIDTH_USER_ID)])
                ->all($db);

            return $rows;
        } catch (Throwable) {
            // Fail closed: "we do not know" has to mean "not linked", or a database fault
            // becomes a way to sign in to accounts this plugin never created.
            return [];
        }
    }

    /** True when any row exists for this account and issuer, whatever subject it names. */
    private function hasRowFor(string $userId, string $issuer): bool
    {
        foreach ($this->rowsFor($userId) as $row) {
            if ((string)($row['issuer'] ?? '') === $issuer) {
                return true;
            }
        }

        return false;
    }

    private function tableIsUsable(Connection $db): bool
    {
        if ($this->tableUsable !== null) {
            return $this->tableUsable;
        }

        return $this->tableUsable = $db->tableExists(self::TABLE);
    }

    private function connection(): Connection
    {
        return $this->db ??= Craft::$app->getDb();
    }
}
