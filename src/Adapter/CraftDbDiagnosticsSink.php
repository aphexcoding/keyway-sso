<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use Craft;
use craft\db\Connection;
use craft\db\Query;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Diagnostics\DiagnosticRow;
use Keyway\Sso\Core\Diagnostics\DiagnosticsQuery;
use Keyway\Sso\Core\Diagnostics\RetentionPolicy;
use Keyway\Sso\Core\Port\ClockInterface;
use Keyway\Sso\Core\Port\DiagnosticsReaderInterface;
use Keyway\Sso\Core\Port\DiagnosticsSinkInterface;
use Keyway\Sso\Core\Port\KeyValueCacheInterface;
use Keyway\Sso\Core\Support\Ascii;
use Throwable;

/**
 * Diagnostics in a table of their own: the storage the support panel reads.
 *
 * This is the class that makes the product's support model real. Until now events went to
 * Craft's log (CraftLogDiagnosticsSink, whose docblock says plainly that it is not a panel): no
 * filtering by outcome, no retention, and nothing an agency's administrator will ever find on
 * their own. A failed login that only exists in `storage/logs` is a support e-mail to us, which
 * is the opposite of what this plugin is for.
 *
 * ONE RULE OUTRANKS EVERY OTHER IN THIS FILE: A BROKEN DIAGNOSTICS TABLE MUST NOT BREAK A
 * LOGIN. Diagnostics are an accessory to signing in; the sink runs inside the callback, after
 * the assertion has been verified and while the person is waiting. So record() catches
 * Throwable - not a database exception, Throwable - hands the event to the fallback sink and
 * returns normally. The fallback is not decoration: it is the difference between "the panel is
 * empty" and "the event is gone".
 *
 * THE MISSING TABLE IS AN EXPECTED STATE, NOT AN ERROR. A site can have the plugin installed
 * and updated with `composer update` and simply not have run `craft up` yet, and in that window
 * every login still has to work. So the table is probed once per request and its absence routes
 * events to the log instead - silently, because an administrator mid-deployment does not need a
 * warning about a support feature.
 *
 * NOTHING IS MASKED HERE, AND THAT IS CORRECT. DiagnosticEvent masks in its constructor, so
 * everything arriving at record() is already safe to store; masking again would push
 * already-masked text through Masker twice. The reverse direction is DiagnosticRow, which
 * likewise neither masks nor unmasks. What this class does do is TRUNCATE to the column widths,
 * because MySQL in strict mode rejects an over-long value outright and a rejected INSERT loses
 * the whole event over one long issuer URL.
 *
 * PRUNING RUNS HERE BUT DECIDES NOTHING. RetentionPolicy owns age, volume and frequency; this
 * class only asks. The last sweep's timestamp lives in the shared key-value cache rather than
 * in the table, so answering "is a sweep due" costs a cache read instead of a MAX() over the
 * rows we are about to delete, and so a login does not pay for a DELETE it did not cause.
 */
final class CraftDbDiagnosticsSink implements DiagnosticsSinkInterface, DiagnosticsReaderInterface
{
    public const TABLE = '{{%keyway_sso_diagnostics}}';

    /** Namespaced by CraftKeyValueCache; this is the suffix. */
    private const PRUNE_KEY = 'diagnostics.lastPruneAt';

    /**
     * Column widths, mirrored from src/migrations/Install.php. Kept as constants rather than
     * read from the schema: this runs inside a login, and a schema round-trip per event to
     * discover a number we wrote ourselves is a bad trade.
     */
    private const WIDTH_EVENT_ID = 32;
    private const WIDTH_PROTOCOL = 16;
    private const WIDTH_STAGE = 32;
    private const WIDTH_OUTCOME = 16;
    private const WIDTH_REASON = 64;
    private const WIDTH_SUBJECT = 255;
    private const WIDTH_ISSUER = 255;

    /**
     * Below MySQL's 65,535-byte `text` limit with room for multi-byte expansion. An event this
     * large means something upstream stopped bounding itself; storing a marker keeps the row.
     */
    private const MAX_PAYLOAD_BYTES = 48_000;

    private DiagnosticsSinkInterface $fallback;
    private KeyValueCacheInterface $cache;
    private ClockInterface $clock;
    private RetentionPolicy $retention;
    private ?Connection $db;

    /** Per-request memo of the table probe; null until the first record() or read. */
    private ?bool $tableUsable = null;

    /**
     * @param DiagnosticsSinkInterface $fallback Where events go when the table cannot take them
     *                                           (CraftLogDiagnosticsSink in production).
     * @param Connection|null          $db       Injected for testing; resolved from Craft when null.
     */
    public function __construct(
        DiagnosticsSinkInterface $fallback,
        KeyValueCacheInterface $cache,
        ClockInterface $clock,
        ?RetentionPolicy $retention = null,
        ?Connection $db = null
    ) {
        $this->fallback = $fallback;
        $this->cache = $cache;
        $this->clock = $clock;
        $this->retention = $retention ?? RetentionPolicy::default();
        $this->db = $db;
    }

    /**
     * Stores one event. Never throws, whatever the database does.
     */
    public function record(DiagnosticEvent $event): void
    {
        try {
            $db = $this->connection();

            if (!$this->tableIsUsable($db)) {
                $this->fallback->record($event);

                return;
            }

            Db::insert(self::TABLE, $this->columns($event), $db);
        } catch (Throwable) {
            // Deliberately swallowed, and deliberately not re-logged as an error: the event
            // itself goes to the fallback, which is the information that matters. Rethrowing
            // would turn "diagnostics are unavailable" into "nobody can sign in".
            $this->fallbackQuietly($event);

            return;
        }

        // Separate try: a sweep that fails must not send the event to the fallback as well, or
        // a broken DELETE would duplicate every row into the log.
        try {
            $this->pruneIfDue();
        } catch (Throwable) {
            // Retention is best-effort. The next login tries again.
        }
    }

    /**
     * @return list<DiagnosticRow>
     */
    public function recent(DiagnosticsQuery $query): array
    {
        try {
            $db = $this->connection();

            if (!$this->tableIsUsable($db)) {
                return [];
            }

            /** @var list<array<string, mixed>> $rows */
            $rows = $this->filtered($query)
                ->select(['payload', 'occurredAt'])
                // `id` breaks ties: two logins inside one second are ordered by insertion, and
                // an unstable sort would make the pager repeat or skip rows between pages.
                ->orderBy(['occurredAt' => SORT_DESC, 'id' => SORT_DESC])
                ->limit($query->limit())
                ->offset($query->offset())
                ->all($db);
        } catch (Throwable) {
            return [];
        }

        $result = [];
        foreach ($rows as $row) {
            $payload = $row['payload'] ?? '';
            $result[] = DiagnosticRow::fromStoredJson(
                is_string($payload) ? $payload : '',
                (int)($row['occurredAt'] ?? 0)
            );
        }

        return $result;
    }

    public function total(DiagnosticsQuery $query): int
    {
        try {
            $db = $this->connection();

            if (!$this->tableIsUsable($db)) {
                return 0;
            }

            return (int)$this->filtered($query)->count('*', $db);
        } catch (Throwable) {
            return 0;
        }
    }

    /**
     * True when the plugin's own migration has run. Cheap after the first call.
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
     * @return array<string, mixed>
     */
    private function columns(DiagnosticEvent $event): array
    {
        $now = $this->clock->now();
        $stamp = gmdate('Y-m-d H:i:s', $now);

        return [
            'eventId' => Ascii::truncateBytes($event->id, self::WIDTH_EVENT_ID),
            'occurredAt' => $event->timestamp,
            'protocol' => Ascii::truncateBytes($event->protocol, self::WIDTH_PROTOCOL),
            'stage' => Ascii::truncateBytes($event->stage, self::WIDTH_STAGE),
            'outcome' => Ascii::truncateBytes($event->outcome->value, self::WIDTH_OUTCOME),
            'reasonCode' => Ascii::truncateBytes($event->reasonCode, self::WIDTH_REASON),
            'subject' => Ascii::truncateBytes($event->subject, self::WIDTH_SUBJECT),
            'issuer' => Ascii::truncateBytes($event->issuer, self::WIDTH_ISSUER),
            'payload' => $this->payload($event),
            // Written explicitly rather than left to craft\db\Command's auto-fill, so the
            // INSERT behaves the same on any connection this class is handed.
            'dateCreated' => $stamp,
            'dateUpdated' => $stamp,
            'uid' => StringHelper::UUID(),
        ];
    }

    /**
     * The JSON that DiagnosticRow reads back, shrunk to a marker if it somehow got huge.
     */
    private function payload(DiagnosticEvent $event): string
    {
        $json = $event->toJson();

        if (strlen($json) <= self::MAX_PAYLOAD_BYTES) {
            return $json;
        }

        $reduced = json_encode([
            'id' => $event->id,
            'timestamp' => $event->timestamp,
            'protocol' => $event->protocol,
            'stage' => $event->stage,
            'outcome' => $event->outcome->value,
            'reason' => $event->reasonCode,
            'message' => 'Diagnostics payload exceeded the storage limit and was dropped; '
                . 'the outcome above is accurate.',
            'issuer' => Ascii::truncateBytes($event->issuer, self::WIDTH_ISSUER),
            'subject' => Ascii::truncateBytes($event->subject, self::WIDTH_SUBJECT),
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $reduced === false ? '{"outcome":"error","reason":"diagnostics_encoding_failed"}' : $reduced;
    }

    /**
     * The filters, applied identically for recent() and total() - a pager whose count comes
     * from a different WHERE clause than its rows is a pager that lies.
     */
    private function filtered(DiagnosticsQuery $query): Query
    {
        $builder = (new Query())->from([self::TABLE]);

        if ($query->outcome() !== null) {
            $builder->andWhere(['outcome' => $query->outcome()]);
        }

        if ($query->protocol() !== null) {
            // The stored values, not the filter value: a SAML login row says `saml2`, the
            // filter says `saml`. See DiagnosticsQuery::STORED_PROTOCOLS.
            $builder->andWhere(['protocol' => $query->storedProtocols()]);
        }

        $search = $query->search();
        if ($search !== null) {
            // Yii escapes `%` and `_` in LIKE parameters by default, so a search for "100%"
            // is a search for that text and not a wildcard.
            $builder->andWhere([
                'or',
                ['like', 'subject', $search],
                ['like', 'issuer', $search],
                ['like', 'reasonCode', $search],
                ['like', 'eventId', $search],
            ]);
        }

        return $builder;
    }

    private function pruneIfDue(): void
    {
        $now = $this->clock->now();
        $entry = $this->cache->get(self::PRUNE_KEY);
        $lastPruneAt = is_array($entry) && isset($entry['at']) && is_int($entry['at'])
            ? $entry['at']
            : null;

        if (!$this->retention->shouldPrune($lastPruneAt, $now)) {
            return;
        }

        // Stamped BEFORE the deletes, so a sweep that dies half way does not have every
        // subsequent login retry it.
        $this->cache->set(
            self::PRUNE_KEY,
            ['at' => $now],
            max($this->retention->pruneIntervalSeconds() * 4, 3600)
        );

        $db = $this->connection();

        Db::delete(self::TABLE, ['<', 'occurredAt', $this->retention->cutoff($now)], [], $db);

        $this->trimToMaxRows($db);
    }

    /**
     * Keeps the newest `maxRows` rows and deletes the rest.
     *
     * Two statements rather than `DELETE ... WHERE id NOT IN (SELECT ...)`, because MySQL
     * refuses to delete from a table that appears in the subquery of the same statement. The
     * cut is made on `id` and not on `occurredAt`: `id` is the insertion order, so a burst of
     * events sharing one second still has a deterministic boundary.
     */
    private function trimToMaxRows(Connection $db): void
    {
        $maxRows = $this->retention->maxRows();

        /** @var mixed $oldestKept */
        $oldestKept = (new Query())
            ->select(['id'])
            ->from([self::TABLE])
            ->orderBy(['id' => SORT_DESC])
            ->offset($maxRows - 1)
            ->limit(1)
            ->scalar($db);

        if ($oldestKept === null || $oldestKept === false || $oldestKept === '') {
            return;
        }

        Db::delete(self::TABLE, ['<', 'id', (int)$oldestKept], [], $db);
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

    /**
     * The fallback is the last line; if it throws too, the login still has to finish.
     */
    private function fallbackQuietly(DiagnosticEvent $event): void
    {
        try {
            $this->fallback->record($event);
        } catch (Throwable) {
            // Nothing left to try, and nothing worth failing a login over.
        }
    }
}
