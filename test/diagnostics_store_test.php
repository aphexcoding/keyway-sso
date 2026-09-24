<?php

declare(strict_types=1);

use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Diagnostics\DiagnosticRow;
use Keyway\Sso\Core\Diagnostics\DiagnosticsQuery;
use Keyway\Sso\Core\Diagnostics\LoginOutcome;
use Keyway\Sso\Core\Diagnostics\Masker;
use Keyway\Sso\Core\Diagnostics\RetentionPolicy;
use Keyway\Sso\Test\Support\Assert;

/**
 * The storage half of the diagnostics panel: what is written, what comes back, what is swept.
 *
 * The cases below are grouped by the thing that would break in production if they were absent.
 *
 * READING A ROW CANNOT FAIL. The panel is opened during an incident, and it shows rows written
 * by every version of the plugin that ever ran on that site. One row from an older schema, one
 * truncated by a `text` column, one half-written when the database went away - any of them
 * taking the screen down turns a support feature into a second outage. So fromStoredJson() is
 * hammered with rubbish here and is required to answer with a row every time.
 *
 * FILTERS COME FROM THE URL BAR. Everything DiagnosticsQuery holds arrived as a query-string
 * parameter, so the cases treat it as hostile: unknown values must collapse, not travel into a
 * WHERE clause, and `limit` must be clamped at BOTH ends so neither `?limit=0` nor
 * `?limit=100000` reaches the database.
 *
 * DIAGNOSTICS MUST NOT BREAK A LOGIN. The adapter cases plant a failure in the database layer
 * and require that it stays inside record(), with the event reaching the fallback sink. This is
 * the single most important property in the file: the sink runs inside the callback, while the
 * person is waiting.
 *
 * The Craft-facing half skips itself when `vendor/` is absent, loudly, the way
 * craft_adapters and sso_controller do - a suite that returns [] in silence reads as green.
 */

$suite = 'diagnostics_store';

$event = static function (
    LoginOutcome $outcome = LoginOutcome::Success,
    string $subject = 'jan.kowalski@example.com',
    string $issuer = 'https://idp.example.com/metadata',
    array $attributes = ['email' => ['jan.kowalski@example.com'], 'memberOf' => ['Editors', 'Staff']]
): DiagnosticEvent {
    return new DiagnosticEvent(
        'a1b2c3d4e5f60718',
        1_700_000_123,
        'saml',
        DiagnosticEvent::STAGE_PROVISIONING,
        $outcome,
        'user_created',
        'Created a new user from the assertion.',
        $issuer,
        $subject,
        $attributes,
        ['fields' => ['email' => 'j***i@example.com']],
        ['action' => 'create', 'grantsAdmin' => false]
    );
};

$cases = [
    // ---------------------------------------------------------------- DiagnosticRow (pure)

    'a stored event comes back as a row without being masked a second time' => static function () use ($event): void {
        $stored = $event()->toJson();
        $row = DiagnosticRow::fromStoredJson($stored, 0);

        Assert::same('a1b2c3d4e5f60718', $row->id);
        Assert::same(1_700_000_123, $row->timestamp);
        Assert::same('saml', $row->protocol);
        Assert::same(DiagnosticEvent::STAGE_PROVISIONING, $row->stage);
        Assert::same('success', $row->outcome);
        // `reason` is the key DiagnosticEvent writes; reading `reasonCode` would silently
        // produce an empty column on every row in the panel.
        Assert::same('user_created', $row->reasonCode);
        Assert::true($row->isSuccess());
        Assert::false($row->isUnreadable());

        // Byte for byte what the sink stored: not masked again on the way out, not unmasked.
        Assert::same(Masker::maskValue('jan.kowalski@example.com'), $row->subject);
        Assert::same('j***i@example.com', $row->subject);

        Assert::same(
            [Masker::maskValue('Editors'), Masker::maskValue('Staff')],
            $row->attributes()['memberOf']
        );
        Assert::same('create', $row->decision()['action']);
        Assert::same('j***i@example.com', $row->mapping()['fields']['email']);
    },

    'the read model does not reach for the masker at all' => static function (): void {
        // The guarantee in DiagnosticRow's docblock is a property of the FILE, so it is checked
        // on the file rather than described and hoped for. Masking on the way out would be a
        // second pass over already-masked text, and unmasking would defeat the point of the
        // first pass; neither belongs in a read model.
        $source = (string)file_get_contents(
            (string)(new ReflectionClass(DiagnosticRow::class))->getFileName()
        );

        $code = '';
        foreach (token_get_all($source) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $code .= is_array($token) ? $token[1] : $token;
        }

        Assert::notContains('Masker', $code);
        Assert::notContains('mask', $code);
    },

    'rubbish in the payload column becomes a placeholder row, never an exception' => static function (): void {
        $rubbish = [
            '',
            '   ',
            'not json at all',
            '{"outcome":"success"',            // truncated by a too-small column
            '{"outcome":"success","attributes', // truncated mid-key
            '[1,2,3]',                          // a list where an object was expected
            'null',
            'true',
            '"a string"',
            '{}',                               // no outcome at all
            '{"outcome":"succes"}',             // typo: outside the enum
            '{"outcome":42}',
            '{"outcome":null}',
            "{\"outcome\":\"success\",\"id\":\"\xC3\x28\"}", // invalid UTF-8
        ];

        foreach ($rubbish as $json) {
            $row = DiagnosticRow::fromStoredJson($json, 1_700_000_500);

            Assert::same(DiagnosticRow::REASON_UNREADABLE, $row->reasonCode, $json);
            Assert::true($row->isUnreadable(), $json);
            Assert::same('error', $row->outcome, $json);
            Assert::false($row->isSuccess(), $json);
            Assert::same(1_700_000_500, $row->timestamp, $json);
            Assert::same([], $row->attributes(), $json);
            Assert::same([], $row->mapping(), $json);
            Assert::same([], $row->decision(), $json);
            Assert::notSame('', $row->message, $json);
        }
    },

    'an unreadable row keeps the id and timestamp it could read' => static function (): void {
        $row = DiagnosticRow::fromStoredJson(
            '{"id":"deadbeefdeadbeef","timestamp":1700000042,"outcome":"from-the-future"}',
            7
        );

        Assert::same(DiagnosticRow::REASON_UNREADABLE, $row->reasonCode);
        // Kept so the panel can still show WHEN, and so support can correlate the id from the
        // administrator's e-mail with a row it otherwise cannot parse.
        Assert::same('deadbeefdeadbeef', $row->id);
        Assert::same(1_700_000_042, $row->timestamp);
    },

    'wrong types in a stored row are coerced rather than fatal' => static function (): void {
        $row = DiagnosticRow::fromStoredJson(json_encode([
            'id' => 12345,
            'timestamp' => '1700000777',
            'protocol' => ['saml'],
            'stage' => true,
            'outcome' => 'denied',
            'reason' => 'domain_not_allowed',
            'message' => 1.5,
            'issuer' => null,
            'subject' => 'j***i@example.com',
            'attributes' => ['memberOf' => 'Editors', 'roles' => ['a', ['nested'], 'b'], 'n' => 7],
            'mapping' => ['already', 'a', 'list'],
            'decision' => 'not an array',
        ], JSON_THROW_ON_ERROR), 0);

        Assert::same('12345', $row->id);
        Assert::same(1_700_000_777, $row->timestamp);
        Assert::same('', $row->protocol, 'an array is not a protocol');
        Assert::same('true', $row->stage);
        Assert::same('denied', $row->outcome);
        Assert::same('domain_not_allowed', $row->reasonCode);
        Assert::same('1.5', $row->message);
        Assert::same('', $row->issuer);
        Assert::same(['Editors'], $row->attributes()['memberOf']);
        Assert::same(['a', 'b'], $row->attributes()['roles'], 'nested arrays are dropped, siblings kept');
        Assert::same(['7'], $row->attributes()['n']);
        Assert::same([], $row->mapping(), 'a JSON list is not a mapping summary');
        Assert::same([], $row->decision());
    },

    'a row built with an outcome outside the enum still reads as an error' => static function (): void {
        $row = new DiagnosticRow('id', 1, 'saml', 'state', 'whatever', 'r', 'm');

        Assert::same('error', $row->outcome);
        Assert::false($row->isSuccess());
    },

    'every outcome the recorder can produce survives the round trip' => static function () use ($event): void {
        foreach (LoginOutcome::cases() as $outcome) {
            $row = DiagnosticRow::fromStoredJson($event($outcome)->toJson(), 0);

            Assert::same($outcome->value, $row->outcome, $outcome->value);
            Assert::false($row->isUnreadable(), $outcome->value);
            Assert::same($outcome === LoginOutcome::Success, $row->isSuccess(), $outcome->value);
        }
    },

    // ---------------------------------------------------------------- DiagnosticsQuery (pure)

    'an unknown outcome is dropped instead of becoming a filter' => static function (): void {
        foreach (['succes', 'SUCCESS-ish', 'failed', '1', 'success;drop', '%'] as $value) {
            Assert::null(DiagnosticsQuery::fromInput($value, null, null, null, null)->outcome(), $value);
        }

        foreach (LoginOutcome::cases() as $outcome) {
            Assert::same(
                $outcome->value,
                DiagnosticsQuery::fromInput($outcome->value, null, null, null, null)->outcome()
            );
        }

        Assert::same('denied', DiagnosticsQuery::fromInput('  DENIED ', null, null, null, null)->outcome());
        Assert::null(DiagnosticsQuery::fromInput('all', null, null, null, null)->outcome());
        Assert::null(DiagnosticsQuery::fromInput('', null, null, null, null)->outcome());
        Assert::null(DiagnosticsQuery::fromInput(null, null, null, null, null)->outcome());
    },

    'an unknown protocol is dropped, and `disabled` is not a protocol a row can have' => static function (): void {
        Assert::same('saml', DiagnosticsQuery::fromInput(null, 'SAML', null, null, null)->protocol());
        Assert::same('oidc', DiagnosticsQuery::fromInput(null, ' oidc ', null, null, null)->protocol());
        Assert::null(DiagnosticsQuery::fromInput(null, 'disabled', null, null, null)->protocol());
        Assert::null(DiagnosticsQuery::fromInput(null, 'ldap', null, null, null)->protocol());
        Assert::null(DiagnosticsQuery::fromInput(null, '', null, null, null)->protocol());
    },

    'the protocol list stays in step with AuthProtocol' => static function (): void {
        // Core must not import Config, so the list is duplicated; this pins the duplicate.
        $enabled = array_values(array_filter(
            AuthProtocol::values(),
            static fn(string $value): bool => AuthProtocol::from($value)->isEnabled()
        ));

        Assert::sameList($enabled, DiagnosticsQuery::PROTOCOLS);

        foreach (DiagnosticsQuery::PROTOCOLS as $protocol) {
            Assert::same($protocol, DiagnosticsQuery::fromInput(null, $protocol, null, null, null)->protocol());
        }
    },

    'limit is clamped at both ends and offset never goes negative' => static function (): void {
        Assert::same(50, DiagnosticsQuery::fromInput(null, null, null, null, null)->limit());
        Assert::same(1, DiagnosticsQuery::fromInput(null, null, null, 0, null)->limit());
        Assert::same(1, DiagnosticsQuery::fromInput(null, null, null, -20, null)->limit());
        Assert::same(200, DiagnosticsQuery::fromInput(null, null, null, 100_000, null)->limit());
        Assert::same(200, DiagnosticsQuery::fromInput(null, null, null, PHP_INT_MAX, null)->limit());
        Assert::same(25, DiagnosticsQuery::fromInput(null, null, null, 25, null)->limit());

        Assert::same(0, DiagnosticsQuery::fromInput(null, null, null, null, null)->offset());
        Assert::same(0, DiagnosticsQuery::fromInput(null, null, null, null, -5)->offset());
        Assert::same(80, DiagnosticsQuery::fromInput(null, null, null, null, 80)->offset());
        Assert::same(0, DiagnosticsQuery::fromInput(null, null, null, null, 80)->withOffset(-1)->offset());
        Assert::same(200, DiagnosticsQuery::all(999)->limit());
    },

    'search is trimmed, stripped of control characters and byte-capped' => static function (): void {
        Assert::null(DiagnosticsQuery::fromInput(null, null, null, null, null)->search());
        Assert::null(DiagnosticsQuery::fromInput(null, null, '', null, null)->search());
        Assert::null(DiagnosticsQuery::fromInput(null, null, "  \t \n ", null, null)->search());
        Assert::same('okta', DiagnosticsQuery::fromInput(null, null, '  okta  ', null, null)->search());
        Assert::same(
            'okta com',
            DiagnosticsQuery::fromInput(null, null, "okta\r\ncom", null, null)->search()
        );

        $long = str_repeat('a', 5000);
        $search = DiagnosticsQuery::fromInput(null, null, $long, null, null)->search();
        Assert::notNull($search);
        Assert::same(DiagnosticsQuery::MAX_SEARCH_BYTES, strlen((string)$search));

        // A cap that cut a multi-byte character in half would break json_encode downstream.
        $utf8 = DiagnosticsQuery::fromInput(null, null, str_repeat('ą', 200), null, null)->search();
        Assert::notNull($utf8);
        Assert::same($utf8, (string)json_decode((string)json_encode($utf8)));
    },

    'hasFilters reports what the panel should show as active' => static function (): void {
        Assert::false(DiagnosticsQuery::all()->hasFilters());
        Assert::false(DiagnosticsQuery::fromInput('nonsense', 'nonsense', '  ', 10, 0)->hasFilters());
        Assert::true(DiagnosticsQuery::fromInput('error', null, null, null, null)->hasFilters());
        Assert::true(DiagnosticsQuery::fromInput(null, null, 'okta', null, null)->hasFilters());
    },

    // ---------------------------------------------------------------- RetentionPolicy (pure)

    'the default policy is 30 days and 2000 rows' => static function (): void {
        $policy = RetentionPolicy::default();

        Assert::same(30, $policy->days());
        Assert::same(2000, $policy->maxRows());
        Assert::same(3600, $policy->pruneIntervalSeconds());
        Assert::same(1_700_000_000 - (30 * 86_400), $policy->cutoff(1_700_000_000));
    },

    'nonsensical retention settings are clamped, not obeyed' => static function (): void {
        // days = 0 obeyed literally would delete every row the moment it was written.
        $zero = new RetentionPolicy(0, 0, 0);
        Assert::same(1, $zero->days());
        Assert::true($zero->maxRows() >= 10);
        Assert::true($zero->pruneIntervalSeconds() >= 60);
        Assert::true($zero->cutoff(1_700_000_000) < 1_700_000_000);

        $negative = new RetentionPolicy(-30, -5, -1);
        Assert::same(1, $negative->days());
        Assert::true($negative->maxRows() >= 10);

        $absurd = new RetentionPolicy(PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX);
        Assert::same(3650, $absurd->days());
        Assert::same(1_000_000, $absurd->maxRows());
        Assert::same(86_400, $absurd->pruneIntervalSeconds());
        // The clamp is what keeps this from overflowing into a negative cutoff.
        Assert::true($absurd->cutoff(1_700_000_000) > 0);
    },

    'a sweep is due once per interval and never twice in a row' => static function (): void {
        $policy = new RetentionPolicy(30, 2000, 3600);
        $now = 1_700_000_000;

        Assert::true($policy->shouldPrune(null, $now), 'never swept');
        Assert::false($policy->shouldPrune($now, $now), 'just swept');
        Assert::false($policy->shouldPrune($now - 3599, $now));
        Assert::true($policy->shouldPrune($now - 3600, $now));
        Assert::true($policy->shouldPrune($now - 100_000, $now));
        // A stamp from the future (clock change, another host) must not suspend pruning until
        // that future arrives.
        Assert::true($policy->shouldPrune($now + 10_000, $now));
    },
];

/**
 * Everything below needs Craft's DB classes. Skipped loudly rather than silently.
 */
if (!class_exists(\craft\db\Connection::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", $suite, 'skipped (adapter cases): vendor absent (run composer install)'));

    return $cases;
}

$sink = static function (
    \Keyway\Sso\Test\Support\FakeCraftDbConnection $db,
    \Keyway\Sso\Test\Support\CollectingSink $fallback,
    \Keyway\Sso\Test\Support\FixedClock $clock,
    ?RetentionPolicy $policy = null
): \Keyway\Sso\Adapter\CraftDbDiagnosticsSink {
    return new \Keyway\Sso\Adapter\CraftDbDiagnosticsSink(
        $fallback,
        new \Keyway\Sso\Core\Support\InMemoryKeyValueCache($clock),
        $clock,
        $policy,
        $db
    );
};

return $cases + [
    'one login writes one row, and the row reads back as itself' => static function () use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $fallback = new \Keyway\Sso\Test\Support\CollectingSink();
        $clock = new \Keyway\Sso\Test\Support\FixedClock(1_700_000_900);

        $sink($db, $fallback, $clock)->record($event());

        Assert::same(1, count($db->inserts));
        Assert::same([], $fallback->events, 'the fallback is for failures only');

        $insert = $db->inserts[0];
        Assert::same('{{%keyway_sso_diagnostics}}', $insert['table']);

        $columns = $insert['columns'];
        Assert::same('a1b2c3d4e5f60718', $columns['eventId']);
        // occurredAt is the login's clock, dateCreated is the write's - they are not the same
        // field and the panel sorts on the first.
        Assert::same(1_700_000_123, $columns['occurredAt']);
        Assert::same(gmdate('Y-m-d H:i:s', 1_700_000_900), $columns['dateCreated']);
        Assert::same($columns['dateCreated'], $columns['dateUpdated']);
        Assert::same(36, strlen((string)$columns['uid']));
        Assert::same('saml', $columns['protocol']);
        Assert::same('provisioning', $columns['stage']);
        Assert::same('success', $columns['outcome']);
        Assert::same('user_created', $columns['reasonCode']);
        Assert::same(Masker::maskValue('jan.kowalski@example.com'), $columns['subject']);

        $row = DiagnosticRow::fromStoredJson((string)$columns['payload'], 0);
        Assert::false($row->isUnreadable(), 'what the sink writes must be what the panel can read');
        Assert::same('user_created', $row->reasonCode);
        Assert::same(
            [Masker::maskValue('Editors'), Masker::maskValue('Staff')],
            $row->attributes()['memberOf']
        );
    },

    'values too long for their columns are cut instead of losing the whole row' => static function ($_ = null) use ($sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();

        // DiagnosticEvent caps `message` and `issuer` itself, but NOT the id, the protocol, the
        // stage or the reason code - those reach the sink exactly as whoever built the event
        // wrote them. MySQL in strict mode rejects an over-long value outright, so without the
        // truncation below the whole event is lost to one long reason code.
        $oversized = new DiagnosticEvent(
            str_repeat('e', 200),
            1_700_000_123,
            str_repeat('p', 200),
            str_repeat('s', 200),
            LoginOutcome::Error,
            str_repeat('r', 200),
            str_repeat('m', 5000),
            'https://' . str_repeat('i', 900),
            str_repeat('x', 900) . '@example.com'
        );

        $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), new \Keyway\Sso\Test\Support\FixedClock())
            ->record($oversized);

        $columns = $db->inserts[0]['columns'];
        foreach ([
            'eventId' => 32,
            'protocol' => 16,
            'stage' => 32,
            'outcome' => 16,
            'reasonCode' => 64,
            'subject' => 255,
            'issuer' => 255,
        ] as $column => $width) {
            Assert::true(
                strlen((string)$columns[$column]) <= $width,
                $column . ' is wider than its column (' . strlen((string)$columns[$column]) . ')'
            );
            Assert::notSame('', (string)$columns[$column], $column . ' survived truncation');
        }

        Assert::true(strlen((string)$columns['payload']) <= 48_000, 'payload cap');
        // Truncation must leave valid UTF-8 or json_encode() downstream drops the row.
        Assert::notSame(false, json_encode($columns));

        // A truncated multi-byte value would make the payload unencodable, so check the one
        // column that is built from characters rather than from our own hex ids.
        $utf8 = new DiagnosticEvent(
            'id', 1, str_repeat('ą', 40), 'stage', LoginOutcome::Error, str_repeat('ę', 80), 'm'
        );
        $db->inserts = [];
        $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), new \Keyway\Sso\Test\Support\FixedClock())
            ->record($utf8);
        $utf8Columns = $db->inserts[0]['columns'];
        Assert::true(strlen((string)$utf8Columns['protocol']) <= 16);
        Assert::notSame(false, json_encode($utf8Columns), 'truncation left valid UTF-8');
    },

    'a database that explodes mid-login keeps the failure to itself' => static function () use ($event, $sink): void {
        foreach ([
            'command' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failCommands = new \yii\db\Exception('the server has gone away');
            },
            'insert' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failInserts = new \yii\db\IntegrityException('deadlock found when trying to get lock');
            },
            'table check' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failTableCheck = new \RuntimeException('schema unavailable');
            },
            'error, not exception' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failCommands = new \Error('out of memory somewhere below us');
            },
        ] as $label => $break) {
            $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
            $break($db);

            $fallback = new \Keyway\Sso\Test\Support\CollectingSink();
            $recorded = $event();

            Assert::doesNotThrow(
                static fn() => $sink($db, $fallback, new \Keyway\Sso\Test\Support\FixedClock())->record($recorded),
                $label
            );

            // The event is not lost: it goes where CraftLogDiagnosticsSink can still see it.
            Assert::same(1, count($fallback->events), $label);
            Assert::same($recorded, $fallback->last(), $label);
        }
    },

    'a fallback sink that fails too still does not fail the login' => static function () use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->failCommands = new \yii\db\Exception('gone');

        $angry = new class implements \Keyway\Sso\Core\Port\DiagnosticsSinkInterface {
            public int $calls = 0;

            public function record(DiagnosticEvent $event): void
            {
                $this->calls++;

                throw new \RuntimeException('the log directory is not writable either');
            }
        };

        $subject = new \Keyway\Sso\Adapter\CraftDbDiagnosticsSink(
            $angry,
            new \Keyway\Sso\Core\Support\InMemoryKeyValueCache(new \Keyway\Sso\Test\Support\FixedClock()),
            new \Keyway\Sso\Test\Support\FixedClock(),
            null,
            $db
        );

        Assert::doesNotThrow(static fn() => $subject->record($event()));
        Assert::same(1, $angry->calls);
    },

    'a table that was never migrated is an expected state, not an error' => static function () use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->tableThere = false;

        $fallback = new \Keyway\Sso\Test\Support\CollectingSink();
        $subject = $sink($db, $fallback, new \Keyway\Sso\Test\Support\FixedClock());

        $subject->record($event());

        Assert::same([], $db->inserts, 'no INSERT is attempted against a table that is not there');
        Assert::same([], $db->statements);
        Assert::same(1, count($fallback->events));
        Assert::false($subject->isReady());

        // And the panel says "nothing here" rather than throwing at an administrator who is
        // mid-deployment.
        Assert::same([], $subject->recent(DiagnosticsQuery::all()));
        Assert::same(0, $subject->total(DiagnosticsQuery::all()));
    },

    'the panel reads newest first, with the clamped limit and offset' => static function ($_ = null) use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->rows = [
            ['payload' => $event(LoginOutcome::Denied)->toJson(), 'occurredAt' => 1_700_000_300],
            ['payload' => 'truncated{', 'occurredAt' => 1_700_000_200],
            ['payload' => $event(LoginOutcome::Success)->toJson(), 'occurredAt' => 1_700_000_100],
        ];

        $rows = $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), new \Keyway\Sso\Test\Support\FixedClock())
            ->recent(DiagnosticsQuery::fromInput(null, null, null, 9_999, 40));

        Assert::same(3, count($rows));
        Assert::same('denied', $rows[0]->outcome);
        // A single unreadable row in the middle does not take the screen down with it.
        Assert::true($rows[1]->isUnreadable());
        Assert::same(1_700_000_200, $rows[1]->timestamp, 'occurredAt rescues the timestamp');
        Assert::same('success', $rows[2]->outcome);

        $sql = (string)$db->lastSql();
        Assert::contains('ORDER BY `occurredAt` DESC, `id` DESC', $sql);
        Assert::contains('LIMIT 200', $sql);
        Assert::contains('OFFSET 40', $sql);
    },

    'filters become bound parameters, wildcards and all' => static function ($_ = null) use ($sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->scalar = '17';

        $subject = $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), new \Keyway\Sso\Test\Support\FixedClock());
        $query = DiagnosticsQuery::fromInput('error', 'oidc', "100%_o'brien", 10, 0);

        $subject->recent($query);

        $sql = (string)$db->lastSql();
        $params = $db->lastParams();

        Assert::contains('`outcome`=', $sql);
        Assert::contains('`protocol`=', $sql);
        Assert::contains('LIKE', $sql);
        Assert::notContains("o'brien", $sql, 'the search text must never be inlined into SQL');
        Assert::true(in_array('error', $params, true));
        Assert::true(in_array('oidc', $params, true));
        // Yii escapes LIKE metacharacters by default: "100%" searches for that text, not for
        // every row in the table.
        //
        // COUNTED, NOT just "present somewhere". The search spans four columns
        // and this assertion used to accept the escaped value appearing once - so turning off
        // escaping on a SINGLE column left the suite green, while that column quietly stopped
        // being a substring search: Yii binds the raw text with no surrounding `%`, and
        // `subject LIKE 'o''brien'` matches only an exact value.
        Assert::same(
            4,
            count(array_keys($params, "%100\\%\\_o'brien%", true)),
            'every searched column gets the escaped pattern: ' . json_encode($params)
        );

        Assert::same(17, $subject->total($query), 'a string count from the driver is still a number');
        Assert::contains('COUNT(*)', (string)$db->lastSql());
    },

    'reads answer empty instead of throwing when the database is unreachable' => static function () use ($sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->failCommands = new \yii\db\Exception('connection refused');

        $subject = $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), new \Keyway\Sso\Test\Support\FixedClock());

        Assert::same([], $subject->recent(DiagnosticsQuery::all()));
        Assert::same(0, $subject->total(DiagnosticsQuery::all()));
    },

    'the sweep runs once per interval, by age and by row count' => static function () use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->scalar = '4321';
        $clock = new \Keyway\Sso\Test\Support\FixedClock(1_700_000_000);
        $subject = $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), $clock, new RetentionPolicy(30, 2000, 3600));

        $subject->record($event());

        Assert::same(2, count($db->deletes), 'one delete by age, one by row count');
        Assert::same(['<', 'occurredAt', 1_700_000_000 - (30 * 86_400)], $db->deletes[0]['condition']);
        Assert::same(['<', 'id', 4321], $db->deletes[1]['condition']);

        // Every subsequent login inside the interval writes its row and sweeps nothing: a
        // DELETE in the critical path of signing in is the thing this avoids.
        $subject->record($event());
        $clock->advance(3599);
        $subject->record($event());
        Assert::same(3, count($db->inserts));
        Assert::same(2, count($db->deletes), 'still only the first sweep');

        $clock->advance(1);
        $subject->record($event());
        Assert::same(4, count($db->deletes));
        Assert::same(['<', 'occurredAt', 1_700_003_600 - (30 * 86_400)], $db->deletes[2]['condition']);
    },

    'nothing is trimmed when the table is smaller than the row cap' => static function () use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->scalar = null; // fewer rows than maxRows: no Nth-newest id exists

        $sink($db, new \Keyway\Sso\Test\Support\CollectingSink(), new \Keyway\Sso\Test\Support\FixedClock())
            ->record($event());

        Assert::same(1, count($db->deletes), 'only the age sweep');
        Assert::same('occurredAt', $db->deletes[0]['condition'][1]);
    },

    'a sweep that fails does not push the event into the fallback as well' => static function () use ($event, $sink): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->failDeletes = new \yii\db\Exception('lock wait timeout exceeded');

        $fallback = new \Keyway\Sso\Test\Support\CollectingSink();

        Assert::doesNotThrow(
            static fn() => $sink($db, $fallback, new \Keyway\Sso\Test\Support\FixedClock())->record($event())
        );

        Assert::same(1, count($db->inserts), 'the row was written');
        // Sending it to the log as well would duplicate every row on a site whose DELETE is
        // failing - the panel and the log would disagree about what happened.
        Assert::same([], $fallback->events);
    },
];
