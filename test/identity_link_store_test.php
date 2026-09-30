<?php

declare(strict_types=1);

use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Diagnostics\LoginOutcome;
use Keyway\Sso\Core\Login\CallbackStyle;
use Keyway\Sso\Core\Login\CookieDirective;
use Keyway\Sso\Core\Login\IdentityLink;
use Keyway\Sso\Core\Login\LoginCompletion;
use Keyway\Sso\Core\Login\LoginRefusal;
use Keyway\Sso\Core\Attribute\MappedAttributes;
use Keyway\Sso\Core\Attribute\UserField;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Group\GroupRule;
use Keyway\Sso\Core\Provisioning\ProvisioningAction;
use Keyway\Sso\Core\Provisioning\ProvisioningDecision;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Test\Support\Assert;

/**
 * "Which accounts did single sign-on create" - the rule for writing one down, and the storage
 * that keeps it.
 *
 * WHY THE FEATURE EXISTS is a measurement and not a preference: on a live Craft with Okta
 * (2026-09-15) the same person's SECOND login was refused with `linking_disabled` on stock
 * settings, because the account created by the first login looked like an account the site
 * already had. Everything below defends one half of the repair.
 *
 * THE RULE (IdentityLink). A link may only be written for an account this plugin CREATED. Not
 * for one it was allowed to link to: `linkExistingAccounts` is a switch the site owner can turn
 * back off, and a link recorded from such a login would keep step 4a of the provisioning policy
 * open for that account forever - the setting would stop meaning anything. These cases are pure
 * core and run with no vendor directory.
 *
 * THE STORAGE (CraftDbIdentityLinkStore). It runs inside a login, so the cases below plant
 * failures in the database layer and require an answer rather than an exception - and require
 * the two directions of failure to differ: an unreadable table answers "not linked" (refuse the
 * login), while a failed write is swallowed (the person is already signed in).
 *
 * WHAT THIS FILE CANNOT PROVE, stated so nobody reads a green line as more than it is: that
 * MySQL and Postgres accept the SQL, that the unique index really rejects a duplicate under
 * concurrency, or that the migration ran. Those need a server and belong to the acceptance test.
 */

$suite = 'identity_link_store';

$decision = static function (ProvisioningAction $action): ProvisioningDecision {
    return new ProvisioningDecision(
        $action,
        $action === ProvisioningAction::Create
            ? ProvisioningDecision::JIT_CREATE
            : ProvisioningDecision::UPDATE_ON_LOGIN,
        'message for the administrator',
        new MappedAttributes([UserField::EMAIL => 'person@example.com']),
        (new GroupMapper(new GroupMap([GroupRule::exact('Editors', 'editors')])))->mapGroups(['Editors']),
        UserMatchKey::Email,
        'person@example.com',
        $action === ProvisioningAction::Create ? null : '17'
    );
};

$completion = static function (
    ProvisioningDecision $decision,
    string $issuer = 'https://idp.example.com',
    string $subject = 'subject-1'
): LoginCompletion {
    return LoginCompletion::allow(
        $decision,
        '/admin',
        new CookieDirective('keyway_sso_bind', '', '/', 0, false, true, 'Lax'),
        null,
        true,
        $issuer,
        $subject
    );
};

$cases = [
    // ------------------------------------------------------------------ IdentityLink (pure)

    'a created account is recorded, with the issuer and subject the response carried' =>
        static function () use ($decision, $completion): void {
            $link = IdentityLink::afterSignIn($completion($decision(ProvisioningAction::Create)), 17);

            Assert::notNull($link);
            Assert::same('17', $link?->userId, 'the id comes from Craft, not from the decision');
            Assert::same('https://idp.example.com', $link?->issuer);
            Assert::same('subject-1', $link?->subject);
        },

    // THE RULE THAT PROTECTS THE SETTING. A login that merely attached itself to an existing
    // account must leave no link behind, or turning `linkExistingAccounts` back off would stop
    // closing anything.
    'a login that only linked to an existing account records nothing' =>
        static function () use ($decision, $completion): void {
            Assert::null(
                IdentityLink::afterSignIn($completion($decision(ProvisioningAction::Update)), 17)
            );
            Assert::null(
                IdentityLink::afterSignIn($completion($decision(ProvisioningAction::SignInOnly)), 17)
            );
        },

    'nothing is recorded without an account id, an issuer, or an allowed login' =>
        static function () use ($decision, $completion): void {
            $created = $decision(ProvisioningAction::Create);

            // Craft did not come back with an id: there is no account to point at.
            Assert::null(IdentityLink::afterSignIn($completion($created), null));

            // A link with no issuer would be a link to "anybody".
            Assert::null(IdentityLink::afterSignIn($completion($created, ''), 17));
            Assert::null(IdentityLink::afterSignIn($completion($created, '   '), 17));

            // A refusal is not a fact anything may be written from.
            $refused = LoginCompletion::refuse(
                ProvisioningDecision::LINKING_DISABLED,
                'message for the administrator',
                new CookieDirective('keyway_sso_bind', '', '/', 0, false, true, 'Lax')
            );

            Assert::null(IdentityLink::afterSignIn($refused, 17));
        },

    'a link is not written without a subject, because it could never match' =>
        static function () use ($decision, $completion): void {
            // The subject is not an audit column: the lookup is (userId, issuer, subject). A
            // row with a blank subject matches nobody AND occupies the unique (userId, issuer)
            // slot, so it would keep a real link from ever being written for that account.
            Assert::null(
                IdentityLink::afterSignIn(
                    $completion($decision(ProvisioningAction::Create), 'https://idp.example.com', ''),
                    17
                )
            );
            Assert::null(
                IdentityLink::afterSignIn(
                    $completion($decision(ProvisioningAction::Create), 'https://idp.example.com', '   '),
                    17
                )
            );

            // The control: the same login with a subject is recorded.
            Assert::notNull(
                IdentityLink::afterSignIn(
                    $completion($decision(ProvisioningAction::Create), 'https://idp.example.com', 'subject-1'),
                    17
                )
            );
        },

    // THE INSTALLATION THIS FIX WAS MEASURED ON ALREADY HAD THE PLUGIN INSTALLED, so Install.php
    // - which runs once, at install time - could never deliver the table to it. Without a
    // versioned migration and a schema version to match, `craft up` compares 1.0.0 with 1.0.0
    // and does nothing. This case cannot prove the SQL runs; it pins the two halves that make
    // Craft look at all.
    'an installed site gets the links table through a versioned migration' =>
        static function (): void {
            $migrations = glob(dirname(__DIR__) . '/src/migrations/m*.php') ?: [];

            Assert::notSame([], $migrations, 'Install.php alone never reaches an installed site');

            $creates = array_values(array_filter(
                $migrations,
                static fn (string $file): bool => str_contains((string)file_get_contents($file), 'keyway_sso_links')
                    || str_contains((string)file_get_contents($file), 'CraftDbIdentityLinkStore::TABLE')
            ));

            Assert::notSame([], $creates, 'no versioned migration creates the links table');

            $source = (string)file_get_contents($creates[0]);
            Assert::contains('tableExists', $source, 'it also runs on a site that already has the table');
            Assert::contains("createIndex(null, self::TABLE, ['userId', 'issuer'], true)", $source);

            // And the number that makes Craft run it. Read as text so the case needs no Craft.
            $plugin = (string)file_get_contents(dirname(__DIR__) . '/src/Plugin.php');
            preg_match('/\$schemaVersion\s*=\s*\'([^\']+)\'/', $plugin, $found);

            Assert::same(1, version_compare($found[1] ?? '0', '1.0.0'), 'the schema version was not bumped');
        },

    'the reason code for an unreadable link store is its own, and it is a notice' =>
        static function (): void {
            // Distinct from `linking_disabled`, because the administrator's next step differs:
            // one is a setting, the other is `craft up`.
            Assert::same('identity_link_unavailable', LoginRefusal::IDENTITY_LINK_UNAVAILABLE);
            Assert::notSame(LoginRefusal::IDENTITY_LINK_UNAVAILABLE, LoginRefusal::PROVISIONING_INCOMPLETE);
            Assert::same(DiagnosticEvent::STAGE_PROVISIONING, 'provisioning');
            Assert::same('notice', LoginOutcome::Notice->value);
        },
];

/**
 * Everything below needs Craft's DB classes. Skipped loudly rather than silently.
 */
if (!class_exists(\craft\db\Connection::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", $suite, 'skipped (adapter cases): vendor absent (run composer install)'));

    return $cases;
}

$store = static function (
    \Keyway\Sso\Test\Support\FakeCraftDbConnection $db
): \Keyway\Sso\Adapter\CraftDbIdentityLinkStore {
    return new \Keyway\Sso\Adapter\CraftDbIdentityLinkStore($db);
};

return $cases + [
    'a recorded link is found again, by user, issuer and subject' => static function () use ($store): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->rows = [];

        $subject = $store($db);
        $subject->remember('17', 'https://idp.example.com', 'subject-1');

        Assert::same(1, count($db->inserts), 'exactly one row per (account, issuer)');
        $insert = $db->inserts[0];
        Assert::same('{{%keyway_sso_links}}', $insert['table']);
        Assert::same('17', $insert['columns']['userId']);
        Assert::same('https://idp.example.com', $insert['columns']['issuer'], 'never masked: it is compared byte for byte');
        Assert::same('subject-1', $insert['columns']['subject']);
        Assert::same(36, strlen((string)$insert['columns']['uid']));
        Assert::same($insert['columns']['dateCreated'], $insert['columns']['dateUpdated']);

        // The read side selects that account's rows with the id BOUND rather than inlined - a
        // login must not be able to smuggle SQL through an identifier - and decides on the
        // issuer and the subject in PHP, so no site's collation gets a vote.
        $db->rows = [['issuer' => 'https://idp.example.com', 'subject' => 'subject-1']];
        Assert::true($store($db)->isLinkedTo('17', 'https://idp.example.com', 'subject-1'));
        Assert::contains('keyway_sso_links', (string)$db->lastSql());
        Assert::sameList(['17'], array_values($db->lastParams()));
    },

    // THE TAKEOVER THAT (user, issuer) ALLOWED, at the storage layer. Measured on stock
    // settings before the fix: a colleague at the SAME identity provider, subject
    // `mallory-sub`, with the victim's address in their own profile, was let into the victim's
    // account. Comparing the subject as well is what closes that path.
    'a different subject at the same issuer is not the same link' => static function () use ($store): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->rows = [['issuer' => 'https://idp.example.com', 'subject' => 'alice-sub']];

        $subject = $store($db);

        Assert::false(
            $subject->isLinkedTo('17', 'https://idp.example.com', 'mallory-sub'),
            'somebody else at the same directory is somebody else'
        );

        // Exact, and not "exact as the database understands it": MySQL's default collation is
        // case- and accent-insensitive, which would make these one person.
        Assert::false($subject->isLinkedTo('17', 'https://idp.example.com', 'Alice-Sub'));
        Assert::false($subject->isLinkedTo('17', 'HTTPS://idp.example.com', 'alice-sub'));
        Assert::false($subject->isLinkedTo('17', 'https://idp.example.com', 'alice-sub-2'));

        // Surrounding whitespace IS ignored, and that is the plugin's own doing rather than the
        // database's: both sides go through Ascii::trim, the same way the protocol readers trim
        // what they read out of a response.
        Assert::true($subject->isLinkedTo('17', ' https://idp.example.com ', '  alice-sub  '));

        // The control that makes the refusals mean something.
        Assert::true($subject->isLinkedTo('17', 'https://idp.example.com', 'alice-sub'));
    },

    'recording the same link twice writes one row' => static function () use ($store): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $subject = $store($db);

        $db->rows = [];
        $subject->remember('17', 'https://idp.example.com', 'subject-1');

        // The row is there now, so the second call must not insert again: the unique index
        // would reject it, and a swallowed exception per login is not a design.
        $db->rows = [['issuer' => 'https://idp.example.com', 'subject' => 'subject-1']];
        $subject->remember('17', 'https://idp.example.com', 'subject-1');

        // And not even when the subject differs: the unique index is on (userId, issuer), so
        // this INSERT would collide. The stale row is the administrator's to remove.
        $subject->remember('17', 'https://idp.example.com', 'subject-2');

        Assert::same(1, count($db->inserts));
    },

    // THE `craft up` CASE. A site can be running this plugin with the migration not yet applied,
    // and in that window every login still has to behave predictably.
    'a missing table denies rather than admits, and writes nothing' => static function () use ($store): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->tableThere = false;

        $subject = $store($db);

        Assert::false($subject->isLinkedTo('17', 'https://idp.example.com', 'subject-1'), 'unknown means not linked');
        Assert::false($subject->isReady());

        $subject->remember('17', 'https://idp.example.com', 'subject-1');

        Assert::same([], $db->inserts, 'nothing is written into a table that is not there');
        Assert::same([], $db->statements, 'and the row is not looked up either');
    },

    'a database that explodes mid-login keeps the failure to itself' => static function () use ($store): void {
        foreach ([
            'command' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failCommands = new \yii\db\Exception('the server has gone away');
            },
            'insert' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failInserts = new \yii\db\IntegrityException('duplicate entry for key userId_issuer');
            },
            'table check' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failTableCheck = new \RuntimeException('schema unavailable');
            },
            'error, not exception' => static function (\Keyway\Sso\Test\Support\FakeCraftDbConnection $db): void {
                $db->failCommands = new \Error('out of memory somewhere below us');
            },
        ] as $label => $break) {
            $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
            $db->scalar = 0;
            $break($db);

            $subject = $store($db);

            // The read fails CLOSED: a broken query must not open step 4a for every account.
            Assert::false($subject->isLinkedTo('17', 'https://idp.example.com', 'subject-1'), $label);

            // Readiness is about the TABLE, not about the query: a store whose schema probe
            // throws cannot claim to be ready, while one whose SELECT fails still knows the
            // table is there and says so - the notice in LoginFlow is for the first case.
            if ($label === 'table check') {
                Assert::false($subject->isReady(), $label);
            }

            // The write is swallowed: the person is already signed in by the time it runs, and
            // taking their session away would not save the row.
            $subject->remember('17', 'https://idp.example.com', 'subject-1');
        }

        Assert::true(true, 'no exception escaped any of the four failures');
    },

    'a blank id, issuer or subject is answered without touching the database' => static function () use ($store): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $subject = $store($db);

        Assert::false($subject->isLinkedTo('', 'https://idp.example.com', 'subject-1'));
        Assert::false($subject->isLinkedTo('17', '   ', 'subject-1'));
        // A response with no name id must not inherit somebody else's link.
        Assert::false($subject->isLinkedTo('17', 'https://idp.example.com', '   '));

        $subject->remember('', 'https://idp.example.com', 'subject-1');
        $subject->remember('17', '', 'subject-1');

        Assert::same([], $db->inserts);
        Assert::same([], $db->statements);
    },

    'an id or issuer too long for its column is cut instead of losing the row' => static function () use ($store): void {
        $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
        $db->rows = [];

        // MySQL in strict mode rejects an over-long value outright, and a rejected INSERT here
        // costs the person their next login. The issuer survives that treatment because it is
        // the site's own configuration, cut by the same helper on both sides, so the install
        // still matches itself; the subject does NOT - see the case below.
        $store($db)->remember(
            str_repeat('9', 100),
            'https://' . str_repeat('i', 900),
            'subject-1'
        );

        $columns = $db->inserts[0]['columns'];
        Assert::same(32, strlen((string)$columns['userId']));
        Assert::same(255, strlen((string)$columns['issuer']));
        Assert::same('subject-1', $columns['subject']);
        Assert::notSame(false, json_encode($columns), 'truncation left valid UTF-8');

        // And it still matches itself: the same over-long issuer is cut identically on read.
        $db->rows = [['issuer' => 'https://' . str_repeat('i', 247), 'subject' => 'subject-1']];
        Assert::true(
            $store($db)->isLinkedTo(str_repeat('9', 100), 'https://' . str_repeat('i', 900), 'subject-1')
        );
    },

    // A BLANK SUBJECT, AT THE ADAPTER. The core refuses to build such a link (the IdentityLink
    // case above),
    // but this class owns the unique index on (userId, issuer) and has to defend it on its own:
    // a row with a blank subject matches nobody and occupies the account's only slot, after
    // which hasRowFor() skips every later write and the account is refused for good.
    'a blank subject is not written, and does not block the real one afterwards' =>
        static function () use ($store): void {
            $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
            $db->rows = [];
            $subject = $store($db);

            $subject->remember('42', 'https://idp.example.com', '');
            $subject->remember('42', 'https://idp.example.com', '   ');

            Assert::same([], $db->inserts, 'a row that could never match was not written');

            // THE HALF THAT MATTERS. Nothing took the slot, so the real login still records
            // itself - which is the difference between a refused login and a permanently dead
            // account.
            $subject->remember('42', 'https://idp.example.com', 'alice-sub');

            Assert::same(1, count($db->inserts));
            Assert::same('alice-sub', $db->inserts[0]['columns']['subject']);

            $db->rows = [['issuer' => 'https://idp.example.com', 'subject' => 'alice-sub']];
            Assert::true($subject->isLinkedTo('42', 'https://idp.example.com', 'alice-sub'));
        },

    // A TRUNCATED SUBJECT. Measured before the fix: a row holding 255 x 'a' (cut from
    // `255a.alice`) answered TRUE
    // for a probe of 255 x 'a' + '.mallory' - two people, one link, straight across the
    // security boundary the subject exists to draw. Truncation is right for an issuer and wrong
    // for a subject, so an over-long subject now fails closed on both sides.
    'a subject too long for its column is refused, not cut into somebody else' =>
        static function () use ($store): void {
            $db = \Keyway\Sso\Test\Support\FakeCraftDbConnection::make();
            $prefix = str_repeat('a', 255);
            $db->rows = [['issuer' => 'https://idp.example.com', 'subject' => $prefix]];

            $subject = $store($db);

            Assert::false(
                $subject->isLinkedTo('17', 'https://idp.example.com', $prefix . '.mallory'),
                'sharing the first 255 bytes is not being the same person'
            );

            // The write side falls the same way: a truncated row would be the trap the read
            // just refused to walk into.
            $db->rows = [];
            $subject->remember('17', 'https://idp.example.com', $prefix . '.alice');

            Assert::same([], $db->inserts, 'nothing is stored that would match the wrong person');

            // The control: 255 bytes exactly still fits and still works.
            $db->rows = [['issuer' => 'https://idp.example.com', 'subject' => $prefix]];
            Assert::true($subject->isLinkedTo('17', 'https://idp.example.com', $prefix));
        },

    'the migration and the store name the same table' => static function (): void {
        // One constant, read by both: a rename that touches only one of them is a table the
        // plugin creates and never reads.
        $constant = (new ReflectionClass(\Keyway\Sso\migrations\Install::class))
            ->getConstant('LINKS_TABLE');

        Assert::same(\Keyway\Sso\Adapter\CraftDbIdentityLinkStore::TABLE, $constant);
    },
];
