<?php

declare(strict_types=1);

namespace Keyway\Sso\migrations;

use craft\db\Migration;
use Keyway\Sso\Adapter\CraftDbDiagnosticsSink;
use Keyway\Sso\Adapter\CraftDbIdentityLinkStore;

/**
 * Creates the two tables this plugin owns: the diagnostics rows behind the support panel, and
 * the record of which accounts single sign-on created.
 *
 * WHY THERE IS A TABLE AT ALL. The product's support model is that the site's own administrator
 * reads a screen instead of e-mailing us. Craft's log cannot be that screen - it cannot be
 * filtered by outcome, it has no retention of its own, and an agency's administrator will never
 * find it. Everything else in this plugin is stateless on purpose; this is the single
 * exception, and it earns its place by removing a support ticket per failed login.
 *
 * WHAT IS DELIBERATE IN THE SHAPE.
 *
 * `occurredAt` is an integer Unix timestamp, not a datetime, and it is NOT redundant with
 * `dateCreated`. `dateCreated` is Craft's bookkeeping - when the row was written. `occurredAt`
 * is the plugin's clock (Core\Port\ClockInterface) - when the login happened. They differ
 * whenever a row is replayed or a test fixes the clock, and every filter, sort and retention
 * decision reads the second one. Integer seconds also mean the retention sweep compares numbers
 * rather than driver-specific date expressions across MySQL and Postgres.
 *
 * `payload` carries the full masked event as JSON and the flat columns beside it duplicate part
 * of that JSON. The duplication is the point: WHERE and ORDER BY run on real columns with real
 * indexes, while the panel's detail view reads one text column, so adding a field to the event
 * does not need a migration. Nothing in `payload` is unmasked - DiagnosticEvent masks in its
 * constructor - so this table is safe to sit in a client's database and in their backups.
 *
 * `outcome` is NOT NULL and `protocol`/`stage`/`reasonCode` are nullable. An event without an
 * outcome is not a diagnostics row at all; an event that failed before the protocol was known
 * genuinely has no protocol, and a nullable column says that more honestly than an empty string.
 *
 * INDEXES. (occurredAt) serves the default view, which is "newest first". (outcome, occurredAt)
 * serves the only filter anyone uses under pressure - "show me the failures, newest first" - and
 * is composite in that order because outcome is the equality predicate. (eventId) exists because
 * the ID is what an administrator quotes in a support e-mail, and looking it up must not scan.
 * It is deliberately NOT unique: the ID comes from a random source, collisions are
 * astronomically unlikely, and a unique index would turn one into a failed INSERT inside a
 * login.
 *
 * ------------------------------------------------------------------------------------------
 * THE SECOND TABLE: keyway_sso_links
 * ------------------------------------------------------------------------------------------
 *
 * WHY IT EXISTS is a measurement, not a design idea. On a live Craft with Okta (2026-09-15) the
 * same person's SECOND login was refused with `linking_disabled` on stock settings: the plugin
 * had created the account itself on the first login and had nowhere to write that down, so
 * ProvisioningPolicy treated it as an account the site already had. One row per (account,
 * issuer) is the fix; `subject` names WHICH person at that issuer the account was created for,
 * and it is compared on every lookup - a colleague at the same identity provider is not the
 * same human (CraftDbIdentityLinkStore).
 *
 * `userId` IS A STRING AND THERE IS NO FOREIGN KEY TO `users`, which is the one choice here
 * somebody will want to argue with. The core addresses accounts as strings
 * (Provisioning\ExistingUser) because it knows nothing about Craft's id space, and a foreign key
 * would add a cascade this plugin does not need: a deleted user leaves a row that matches
 * nothing, and the next login for that person creates a new account and a new row. The price is
 * orphan rows on a site that deletes users, measured in bytes.
 *
 * INDEXES. (userId, issuer) is UNIQUE, and the uniqueness is load-bearing rather than tidy: it
 * is what makes CraftDbIdentityLinkStore::remember() idempotent under two callbacks racing for
 * one new account - the loser gets a duplicate-key error it already swallows. (issuer, subject)
 * is not unique and exists for the administrator's question "which account belongs to this
 * identity", which is the one asked while somebody is locked out. The uniqueness stays on the
 * PAIR even though the lookup reads three columns: two rows for one account and one issuer would
 * mean two identities at that issuer own the account, which is the property the subject check
 * exists to remove.
 *
 * NOTHING HERE IS MASKED, unlike the diagnostics table, and it has to stay that way: the issuer
 * and the subject are compared byte for byte with the ones the next response carries. What keeps
 * the table safe to
 * sit in a client's backup is that it holds identifiers and nothing else - no attributes, no
 * groups, no address.
 *
 * SAFE TO RE-RUN AND SAFE TO REVERSE. safeUp() skips a table that is already there, one table at
 * a time, so an install that got the first one and died still gets the second; safeDown() drops
 * both, because they hold diagnostics and bookkeeping and nothing else - uninstalling the plugin
 * should not leave orphan rows in a client's database.
 *
 * THIS FILE ONLY EVER RUNS ON A NEW INSTALLATION, and the earlier version of this docblock got
 * that wrong in a way that cost a bug. It claimed no versioned migration was needed because
 * "every installation in existence runs THIS file" - untrue: the live Craft with Okta the
 * missing-link fault was measured on had this plugin installed weeks earlier, so Install.php
 * never ran again there and the links table never appeared. A table added here must therefore
 * ALSO arrive as a versioned migration for installations that already exist - for this one,
 * m260916_101500_add_identity_links_table, with the matching bump of `Plugin::$schemaVersion`.
 * The two files create the same table on purpose; a migration is frozen history and does not
 * call into code that keeps changing.
 */
class Install extends Migration
{
    /** Single source of truth for the names; the adapters read and write the same constants. */
    private const TABLE = CraftDbDiagnosticsSink::TABLE;
    private const LINKS_TABLE = CraftDbIdentityLinkStore::TABLE;

    public function safeUp(): bool
    {
        $this->createDiagnosticsTable();
        $this->createLinksTable();

        return true;
    }

    public function safeDown(): bool
    {
        $this->dropTableIfExists(self::LINKS_TABLE);
        $this->dropTableIfExists(self::TABLE);

        return true;
    }

    private function createDiagnosticsTable(): void
    {
        if ($this->db->tableExists(self::TABLE)) {
            return;
        }

        $this->createTable(self::TABLE, [
            'id' => $this->primaryKey(),
            'eventId' => $this->char(32)->notNull(),
            'occurredAt' => $this->integer()->notNull(),
            'protocol' => $this->string(16),
            'stage' => $this->string(32),
            'outcome' => $this->string(16)->notNull(),
            'reasonCode' => $this->string(64),
            'subject' => $this->string(255),
            'issuer' => $this->string(255),
            'payload' => $this->text()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        // Names left to Craft (createIndex(null, ...)): index names are global in Postgres, and
        // a hand-written one is a collision waiting for the first site that installs two
        // plugins with the same idea.
        $this->createIndex(null, self::TABLE, ['occurredAt']);
        $this->createIndex(null, self::TABLE, ['outcome', 'occurredAt']);
        $this->createIndex(null, self::TABLE, ['eventId']);
    }

    private function createLinksTable(): void
    {
        if ($this->db->tableExists(self::LINKS_TABLE)) {
            return;
        }

        $this->createTable(self::LINKS_TABLE, [
            'id' => $this->primaryKey(),
            'userId' => $this->string(32)->notNull(),
            'issuer' => $this->string(255)->notNull(),
            // Nullable IN THE SCHEMA ONLY, and never blank in practice: the subject is half of
            // the lookup, so IdentityLink and CraftDbIdentityLinkStore::remember() both refuse
            // to write a row without one - a blank subject matches nobody and would occupy this
            // account's only (userId, issuer) slot for good. The column stays nullable because
            // this migration is idempotent by design and skips a table that already exists: a
            // NOT NULL here would apply to fresh installs alone and quietly describe two
            // different schemas as one.
            'subject' => $this->string(255),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        // Unique, and the name is left to Craft for the reason above: index names are global in
        // Postgres.
        $this->createIndex(null, self::LINKS_TABLE, ['userId', 'issuer'], true);
        $this->createIndex(null, self::LINKS_TABLE, ['issuer', 'subject']);
    }
}
