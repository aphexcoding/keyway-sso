<?php

declare(strict_types=1);

namespace Keyway\Sso\migrations;

use craft\db\Migration;
use Keyway\Sso\Adapter\CraftDbIdentityLinkStore;

/**
 * Gives `keyway_sso_links` to an installation that already has this plugin installed.
 *
 * WHY THIS FILE EXISTS, and why Install.php was not enough. The table was added to Install.php
 * alone, which runs ONCE, when Craft installs the plugin. The installation the fix was measured
 * on - a live Craft with Okta that has been running this plugin for weeks - is precisely the one
 * Install.php never runs on again: `craft up` compares the stored schema version with
 * `Plugin::$schemaVersion`, finds them equal, does nothing, and the table stays missing. Step
 * 4a then refuses every second login on that site with `linking_disabled`, which is the bug the
 * table was written to fix. So: a versioned migration, plus the schema version bump in
 * Plugin.php that makes Craft look for it.
 *
 * IDEMPOTENT, because both paths are real. A site installed AFTER the table went into
 * Install.php already has it and must not get a "table exists" error out of `craft up`; a site
 * installed before does not. The table check answers both without a flag anywhere.
 *
 * THE DDL IS DUPLICATED FROM Install.php ON PURPOSE. A migration is a historical record: it must
 * keep doing in a year what it did today, so it does not call into code that is free to change
 * around it. The one thing that is shared is the table NAME, taken from the store's constant,
 * because a plugin that creates a table it does not read is worse than a copied column list.
 */
class m260916_101500_add_identity_links_table extends Migration
{
    private const TABLE = CraftDbIdentityLinkStore::TABLE;

    public function safeUp(): bool
    {
        if ($this->db->tableExists(self::TABLE)) {
            return true;
        }

        $this->createTable(self::TABLE, [
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

        // Names left to Craft: index names are global in Postgres, and a hand-written one is a
        // collision waiting for the first site that installs two plugins with the same idea.
        // (userId, issuer) is UNIQUE and the uniqueness is load-bearing: it is what makes
        // CraftDbIdentityLinkStore::remember() idempotent under two callbacks racing for one
        // new account.
        $this->createIndex(null, self::TABLE, ['userId', 'issuer'], true);
        $this->createIndex(null, self::TABLE, ['issuer', 'subject']);

        return true;
    }

    /**
     * NOT REVERSIBLE, and refusing is the honest answer rather than laziness. Dropping the table
     * here would take the record away from a working site, and every account single sign-on
     * created would be refused on its next login (fail-closed, `linking_disabled`). Uninstalling
     * the plugin still drops it - that is Install::safeDown().
     */
    public function safeDown(): bool
    {
        echo self::class . " cannot be reverted: dropping the link table locks out every account single sign-on created.\n";

        return false;
    }
}
