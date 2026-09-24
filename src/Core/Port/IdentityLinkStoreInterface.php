<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * Remembers which Craft accounts THIS plugin created, for which identity provider, and for whom.
 *
 * WHY IT EXISTS, measured rather than designed. Against a live Craft with Okta (2026-09-15),
 * the same person's SECOND login was refused with `linking_disabled` on default settings
 * (`allowJit` on, `linkExistingAccounts` off): the first login created the account, and on the
 * next one ProvisioningPolicy found an account it had no record of creating and treated it as
 * one the site already had. With nothing stored anywhere, every just-in-time account was good
 * for exactly one sign-in. This port is that record, and it is the only thing that lets step 4a
 * tell "an account we made two minutes ago" apart from "an account somebody made in the control
 * panel".
 *
 * ------------------------------------------------------------------------------------------
 * THE LINK IS (USER, ISSUER, SUBJECT) - ALL THREE, AND THE THIRD IS THE ONE THAT WAS MISSING
 * ------------------------------------------------------------------------------------------
 *
 * The first version of this port asked about (user, issuer) only and argued in this docblock
 * that the subject could not carry security weight. It was wrong, and the cost was measured on
 * stock settings: an attacker with an account at the SAME identity provider - subject
 * `mallory-sub` - who puts somebody else's address in their own profile matched the victim's
 * account and was let in with `update_on_login`, on a site whose owner had deliberately left
 * `linkExistingAccounts` OFF. "This issuer created this account" says nothing about WHICH person
 * at that issuer it was created for, and a shared identity provider is the ordinary case, not
 * the exotic one.
 *
 * So the question is now about a person, not only about a directory: all three values are
 * compared, exactly. THE SITE OWNER DECIDED THIS, not the implementer - it changes the meaning
 * of a switch that was already shipped, and a change of that kind belongs to whoever runs the
 * site rather than to whoever writes the code.
 *
 * THE COST THAT WAS ACCEPTED WITH IT, written down so nobody re-discovers it as a bug: identity
 * providers do re-issue `nameId` for the same human - Okta and Entra both do when an account is
 * recreated, and a SAML `transient` NameID format differs on EVERY login by definition. When
 * that happens the link stops matching, step 4a refuses, and the person cannot get into their
 * own account until an ADMINISTRATOR intervenes (delete the stale row, or link the account
 * deliberately). The diagnostics row says `linking_disabled`; docs/troubleshooting.md carries
 * the administrator's procedure and the "use a stable NameID format" instruction that keeps it
 * from happening.
 *
 * ------------------------------------------------------------------------------------------
 * CONTRACT FOR THE IMPLEMENTER
 * ------------------------------------------------------------------------------------------
 *
 *  - NO METHOD MAY THROW. All three run inside a login. `isLinkedTo()` answers FALSE when it
 *    cannot answer at all (missing table, dead database): false means "not linked", which means
 *    the login is refused, which is the safe direction - the unsafe one would be letting a
 *    broken query open step 4a for everybody.
 *  - `remember()` is best effort and must never break the sign-in it belongs to. The person is
 *    already signed in by the time it runs; the cost of losing the row is that their next login
 *    is refused, which is bad, and strictly better than a 500 on a successful login.
 *  - `remember()` is called repeatedly for the same account over a site's lifetime and must be
 *    idempotent.
 *  - Comparison is EXACT on all three values - byte for byte, and not left to a database
 *    collation, which is case-insensitive by default on MySQL and would make `Mallory-Sub` and
 *    `mallory-sub` the same person.
 *  - A BLANK SUBJECT IS NEVER STORED. `remember()` with an empty (or whitespace-only) subject
 *    must write NOTHING and return quietly. The reason is not tidiness: such a row can never
 *    satisfy `isLinkedTo()`, which rejects a blank subject, while an implementation that keeps
 *    one row per (user, issuer) - the shipped one enforces exactly that with a unique index -
 *    has now spent that account's only slot. Every later `remember()` with the real subject is
 *    skipped as "already recorded", and the account is refused `linking_disabled` for good,
 *    with no way back except deleting the row by hand. The core guards this too
 *    (Core\Login\IdentityLink), and an implementation may not rely on that: it owns its own
 *    storage invariant.
 *  - A VALUE THAT DOES NOT FIT THE STORAGE FAILS CLOSED RATHER THAN BEING TRUNCATED, for the
 *    subject specifically. The subject is per person and comes from the identity provider, so
 *    cutting it to a column width merges everybody who shares that prefix into one link - the
 *    shipped adapter was measured doing it at 255 bytes. Answer false, write nothing. (The
 *    issuer is different in kind: it is the site's own configuration, verified before it gets
 *    here, so the shipped adapter truncates it symmetrically on read and write instead of
 *    locking such a site out.)
 */
interface IdentityLinkStoreInterface
{
    /**
     * True only when this plugin created that account for that issuer AND that subject.
     *
     * @param string $userId Craft user id, as a string - the core never invents numeric ids.
     * @param string $issuer The verified issuer of the response being processed.
     * @param string $subject The subject (`NameID` / `sub`) the response carried.
     */
    public function isLinkedTo(string $userId, string $issuer, string $subject): bool;

    /**
     * Records "this plugin created this account for this issuer and this subject". Idempotent,
     * never throws.
     *
     * Writes nothing when the subject is blank or does not fit the store - see the contract
     * above; both cases would produce a row that matches nobody and blocks the real one.
     */
    public function remember(string $userId, string $issuer, string $subject): void;

    /**
     * Can this store answer at all? False means the record is unavailable - typically the
     * plugin's migrations have not been run on this installation.
     *
     * It exists because the failure is otherwise INVISIBLE: the shipped adapter swallows its own
     * database faults by contract, so nothing throws, `isLinkedTo()` simply answers false, and
     * the administrator sees `linking_disabled` - a refusal whose printed advice is to switch on
     * the very setting that opens account linking for everybody. Asking the store whether it is
     * ready lets LoginFlow say `identity_link_unavailable` instead. MUST NOT THROW either, and
     * must not change what a login is allowed to do: fail-closed stays fail-closed, this only
     * changes what gets written into the diagnostics panel.
     */
    public function isReady(): bool;
}
