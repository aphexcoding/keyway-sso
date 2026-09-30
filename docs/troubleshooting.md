# Troubleshooting: when single sign-on does not sign anybody in

This page is a lookup tool, not a tutorial. Start at the diagnostics screen, read the reason code
off the failed row, then find that code in the tables below.

Related pages: [Keycloak](keycloak.md) · [Okta](okta.md) · [Microsoft Entra ID](entra-id.md) ·
[overview](README.md).

---

## 1. Start here: the diagnostics screen

**Where it is.** Settings → Plugins → Keyway SSO → section **Diagnostics** → button
**Open sign-in diagnostics**. The plugin registers no navigation item, so that button on the
settings screen is the way in. The address is the path `sso/diagnostics` under your control panel
trigger (on a default install, `/admin/sso/diagnostics`).

**Who can open it.** Craft **admin accounts only** — not everybody with control panel access. The
rows carry a masked account identifier, an issuer and group names belonging to other people. The
screen works while `allowAdminChanges` is off, which is the usual state of a production install and
exactly where a failing login has to be diagnosable.

**What a row says.** Seven columns, newest first:

| Column | What it holds |
|---|---|
| Time | When the attempt was handled |
| Outcome | **Signed in** (green) · **Refused** (orange) · **Error** (red) · **Notice** (blue) |
| Protocol | `SAML 2.0`, `OIDC`, or a raw value such as `unknown` when the attempt failed before the connection could be identified |
| Stage | `Protocol`, `Login state`, `Attributes`, `Groups`, `Provisioning`, `Session` |
| Reason | The **reason code**, shown raw in `<code>` — this is the identifier to search for and to quote |
| Subject | The account identifier from the provider, masked (`j***n@acme.example`) |
| Issuer | The issuer the response claimed |

Every row has a **Details** expander with five things: the administrator-facing message, **Attributes
received**, **Mapped to**, **Decision**, and the **Entry ID** (quote it if you contact support).

**How to read the three parts of a failure, in order:**

1. **Outcome** tells you which kind of problem it is. `Error` = the request or the configuration was
   wrong. `Refused` = everything verified and a policy said no — the fix is in the plugin's
   Provisioning/Group settings, not at the identity provider. `Notice` = the login worked and
   something about it deserves attention.
2. **Stage** tells you where in the round trip it stopped: `Protocol` (signature, discovery, token
   exchange), `Login state` (the token tying the callback to a login this site started, plus the
   browser-binding cookie), `Attributes` (claim → Craft field mapping), `Provisioning` (create /
   update / deny), `Session` (Craft refused to sign the account in).
3. **Reason** is the exact cause. Look it up in section 3.

**Filters.** Outcome, Protocol and a free-text **Search** that matches the reason code, the masked
subject, the issuer and the entry ID. The filtered URL is the whole state of the screen, so it can
be bookmarked and pasted into a ticket. Page size defaults to 50 rows and is capped at 200.

**Three empty states, three different meanings:**

* *"The diagnostics entries could not be read…"* — almost always a `composer update` without
  `php craft up`: the plugin's table does not exist yet. Run the pending database updates
  (Utilities → Updates, or `php craft up`) and reload. The technical reason is in the Craft log.
* *"No sign-in attempts have been recorded yet."* — a fresh install. Not an error.
* *"No entries match the current filters."* — there are rows, just not in this view. Use the
  **Clear** link.

**How long rows live.** Age **30 days**, at most **2 000 rows**, and the sweep runs at most once an
hour so that a delete never sits in the critical path of signing in. Whichever limit is hit first
wins: on a site with a broken provider and a scheduled job hitting the login endpoint, the row cap
can consume a day of history in an afternoon. **These values are fixed in the plugin and there is
no setting for them**, so export or screenshot anything you need to keep.

**What is masked, and why something looks unhelpful.** Masking happens when the row is written, not
when it is rendered:

* the subject and mapped values are partial: a plain value keeps two characters at each end
  (`ab***yz`), an e-mail keeps one character of the local part and **the whole domain**
  (`j***n@acme.example`), because the domain is the first thing worth checking;
* claim names are shown in full;
* **group names are shown in full only under `Mapped to`** — the lists `matchedIdpGroups`,
  `unmatchedIdpGroups` and `craftGroups` are deliberately unmasked, because they are the thing being
  debugged. **The same group values under `Attributes received` are masked** like any other claim
  value (`en***ng`), because that block is the raw claim set. When you are comparing a directory
  group name against a mapping rule — the `no_group_match` case — read it from **Mapped to**, never
  from **Attributes received**;
* any attribute whose **name** contains `password`, `secret`, `token`, `assertion`, `signature`,
  `certificate`, `credential`, `authorization`, `cookie`, `code`, `otp`, `pin`, `apikey` (and
  similar) is stored as `[redacted]`. The match is a case-insensitive substring, so an innocent
  claim such as `postalCode` or `countryCode` is redacted too. That is deliberate over-masking, not
  a bug;
* at most 30 attributes and 5 values each are kept, the rest is summarised as `[+n more]`;
* values are truncated to 96 bytes.

---

## 2. Why the person signing in sees a vague message

Everybody refused sees exactly one sentence, on a 403 page, whatever the cause:

> We could not sign you in with single sign-on. If you believe this is a mistake, ask the person who
> runs this site to check the single sign-on diagnostics.

**This is a design decision, not an unfinished error message.** The value used to find the account
comes from the identity provider. If the wording changed with the cause, anyone who can reach the
login endpoint could tell "no such account" from "that account exists", from "that account is
suspended", from "that account is an administrator" — an account-enumeration oracle, and one that
leaks the state of the user table and parts of the site's configuration.

So the split is: **the visitor is told nothing, the administrator is told everything.** The specific
reason, the message, the attributes that arrived and the decision are on the diagnostics screen
described above. If a user reports "it just says it could not sign me in", that is the product
working — open the diagnostics screen, filter by `Refused` or `Error`, and read the newest row.

---

## 3. Reason code → what actually happened → what to do

### 3a. Starting the login (nothing left this site yet)

| Code | What actually happened | What to do |
|---|---|---|
| `not_configured` | Single sign-on is selected but the saved configuration cannot sign anybody in, so the flow refused to start. **No diagnostics row is written for this** — there is no connection to attribute it to. | Open the settings screen. It shows *"Single sign-on is selected but the connection is not usable yet…"* and the failing fields. Note that the SSO button is hidden in this state too, so "the button disappeared" and this refusal have the same cause. |
| `connection_cannot_start` | The connection can validate a response but cannot build a request. Not reachable in the shipped configuration (one connection, both halves built together). **No diagnostics row.** | Treat as a bug and report it with the plugin version. |
| `start_failed` | Building the authentication request threw. For OIDC this is nearly always the discovery document: unreachable, not JSON, wrong issuer, non-https endpoint, or no `S256` PKCE support. For SAML it is a DEFLATE failure. The provider's own message **and its reason code** are in the row's detail. | Read the appended code in the message: `discovery_failed` (the well-known URL is wrong or the provider is down), `issuer_mismatch` (the document's `issuer` is not byte-for-byte the configured issuer), `algorithm_not_allowed` (the provider signs id tokens only with algorithms this plugin refuses). Check the Issuer field on the settings screen first. |
| `state_context_lost` | The request builder issued a login state without the connection handle or the browser-binding decision, so the callback could never verify it. | Internal fault, caught at the start so it points at the cause. Report it; no configuration change fixes it. |

### 3b. The login state and the browser (stage `Login state`)

| Code | What actually happened | What to do |
|---|---|---|
| `state_missing` | The callback carried no login state field at all (`RelayState` for SAML, `state` for OIDC). | Usually a scanner, a bookmarked callback URL, or an IdP-initiated login: this plugin only accepts logins **it** started. Also check that the provider is configured to relay the state parameter back. |
| `state_ambiguous` | State fields for more than one connection arrived at once, so which login this is cannot be known. | Fails closed rather than guessing. Check for a proxy or a rewrite adding parameters to the callback. |
| `state_rejected` | The state itself was refused. The specific reason is **appended in round brackets at the end of the message**, exactly as `(expired)`, `(unknown)`, `(malformed)`, `(already_used)`, `(secret_mismatch)`, `(storage_unconfirmed)` — searchable as written. | `expired` — the login took longer than the window (5 minutes); start again. `unknown` — started on another server, or the cache was cleared mid-login; check that all web nodes share one cache. `already_used` — the response was replayed, or the user pressed back and re-submitted. `storage_unconfirmed` — **the cache backing SSO state is not storing what this site writes to it**; fix the cache configuration, this one will break every login. `malformed` / `secret_mismatch` — the value came back altered. |
| `connection_missing` | The state does not say which connection it belongs to, so there is no way to know whose certificate should validate the response. Refused rather than falling back to the currently configured connection. | Internal fault (the storage layer filtered the key, or the starter rebuilt the context). Report it. |
| `connection_unknown` | The state was issued for a connection this site no longer has configured. | The protocol was switched while a login was in flight. Ask the user to sign in again. |
| `connection_mismatch` | The state came back in the other protocol's callback field — e.g. a SAML state arriving in `state`. | Check which callback address the provider posts to: the SAML assertion must go to the ACS URL, the OIDC code to the redirect URI. |
| `binding_cookie_missing` | A browser-binding cookie **was** issued and the browser sent none back. | Two possibilities with opposite fixes. Either the response arrived in a different browser (which is what the check exists to stop), or something between the browser and the site strips cookies from the callback — a reverse proxy, a privacy extension, or a SameSite policy. For SAML the callback is a cross-site POST and needs a `SameSite=None` cookie, which browsers only accept over HTTPS. |
| `binding_mismatch` | A binding cookie arrived and it belongs to a different login. | A response was presented to a browser that did not start it. Ask the user to close other login tabs and try once; if it repeats for everybody, look for a cache in front of the site serving one user's cookie to another. |
| `binding_undeclared` | The state carries no record of whether a binding was issued at all. Refused — a binding inferred from a missing value could be switched off by sending nothing. | Internal fault; report it. |
| `binding_inconsistent` | The state says it was bound to a browser but carries no value to compare against. | Internal fault; report it. |
| `state_not_burnt` | The response verified, but the login state was not marked as used, so it could be replayed. Refused after a successful verification. | Fail-closed guard against a programming error or a cache that accepts writes without storing them. Check the cache backend (the same cause as `storage_unconfirmed`), then report it. |
| `binding_not_issued` | **Notice, not a refusal.** The login ran (or started) **without** the cookie that ties it to the browser that began it, because none could be issued: a cross-site POST callback on a site not served over HTTPS. | Serve the callback URL over HTTPS. The login works meanwhile, with the login-CSRF gap open. The settings screen carries the matching warning. |

### 3c. The response itself (stage `Protocol`)

| Code | What actually happened | What to do |
|---|---|---|
| `identity_rejected` | The protocol reader refused the response. **The reader's own code is appended in round brackets at the end of the message**, exactly as `(issuer_mismatch)` or `(signature_invalid)`, and that code is the part that matters — see the table below. | Look up the appended code. |

Codes that appear inside `identity_rejected`:

| Appended code | Meaning | Typical fix |
|---|---|---|
| `signature_invalid` | The signature does not verify against the configured IdP certificate, or the JWT signature failed. | Re-copy the IdP signing certificate / check that the provider rotated its key. |
| `signature_coverage` | SAML only: the signature does not cover the assertion that was parsed — missing or duplicate assertion ID, no single `ds:Signature` child, a `Reference` pointing elsewhere, or no enveloped-signature transform. | A provider or proxy is re-wrapping the assertion. Do not relax anything; investigate what modifies the response. |
| `malformed_response` | The document could not be parsed or is structurally wrong: no `SAMLResponse` field, bad base64, not well-formed XML, a token response that is not JSON, no `id_token`, an unusable `access_token`, a non-Bearer token type, an unreadable `aud`, a missing `iat`. | Read the message — it names the specific defect. |
| `issuer_mismatch` | The issuer in the response (or in the discovery document) is not the configured one, compared byte for byte. | Copy the issuer exactly as the provider publishes it, including or excluding a trailing slash. |
| `audience_mismatch` | SAML: the `AudienceRestriction` does not name this SP entity ID. OIDC: `aud` does not contain the client ID, or there are several audiences and no `azp` naming this client. | Make the SP entity ID / client ID identical on both sides. |
| `assertion_expired` | A time window did not check out: SAML `NotBefore`/`NotOnOrAfter`, or OIDC `exp` / `iat` in the future / id token older than the accepted login window (5 minutes) / `nbf`. | Check clock sync on both machines first. Clock skew tolerance is configurable up to 120 seconds; the checks themselves cannot be turned off. |
| `replayed_assertion` | The same assertion or id token (`jti`) was presented twice. | Back button or an actual replay. Not a configuration problem. |
| `unsolicited_response` | Nothing tied the response to a login this site started: no `RelayState` / `state`, a state the store rejected, a state carrying no nonce or PKCE verifier, or a SAML `InResponseTo` that does not match the request id this site issued. | IdP-initiated sign-on is not supported — users must start at the Craft login screen. |
| `subject_missing` | No non-empty `NameID` / `sub`. | Configure the provider to release a subject. |
| `subject_mismatch` | The userinfo response describes a different subject than the verified id token. | Turn off **Fetch userinfo** and report it; this is the shape of an account mix-up. |
| `multiple_assertions` | SAML: more than one assertion element, or decrypted content that is not exactly one assertion. | Configure the provider to send exactly one. |
| `status_not_success` | The provider itself said the login failed — SAML `StatusCode` other than Success, or an OIDC callback carrying `error=…`. **The failure happened at the provider**, and its value is in the message. | Read the provider's own log: consent denied, user not assigned to the application, MFA refused. |
| `confirmation_invalid` | SAML, and the first cause is by far the most common: the assertion's `SubjectConfirmationData/@Recipient` is not **literally equal** to the configured ACS URL (no substring or prefix leniency, no way to relax it). The message quotes the `Recipient` that arrived. The same code also covers a missing bearer `SubjectConfirmation`, not exactly one `SubjectConfirmationData`, and a `SubjectConfirmationData` with no `NotOnOrAfter` of its own. | For the `Recipient` case: put the **three addresses side by side character for character** — the ACS URL registered at the provider, the value in the plugin's **ACS URL** field, and the read-only **ACS URL this site answers on** shown above it. A trailing slash, `http` against `https`, a control-panel prefix or a differing host is enough. For the other causes the provider's SAML profile is wrong: the assertion must use the bearer confirmation method with exactly one data element. |
| `destination_mismatch` | SAML: the `Destination` attribute is not this endpoint. | The ACS URL registered at the provider is not the one this site answers on. Copy the address shown on the settings screen. |
| `doctype_rejected` | The XML carried a `DOCTYPE` declaration. | Refused outright (entity-expansion defence). Whatever produced that document is not sending plain SAML. |
| `decryption_failed` | An `EncryptedAssertion` arrived with no SP private key configured, or decryption failed. | Fill in **SP private key** (as an environment variable), or turn encryption off at the provider. See the limits in section 6 about the SP certificate. |
| `algorithm_not_allowed` | OIDC: the token header, the JWKS key, or the provider's advertised list offers only algorithms this plugin refuses. Only `RS256` and `ES256` are accepted, and the list is fixed in code. | Configure the provider to sign id tokens with RS256 or ES256. |
| `key_not_found` | No JWKS key matched the token's `kid` even after a refresh. | The provider rotated keys faster than the refresh rule allows, or the JWKS URL is wrong. Retry once, then check discovery. |
| `nonce_mismatch` | The id token carries no nonce, or a nonce belonging to a different login. | The provider is dropping the `nonce` parameter. This cannot be disabled here. |
| `token_hash_mismatch` | `at_hash` or `c_hash` present and not matching the token / code it should. | Report it — this indicates a substituted token or code. |
| `discovery_failed` | The discovery document could not be fetched, answered a non-2xx status, is not a JSON object, advertises a non-https endpoint, does not support `S256`, or the token / userinfo endpoint could not be reached. | Fetch `<issuer>/.well-known/openid-configuration` from the server itself (firewall, proxy, TLS trust store), then re-check the issuer value. |

### 3d. Attributes (stage `Attributes`)

| Code | What actually happened | What to do |
|---|---|---|
| `attributes_rejected` | The response verified, but mapping refused it: either a **required** attribute was not sent, or a value mapped to `email` is not a valid address. The message names the exact source attributes. | Open **Details → Attributes received** on that row: it shows the claim names the provider actually sent. Either add the claim at the provider, point the mapping rule at a claim that is there, or clear the **Required** switch on that rule. Remember that with the mapping table left empty, the shipped defaults apply and `email` is required. |

### 3e. Provisioning (stage `Provisioning`, outcome `Refused`)

These rows mean the response was completely valid; the plugin's own policy said no. The fix is on
the Craft settings screen, not at the provider.

| Code | What actually happened | What to do |
|---|---|---|
| `domain_not_allowed` | The address's domain is not on **Allowed e-mail domains**. The allowed list is in the message. | Add the domain, or leave the field empty to allow any. `example.com` matches exactly; `.example.com` matches sub-domains only. |
| `email_missing` | No e-mail address was mapped, and it was needed — either because a domain list is configured, or because it is the match key, or because a new account cannot be created without one. | Fix the attribute mapping (see `attributes_rejected`). |
| `username_missing` | **Match existing accounts by** is set to *Username* and no username was mapped. | Map a claim to `username`, or match by e-mail. |
| `no_group_match` | **Deny login when no group matches** is on and none of the provider's groups matched a mapping rule. Note that the default group deliberately does **not** satisfy this check. | Open **Details → Mapped to → unmatchedIdpGroups**: it shows the group names that arrived, in full. Add a rule for one of them, or turn the switch off. |
| `jit_disabled` | No Craft account matched and **Create accounts on first login** is off. | Turn it on, or create the account by hand first. |
| `linking_disabled` | A Craft account already exists for this identity and **Link to existing Craft accounts** is off. Deliberately off by default — this is the boundary an account takeover crosses. **Second cause, and the one that looks like a configuration mistake and is not one:** the plugin's table of accounts it created itself cannot be read, so an account this connection made just-in-time looks like somebody else's. **Third cause, for one person only:** the account *was* created by SSO, but the provider is now sending a **different subject (`NameID` / `sub`)** for them, so the record no longer matches — see "one person suddenly refused" below. | Turn it on **and** fill in the allowed domains. It never falls through to "create a second account instead". If the person is signing in for the second time to an account SSO created, run the pending migrations first (`php craft up`) — see `identity_link_unavailable` below. If it is one person and only one person, read the subject block below before changing any setting. |
| `admin_link_not_allowed` | The matching account is an **administrator** account and **Linking may include admin accounts** is off. | A second, separate opt-in on purpose. Turn it on only if you accept that whoever administers the directory can hand out the owner's account. |
| `account_suspended` | The matching Craft account is suspended. Single sign-on does not lift a suspension. | Unsuspend it in the control panel. |
| `account_inactive` | The matching account has been deactivated. SSO does not reactivate an account somebody deactivated on purpose. | Reactivate it in the control panel first. |
| `account_locked` | The account is locked after repeated failed sign-in attempts. SSO does not clear a lockout. | Unlock it in the control panel. |
| `identity_link_unavailable` | **Notice, not a refusal**, and the one to read before blaming the identity provider: the record of which accounts single sign-on created could not be read, so the login was decided as if the account had not been created here. The refusal itself is then reported as `linking_disabled`. The message says which of the two it is — *the plugin's table is missing* (the migrations have not run on this site) or *could not be read*, followed by the **class** of the error. The database's own text is deliberately **not** stored: it would carry the SQL statement into a screen support staff read. | Run the pending database updates (`php craft up`), then have them sign in again. If this appears on a site that has been running for a while, that is the expected cause: the table arrived in a plugin update and `craft up` had not been run since. If the table is there, look in Craft's log for the driver's message. |

Successful provisioning rows use `jit_create` (a new account was created), `update_on_login` (an
existing account matched and mapped values were applied) and `existing_unchanged` (matched, sync on
login is off, nothing changed). Seeing `existing_unchanged` when you expected fields to update means
**Update accounts on every login** is off.

**One person suddenly refused with `linking_disabled`, and nobody else.** This is the price of the
rule that protects everybody else, so it is worth knowing before it happens.

When single sign-on creates an account, it records **three** things: the Craft account, the
identity provider's issuer, and **the subject** (`NameID` in SAML, `sub` in OIDC) it was created
for. The next login is recognised only when all three match. The subject is in there because
without it the record would say "this directory created this account" and nothing more — and
anybody else in the same directory who can put this person's e-mail address in their own profile
would then be let into this person's Craft account, on a site with linking switched off.

So when a provider **changes the subject it sends for somebody** — the directory account was
deleted and recreated, the profile was migrated, or the SAML **NameID format is `transient`, which
is a new value on every single login by definition** — the record stops matching and that person is
refused. Their Craft account is fine; the *record of who owns it* is stale. What to do, in order:

1. Open the diagnostics row → **Details** and read the subject that arrived. Compare it with the
   one in the plugin's `keyway_sso_links` table for that account (`SELECT * FROM keyway_sso_links
   WHERE userId = <the Craft user id>`). Different value, same issuer = this case.
2. **Fix the cause at the provider first**: set a stable NameID format — `persistent` or
   `emailAddress` — not `transient`. Otherwise every login of every user hits this from now on.
3. Then clear the stale record: delete that one row from `keyway_sso_links`. The person's next
   login creates the account fresh only if no Craft account matches; since one does, either link it
   deliberately (**Link to existing Craft accounts**, with **Allowed e-mail domains** filled in, and
   switch it back off afterwards if that is your posture) or let them sign in once that way and
   leave the rest of the site unchanged.

**Do not** reach for **Link to existing Craft accounts** as the first move. It is the setting that
opens *every* account on the site to whatever the directory sends, and the refusal you are looking
at is one person with a changed identifier.

### 3f. Sign-in (stage `Session`)

Reached only after everything verified and the policy allowed the login.

| Code | What actually happened | What to do |
|---|---|---|
| `no_cp_access` | The account was provisioned but has no control panel permission, so signing it in would drop somebody on a page they cannot use. The missing permission is named in the message. | A just-created account gets this when the group mapping put it in no group granting control panel access. Fix the group mapping or the Craft group's permissions. |
| `auth_refused` | Craft itself refused to authenticate the account after provisioning — suspended, pending, locked, archived, or owed a password reset. This is the account's own state, not a permissions problem. | The exact Craft status is in the message; fix the account in the control panel. |
| `user_not_saved` | Craft refused to save the user element; its validation errors are in the message. | Usually a custom field validation rule, a duplicate username or a required field the mapping does not fill. A blank username is not one of them: a created account falls back to the mapped e-mail address, so `username: Username cannot be blank` means the mapping carried neither. If the message says **no validation errors were reported**, the licence limit is the likely cause: Craft refuses a new user outright when the edition is full (Solo allows 1 user, Team 5), and it reports nothing further. |
| `account_vanished` | The account this login matched no longer exists, or could not be loaded. | Deleted while the login was in flight. Ask the user to try again. |
| `session_not_started` | Craft accepted the account but would not start a session for it. | Check session storage and cookie configuration. |
| `not_allowed` | A denied decision reached the sign-in step. Defensive; not reachable in normal operation. | Report it. |
| `provisioning_incomplete` | **Notice, not a refusal.** The login succeeded, but part of what was configured could not be applied — a mapped Craft group handle that does not exist on this site, a custom field that is not in the user's field layout, or group membership that could not be written. | The person is signed in with a permission set that is **not** the one on the settings screen, and nothing else would ever say so. The message names the group handle or field. Fix the handle, then have them sign in again. |
| `decision_missing` | A login was allowed with no provisioning decision behind it and was refused. | Not reachable through configuration; report it. |

---

## 4. Configuration warnings on the settings screen

Warnings appear at the top of the plugin settings and **never block a save** — two of them describe
a safety net that has already fired, and a guard that stops you saving the configuration it just
corrected is a guard that locks you out.

**"The `oidcClientSecret` field points at environment variable `$…`, which is not set, or is set to
an empty value."** The field looks filled in — it holds `$KEYWAY_OIDC_SECRET` — but there is nothing
behind that name on the server. **The warning names the variable deliberately**, because the actual
fault is in the server environment, not on this page, and the person who has to fix it needs the
name; the field-level error alone sits somewhere the administrator may never scroll to. Until it
resolves, single sign-on stays off: an unresolved reference is treated as "no secret", which for
OIDC would silently downgrade a confidential client to a public one and for SAML would claim the
site can decrypt assertions and then fail inside OpenSSL on the first encrypted one. Set the
variable on the server, or clear the field.

**"Single sign-on is selected but the connection is not usable yet…"** The protocol is set but the
connection does not build. The SSO button stays hidden until it does — a button that leads to a
configuration error is worse than no button, because whoever clicks it is usually the person who
cannot get in. The failing fields carry their own errors further down the page.

**"These settings would have left nobody able to reach the control panel if the identity provider
failed, so password login for admins was turned back on."** The anti-lockout guard fired. Add an
emergency account if you really want SSO only.

**"Emergency password login was requested without an expiry time, so it stays off."** See section 5.

**"Emergency password login is active for another *n* minute(s)."** Informational; the switch closes
itself.

**"Existing Craft accounts may be linked to an identity from the provider."** On a site with public
registration, an account registered with somebody else's address and never verified can be linked
this way. Keep the domain allow list filled in.

**"The assertion consumer URL is not HTTPS…" / "The redirect URI is not HTTPS."** For SAML this
means the login runs without the browser binding (see `binding_not_issued`). For OIDC the login is
still bound, but the binding cookie and the authorization code travel in the clear.

**"Your identity provider can grant Craft admin status through the admin rules below."** Anybody who
can edit those groups in the directory can make themselves an admin here.

**"The signing certificate was pasted together with a private key."** The IdP signing certificate
field holds a certificate *and* a private key — two PEM blocks, or both structures in one block of
base64. This is what `openssl pkcs12 -in idp.pfx -out idp.pem` writes, and PKCS#12 (`.pfx`) is how
ADFS, Entra and `keytool` hand a certificate over, so it is an easy paste to make: the export is
opened, copied whole and pasted. **The save is allowed and sign-in works** — every reader takes the
first structure in the field and ignores the rest — which is exactly why it needs saying: nothing
else on the screen would ever mention it. What is wrong is where the key now lives. This field is
stored with the rest of the settings, so the key is in the database, in project config if settings
are written there, and in every backup of either, readable by anyone who can read those. Paste the
certificate on its own — only the `X509Certificate` element of the provider's SAML metadata belongs
here. **If the key belongs to the identity provider, treat it as exposed** and ask the provider to
replace it; a signing key that has been through a settings table and a backup rotation is no longer
private, and rotating it is the provider's job, not this plugin's. If it is the site's own SP key,
it goes in the SP private key field and nowhere else.

**Notes next to the ACS URL / Redirect URI fields** are not warnings but they catch the most common
silent failure: both protocols compare that value **character for character**. *"This reaches the
same endpoint … but is not written the same way"* (a trailing slash, letter case, a default port)
means the provider must be given the value exactly as written. *"This points at a host that this
installation does not serve"* means a response sent there will never reach the plugin.

---

## 5. Locked out of the control panel

### What this build actually does

**The password-fallback switches are enforced.** When **Single sign-on only** is on, a password
sign-in on the control panel is refused unless one of the escape hatches below applies. Precisely:

* the refusal happens **on the control panel only**. Front-end logins on your own site — members,
  customers, a headless login form — are not touched, because the setting says "control panel" and
  that is all it does;
* it applies to **password sign-ins only**. Passkeys are a separate method and are left alone;
* **the password form is still shown.** The refusal happens when you submit, not by hiding the
  fields. See "What the login screen looks like" below, which explains why;
* **already signed in?** Actions that ask you to confirm your identity with your password (an
  elevated session) still work. Craft checks that password on a different path, and this plugin
  does not touch it.

**It will not lock you out by accident, but it is not lockout-proof.** The anti-lockout guard
below refuses to leave the password door shut *on paper* — if your settings would close it, the
guard reopens the admin fallback when they are loaded. What the guard cannot check is whether the
accounts you nominated can really sign in. Leave **Admins may still use a password** on and this
does not concern you; turn it off and read
[If you really cannot get in](#if-you-really-cannot-get-in) before you do.

### What the login screen looks like

The password fields stay visible even with **Single sign-on only** on, and that is deliberate
rather than unfinished.

**The plugin never hides the password form** — there is no setting that makes it do so, and no
code in it that could. Hiding would only ever be correct when nobody at all could use a password,
and the anti-lockout guard rewrites exactly that combination when your settings are loaded, turning
the admin fallback back on. The state that would justify hiding cannot be reached, so code to hide
the form would be code that never runs.

What this means in practice: a user who may not sign in with a password sees the form, types their
details, and is refused with *"This site requires single sign-on. Use the sign-in button on this
screen."* The single sign-on button is on the same screen.

Two consequences worth knowing:

* if [`preventUserEnumeration`](https://craftcms.com/docs/5.x/reference/config/general.html#preventuserenumeration)
  is on, the refusal becomes indistinguishable from a wrong password: both the message **and** the
  `errorCode` Craft returns fall back to its generic *"Invalid username or password."* Anything
  specific would confirm the account exists, since an unknown login name never reaches this plugin
  at all. **One difference does remain, and we cannot close it from a plugin:** Craft spends a
  deliberate moment hashing a dummy password for an unknown login name, while a refusal here
  returns before any hashing, so a careful attacker timing the responses can still tell the two
  apart;
* a refused attempt is **not** counted as a failed password. It cannot push an account into Craft's
  lockout or cooldown, so trying repeatedly during an outage costs you nothing.

### What the settings mean

1. **Admins may still use a password** is on by default and is the intended fallback while SSO-only
   mode is on.
2. **Emergency accounts** — e-mail addresses or usernames, one per line, that may sign in with a
   password while SSO-only mode is on. This is the list to fill in if you want to turn the admin
   fallback off.

   **An entry only works if it names an account that exists and has a local Craft password.** Craft
   rejects an unknown login name, and an account with no password set, before this plugin is
   consulted at all — so neither a typo nor a passwordless account is a way back in, however it is
   spelled here. **Accounts created by this plugin through single sign-on have no local password**,
   which makes them the wrong choice for this list unless somebody has since set one. See
   [If you really cannot get in](#if-you-really-cannot-get-in).
3. **The anti-lockout guard.** If the combination you save would leave nobody able to get in when
   the provider breaks — SSO only, admins blocked, no emergency account — the plugin **silently
   turns password login for admins back on** and says so in a warning. It does not refuse the save,
   because these settings are also read while rendering the login page, and failing there would lock
   you out with the very guard meant to prevent it.
4. **Break glass.** **Emergency password login (break glass)** requires **Emergency login expires
   at** (a Unix timestamp) and has a hard ceiling of **24 hours**. Saving it with an expiry in the
   past, or more than 24 hours away, is a validation error you see immediately.

   **The non-obvious part, and it is deliberate:** if break glass is enabled with **no expiry at
   all** — hand-edited project config, a legacy row, a value that did not survive a deploy — the
   switch is **treated as off**, not as open forever, and the settings screen says *"Emergency
   password login was requested without an expiry time, so it stays off."* An expiry further out
   than 24 hours (for example a timestamp accidentally written in milliseconds) is treated the same
   way: closed, not honoured. An emergency switch that never closes is a permanent password door.

### If you really cannot get in

One configuration can leave nobody able to use a password. It needs a deliberate choice —
**Admins may still use a password** turned **off** — plus an **Emergency accounts** list that only
*looks* usable. The anti-lockout guard checks that the list is **not empty**; it cannot check that
the entries on it can sign in. Craft settles both of the following before this plugin is consulted
at all, so in each case the plugin never gets the chance to let anyone in:

* **the entry matches no account** — a typo, a renamed user, a deleted one;
* **the account exists but has no local Craft password.** This is the likelier trap of the two,
  because **accounts created by this plugin through single sign-on never get one**. On a site that
  has run SSO-only for a while, the obvious-looking candidates for an emergency account are exactly
  the accounts that cannot use a password. An account that is **suspended** or still **pending**
  activation is refused as well, by Craft's own status rules.

So: before you turn the admin fallback off, **sign in as an emergency account with its password to
prove it works.** Nothing else confirms it.

Two ways out, in order:

1. **Break glass, if you can still reach the settings screen** through another session.
2. **Turn the plugin off from the command line**, which needs no browser and no session:

   ```
   php craft plugin/disable keyway-sso
   ```

   A disabled plugin registers nothing, so Craft's password login returns to normal immediately.
   Your settings are kept, so you can fix the emergency list and re-enable with
   `php craft plugin/enable keyway-sso`.

The plugin does not yet check the emergency list against real accounts when you save it; until it
does, that proof is yours to make.

### What can actually cost you access today

Not the switches above — the **group and admin mapping**, but only **when the login actually writes
to the account**. That is the condition to hold on to:

> Attributes, the admin flag and group membership are written **only** for a decision of
> `jit_create` (a new account) or `update_on_login` (an existing account with **Update accounts on
> every login** switched on). With that switch **off**, the decision is `existing_unchanged` and
> **nothing is applied** — neither `Replace`, nor admin revocation, nor a single mapped field.

So the two dangerous settings are dangerous **only in combination with `Update accounts on every
login`** (or on the very first, account-creating login):

* **Sync mode `Replace`** makes the provider the only source of truth and removes Craft groups the
  user has but the mapping does not ask for. If the removed group was the one granting control panel
  access, that account is signed in with nowhere to go, or refused with `no_cp_access`.
* **Revoke admin when no rule matches** (only active while **Allow admin escalation** is on) clears
  the Craft admin flag of anybody who signs in without matching an admin rule — including the
  account that configured the plugin.

The trap is the reverse of the obvious one: testing `Replace` with sync on login switched off shows
a login that changes nothing, which is **not** evidence that the setting is safe. Check the
diagnostics row first — if it says `existing_unchanged`, the mapping was never applied.
* A **just-created account** whose mapped groups grant no control panel permission is refused with
  `no_cp_access` rather than dropped on a page it cannot use.

Recovery is ordinary Craft: sign in with a password (see above), from another administrator account
if the first one lost its admin flag, and fix the mapping before signing in over single sign-on
again. Test `Replace` and admin revocation on a throwaway account first.

## 6. Known limits, and things that are not bugs

* **The SAML metadata endpoint answers 404** when the protocol is not SAML, or when the SP entity ID
  or the ACS URL is empty or not an absolute URL. That is fail-closed on purpose: a metadata
  document naming a blank entity ID would be **accepted** by the identity provider and would
  configure it against a sign-in that can never validate.
  Filling those two fields in is not enough on its own, though: the settings screen is validated as
  a whole, so a SAML configuration saves only once the identity provider's values are there too
  (**IdP entity ID**, **IdP signing certificate**, **IdP SSO URL**), and a rejected save stores
  nothing. The document therefore appears after the first *complete* save — it is a way to hand a
  finished configuration to the provider, not a way to start one. See the ordering in
  [keycloak.md](keycloak.md) or [okta.md](okta.md).
* **The password fallback refuses a sign-in; it does not hide the form.** `Single sign-on only`
  blocks a password sign-in on the control panel when you submit it, and leaves the password
  fields on screen — the anti-lockout guard means no saveable configuration would justify hiding
  them. Front-end logins, passkeys and the "confirm your password" elevated-session check are not
  affected. See section 5.
* **Single Logout works in one direction only, and for SAML only.** The plugin answers an
  IdP-initiated `LogoutRequest` on `/actions/keyway-sso/sso/slo`, **HTTP-Redirect binding only**,
  once *IdP single logout URL* and an *SP private key* are both set; until then the endpoint
  refuses every message and the metadata document deliberately advertises no
  `SingleLogoutService` — advertising one would make every provider that reads the document send
  logout requests to an address that answers nothing. A request is honoured **only when its
  subject matches the session in the browser that carried it**; a mismatch ends nothing and is
  answered `UnknownPrincipal`, which is also what a browser with no session gets.
  **Signing out of Craft does not sign anybody out of the identity provider** — SP-initiated
  logout is not implemented. **OIDC has no logout support at all**, in either direction.
* **The SP certificate is not published in the metadata.** There is no settings field for an SP
  certificate (only an SP **private key**, for decrypting assertions), and a metadata
  `KeyDescriptor` can only carry a certificate. A site using **encrypted assertions** must therefore
  hand its certificate to the identity provider **out of band**.
* **An IdP certificate fingerprint is not accepted in place of the certificate.** A fingerprint
  proves which certificate the message carried, not which one you trust. Paste the full X.509
  certificate (PEM or base64).
* **Clock skew has a ceiling of 120 seconds**, for both SAML and OIDC, and **the time checks
  themselves cannot be switched off**. An id token is additionally refused once it is older than
  **300 seconds**, whatever the skew setting, and a login state expires after **5 minutes**. If
  logins fail only for some users, compare clocks before touching anything else.
* **SAML authentication requests are not signed.** There is no `SigAlg` and no `Signature` on the
  redirect, and the metadata says `AuthnRequestsSigned="false"`. A provider configured to require
  signed authentication requests will refuse the login.
* **The subject must be stable, and the plugin does not inspect the NameID *format*.** Accounts
  created by single sign-on are recognised on later logins by (account, issuer, **subject**), so a
  provider that re-issues the subject for the same person locks them out of their own account until
  an administrator clears the stale record (see section 3e). Configure a **stable** NameID format at
  the provider — `persistent` or `emailAddress`. **`transient` is not usable with this plugin**: it
  is a fresh value on every login by definition, so every second login of every user is refused with
  `linking_disabled`. Nothing here rejects a transient NameID at the door — the plugin never reads
  the format attribute, and our metadata advertises `unspecified` — so this is a configuration rule,
  not a check you can fail.
* **A subject longer than 255 bytes gets no link at all.** The column that remembers it holds 255
  bytes, and an over-long value is refused rather than cut down — two people whose subjects share
  their first 255 bytes would otherwise become one account. The visible effect is the same as a
  re-issued subject: the account is created on the first login and refused with `linking_disabled`
  on every one after it. Rare, and not something we have measured in the wild - the `persistent` formats issued by Okta, Entra ID and Keycloak are all far shorter than this - but possible with an unusually long identifier; if you see it,
  configure the provider to send a shorter stable identifier (`emailAddress` is the usual answer).
* **IdP-initiated sign-on is not supported.** A response that does not match a login this site
  started is refused (`unsolicited_response`). Users must start at the Craft login screen.
* **One connection at a time.** The protocol dropdown selects a single connection; there is no
  multi-provider mode.
* **Signed userinfo responses (`application/jwt`) are refused.** Verifying them is a separate path
  that does not exist yet, and parsing one unverified would be exactly the shortcut the design
  forbids.
* **Group matching has no regular expressions** — exact, prefix and suffix only. An
  administrator-supplied regex is an attack surface, and a pattern like `.*` silently matching every
  directory group into an admin rule is the failure that matters.
* **Diagnostics retention is not configurable** (30 days / 2 000 rows / hourly sweep), and the screen
  is **admin-only** — control panel access alone is not enough.
* **The `Groups` stage is a label with no writer.** The stage exists in the code and the screen
  renders a `Groups` label for it, but **no code path records a row with that stage**, so filtering
  or waiting for one is pointless. Group results are reported inside the `Provisioning` row, under
  **Details → Mapped to**.
* **A diagnostics row is not written for every refusal.** `not_configured` and
  `connection_cannot_start` happen before there is a connection to attribute a row to, so they show
  up only as "the button is missing" or a 403 page. The settings screen is the diagnosis for those.
