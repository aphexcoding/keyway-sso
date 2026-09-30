# Okta (SAML 2.0)

This guide covers **SAML 2.0 with Okta**, and that path was **run end to end against a live
Okta tenant on 17 September 2026** (Integrator Free Plan, fresh Craft 5.11 install on default
settings): the first sign-in created the account just in time with the mapped group, and the
second one updated it and reached the control panel.
**OpenID Connect with Okta has not been checked** — the OIDC side of the plugin is written to the
specification and has been run end to end against a different provider (Keycloak) only, so if you
go that way, treat it as
unverified and test it carefully before anyone depends on it.

Okta's admin console changes wording from time to time. Where a name below does not match what
you see, look for the setting that does the same job.

---

## What you will need

* A Craft 5 site where you can reach **Settings → Plugins → Keyway SSO**, and a Craft account with
  admin rights on it.
* An Okta org and an administrator account allowed to create application integrations and assign
  people to them.
* One Okta test user with an e-mail address, assigned to the app once it exists. An unassigned
  user is rejected by Okta before Craft is involved, and nothing appears in the plugin's
  diagnostics.

---

## Step 1 — Turn the plugin on and copy this site's values

1. Open **Settings → Plugins → Keyway SSO** on the Craft site.
2. Set **Protocol** to `SAML 2.0`.
3. Optionally change **Login button label** (default: `Sign in with SSO`, at most 120 characters).
4. Note down the two values Okta will need. **Both are readable on this screen before you save
   anything**, because the plugin builds them from its own registered routes and this site's base
   URL:
   * **This site's URL** (the copy field above **SP entity ID**) — this site's base URL without a
     trailing slash, the usual choice for the SP entity ID. An entity ID is an identifier, not an
     address; any stable string works as long as both sides carry exactly the same one.
   * **ACS URL this site answers on** — that is `<BASE>/actions/keyway-sso/sso/acs`, or the same
     address written as `<BASE>/index.php?p=actions/keyway-sso/sso/acs` on an installation with
     Craft's default `omitScriptNameInUrls = false`. For SAML both forms are fine; Okta accepts an
     ACS URL with a query string. Copy whatever the screen shows — it is what this site really
     answers on.
5. You may type those two values into **SP entity ID** and **ACS URL** now, but **do not expect the
   save to go through yet, and do not expect the metadata file**. With **Protocol** set to
   `SAML 2.0`, the settings screen is validated as a whole: the save is rejected until **IdP entity
   ID**, **IdP signing certificate** and **IdP SSO URL** are filled in too, and a rejected save
   stores nothing. Those three values come from Okta, so go and create the application first
   (Step 2), come back and save the complete configuration (Step 3) — and only then, if you want
   it, use **Download metadata** / **Metadata URL**. Until that save, the button is inert and the
   metadata address answers **404** by design: a metadata file naming a blank entity ID would
   configure Okta against a login that can never validate.

---

## Step 2 — Create the application in Okta

In the Okta admin console, create a new app integration of the **SAML 2.0** kind and give it a
name. Then work through its SAML settings:

| Okta setting | Value |
|---|---|
| **Single sign-on URL** | the **ACS URL this site answers on** value from Step 1 |
| *Use this for Recipient URL and Destination URL* | **leave it checked** (see the warning below) |
| **Audience URI (SP Entity ID)** | exactly what you put in **SP entity ID** — this site's URL without a trailing slash |
| **Default RelayState** | leave empty |
| **Name ID format** | `EmailAddress` — **and not `Unspecified` or `Transient`**, see below |
| **Application username** | `Email` |

> **The Name ID format has to be a stable one.** Accounts this plugin creates are recognised on
> later logins by (account, issuer, **Name ID**). A format that changes the value — `Transient` is a
> new value on *every* login by definition — means the second login of every user is refused with
> `linking_disabled`, and a person whose Name ID changes for any other reason (their Okta account
> recreated, their username migrated) needs an administrator to clear the stale record. Use
> `EmailAddress` or `Persistent`. The plugin does not read the format attribute, so there is no
> error message pointing at this: see
> [troubleshooting → one person suddenly refused](troubleshooting.md#3e-provisioning-stage-provisioning-outcome-refused).

> **The Recipient and Destination checkbox is load-bearing.** The plugin compares the response's
> `Destination` attribute (when present) and the assertion's `SubjectConfirmationData/@Recipient`
> against the configured **ACS URL**, exactly, with no substring or prefix leniency and no way to
> relax it. If those three addresses are not the same string, the login fails with
> `destination_mismatch` or `confirmation_invalid`.

Paste the two addresses by hand here and then compare them character for character — that is what
both sides do with them. *(If your Okta edition offers an import of service-provider metadata, our
metadata document carries the same entity ID and ACS URL and can replace the retyping — we have
not tested that import — but it
exists only once the complete configuration has been saved in Step 3, so that route means
finishing Step 3 first and re-checking this application afterwards.)*

Note what our metadata document does **not** carry, so nothing surprises you if you do use it: no
`KeyDescriptor` (the plugin has no field for an SP certificate), and a `NameIDFormat` of
`unspecified`. Set `EmailAddress` in Okta yourself, as in the table above.

**Attribute statements.** Add three, with these names exactly — the plugin matches on the
attribute's `Name`:

| Name | Value |
|---|---|
| `email` | `user.email` |
| `firstName` | `user.firstName` |
| `lastName` | `user.lastName` |

**Group attribute statement.** If you want group mapping, add one named `groups` with the filter
**Matches regex** and the expression `.*`. That sends every Okta group the user belongs to; the
narrowing happens in Craft, in the **Groups** table (Step 4).

**Signing.** The assertion must be **signed**, with **RSA-SHA256**. The plugin requires a signed
assertion unconditionally; there is no setting to accept an unsigned one. Leave assertion
encryption off unless you have a reason for it — see the last section.

**Assign somebody.** Assign your test user (or a group containing them) to the application.

**Then collect three values from Okta** — they are on the app's sign-on settings, usually behind a
link with the SAML setup instructions:

| Craft field | Okta value |
|---|---|
| **IdP SSO URL** | *Identity Provider Single Sign-On URL* |
| **IdP entity ID** | *Identity Provider Issuer* |
| **IdP signing certificate** | the *X.509 Certificate*, in PEM form (the `-----BEGIN CERTIFICATE-----` block) |

---

## Step 3 — Paste Okta's values back into the plugin

Back on **Settings → Plugins → Keyway SSO**, in the **SAML 2.0** section:

| Field on the settings screen | What to put in it |
|---|---|
| **IdP entity ID** | Okta's *Identity Provider Issuer*. Compared byte for byte against the assertion issuer. |
| **IdP signing certificate** | Okta's certificate, PEM or bare base64. A fingerprint is rejected: it proves which certificate the message carried, not which one you trust. |
| **IdP SSO URL** | Okta's *Identity Provider Single Sign-On URL*. **Required** — without it the login cannot start at all, because there is nowhere to send the browser. |
| **SP entity ID** | The same string you gave Okta as *Audience URI*. |
| **ACS URL** | The **ACS URL this site answers on** value, unchanged. |
| **SP private key** | Needed for encrypted assertions, and for Single Logout — as an environment reference (`$KEYWAY_SP_KEY`). Leave it empty unless you turned on encrypted assertions in Okta; Single Logout is not a reason to fill it in here (see *Single Logout with Okta* below). |
| **Clock skew (seconds)** | Default `60`, maximum `120`. The time checks themselves cannot be turned off. |

Save and read the screen. Under **ACS URL** the plugin comments on what you typed: no message
means it is identical to the address this site answers on; anything else describes exactly how it
differs — written differently but equivalent, the control-panel alias, another site of this
installation, a host this installation does not serve, or not an absolute URL at all. A banner at
the top saying the connection *"is not usable yet"* means the login screen still offers password
login only.

---

## Step 4 — Map attributes and groups

**Attributes.** An empty **Attributes** table does not mean "map nothing" — it means "use the
shipped defaults", and the defaults are exactly what Step 2 configures in Okta:

| IdP attribute | User field | Required |
|---|---|---|
| `email` | `email` | yes |
| `firstName` | `firstName` | no |
| `lastName` | `lastName` | no |

So with the attribute statements above, you can leave the table alone. Add rows only when you need
something else: targets may be `email`, `username`, `firstName`, `lastName`, `fullName` or
`field:<handle>` for a custom field on the user field layout, and the two special sources
`@nameId` and `@issuer` read the assertion itself. A `username` row is optional: when a new
account is created and the mapping carries no username, the e-mail address becomes the Craft
username. Craft accepts an address there, and on Craft's default configuration
(`useEmailAsUsername` off) an account with no username at all cannot be saved. **Multiple values**
picks `First`, `Last` or `Join` when an attribute arrives more than once; **Transform** can force
lower or upper case; **Required** makes a missing value fail the login instead of being skipped.

**Groups.** **Source attributes** defaults to `groups` — the name used by the group attribute
statement in Step 2. Each row of the **Groups** table maps an Okta group to a **Craft group
handle** with `Exact`, `Prefix` or `Suffix` matching; there are no regular expressions, on
purpose. A Craft group handle starts with a letter and contains letters, digits or underscores
(64 characters at most). Prefix and suffix patterns must be at least two characters long, and an
empty pattern is refused — it would match everything Okta sends. Matching ignores case unless
**Case-sensitive matching** is on.

* **Default group** — a handle everybody joins; empty for none.
* **Sync mode** — `Append` (default) keeps memberships the account already has; `Replace` makes
  Okta the only source of truth, which also means that a login mapping to nothing empties the
  account's group list on every login. **Deny login when no group matches** is the guard for that.
* **Allow admin escalation** — **off by default, and worth leaving off.** With it on, the
  **Admin rules** table can grant Craft admin status, which means whoever administers your Okta
  groups can grant admin here. Turning it on also reveals **Revoke admin when no rule matches**,
  which removes admin from people who stop matching (only admin granted through these rules).

**Provisioning.** **Create accounts on first login** and **Update accounts on every login** are on
by default; **Match existing accounts by** is `E-mail`, matching the `EmailAddress` / `Email`
choices in Step 2. **Link to existing Craft accounts** is **off**, so a Craft account that already
exists with the same address is not adopted until you say so — and **Linking may include admin
accounts** is a separate switch, because "let the team sign in with SSO" and "let Okta hand out
the owner's account" are not the same sentence. When you enable linking, fill in **Allowed e-mail
domains**: one per line, `example.com` exact, `.example.com` sub-domains only, empty means any
domain.

---

## Step 5 — Keep a way back in

* **Keep at least one Craft admin whose password you know**, and confirm that password still works
  before you rely on it. The switches below decide who may keep using one; leaving **Admins may
  still use a password** on is what keeps that answer safe.
* **`Single sign-on only` refuses a password sign-in on the control panel.** The password fields
  stay on screen and the refusal happens when you submit, with the message *"This site requires
  single sign-on. Use the sign-in button on this screen."* Front-end logins on your own site,
  passkeys, and the "confirm your password" prompt for an already-signed-in admin are all
  untouched. Detail:
  [troubleshooting → Locked out of the control panel](troubleshooting.md#5-locked-out-of-the-control-panel).
* **Admins may still use a password** is on by default. If your settings would leave nobody able
  to reach the control panel when Okta is unreachable, the plugin turns it back on as you save and
  says so in a warning. It checks the settings, not the accounts — see the next point.
* **Emergency accounts** — e-mail addresses or usernames, one per line: the accounts that keep
  password access while **Single sign-on only** is on. An entry only counts if it names an existing
  account **with a local Craft password** — accounts this plugin created from Okta logins have
  none — so sign in as one to prove it works before turning the admin fallback off. Detail:
  [troubleshooting → If you really cannot get in](troubleshooting.md#if-you-really-cannot-get-in).
* **Emergency password login (break glass)** plus **Emergency login expires at** — a Unix
  timestamp, required when the switch is on, in the future, and **at most 24 hours ahead**;
  all three are enforced when you save, and a switch turned on without an expiry is treated as
  off rather than as open. Produce the number with something like `date -u -d '+8 hours' +%s`.
  While the window is open, the settings screen counts down the minutes left.

---

## Step 6 — Test the login and read the diagnostics

1. Open the Craft login screen in a private window. The SSO button appears only when the
   configuration is usable; if it is missing, the warnings on the settings screen say why.
2. Sign in as the Okta user you assigned in Step 2.
3. Open **Open sign-in diagnostics** at the bottom of the settings screen — after a success as
   well as after a failure. Each attempt is a row: time, outcome (`Signed in`, `Refused`, `Error`,
   `Notice`), protocol, stage (`Protocol`, `Login state`, `Attributes`, `Groups`, `Provisioning`,
   `Session`), reason code, subject, issuer, and a **Details** panel with the attributes received,
   what they mapped to, and the decision taken. You can filter by outcome, by protocol and by a
   search term.
4. Reason codes worth recognising on a first attempt with Okta. When Okta's response itself is
   refused, the **Reason** column reads `identity_rejected` and the specific code stands in round
   brackets at the end of the message under **Details**:
   * `destination_mismatch`, `confirmation_invalid` — the Recipient/Destination addresses do not
     equal **ACS URL** exactly (Step 2, the checkbox).
   * `audience_mismatch` — Okta's *Audience URI* is not what **SP entity ID** holds.
   * `issuer_mismatch` — **IdP entity ID** is not Okta's *Identity Provider Issuer*.
   * `signature_invalid`, `signature_coverage` — the wrong certificate in **IdP signing
     certificate**, or the assertion is not signed the way Step 2 requires.
   * `unsolicited_response` — the response cannot be matched to a login this site started (see the
     limits below).
   * `no_group_match`, `domain_not_allowed`, `linking_disabled`, `jit_disabled` — the login was
     understood and then refused by your own policy in Step 4.
   * [troubleshooting.md](troubleshooting.md) works through them.
5. If the panel reports that the diagnostics store is unavailable, the plugin's migration has not
   run: `php craft up`.

A login has five minutes between pressing the SSO button and the assertion coming back. After
that the single-use login state has expired and the attempt is refused — a stale browser tab, not
a session length.

---

## Single Logout with Okta

**Plan for single sign-on, not for single logout. With Okta as your only provider, Single Logout
will not work in practice** — and the reason is structural on both sides, so there is no setting
that rescues it.

* **This plugin only answers.** It verifies a signed SAML `LogoutRequest` that the identity
  provider sends to `<BASE>/actions/keyway-sso/sso/slo` and ends the Craft session that request
  names. It never *sends* one: SP-initiated logout is not implemented.
* **Okta does not send one after an ordinary sign-out from Okta.** Okta issues a `LogoutRequest`
  to an application only as the continuation of a logout that began at *another* SAML application
  — an SP-initiated logout addressed to Okta — and turning Single Logout on for an Okta
  application requires the service provider to be able to send Okta a **signed** logout request in
  the first place. That is exactly the half this plugin does not have. Okta describes both points in
  [Single Logout](https://help.okta.com/oie/en-us/content/topics/apps/apps_single_logout.htm) and
  [Configure SAML Single Logout](https://developer.okta.com/docs/guides/single-logout/saml2/main/)
  (read 17 September 2026).
* **And configuration could not bridge it.** There is no settings field for an SP **certificate**
  here — only an SP private key — so a provider that has to verify a signature of ours has no way
  of being handed the matching certificate except out of band; the metadata document carries no key
  material either. See
  [troubleshooting → Known limits](troubleshooting.md#6-known-limits-and-things-that-are-not-bugs).

**What happens instead, day to day:**

* Signing out **of Okta** leaves the Craft session running. It lasts until the person signs out in
  Craft, or until Craft's own session expires (`userSessionDuration` in Craft's general config —
  not something this plugin touches).
* Signing out **of Craft** ends the Craft session and nothing else. Okta still has that person
  signed in, so pressing the SSO button again lets them straight back in without asking for
  anything.
* The two sessions are independent, so on a shared machine the instruction to give people is
  **sign out twice**: once in Craft, once in Okta.

**Leave the logout fields empty on an Okta installation.** With **IdP single logout URL** (and an
**SP private key**) unset, the `sso/slo` endpoint refuses every message and the metadata document
advertises no `SingleLogoutService`. That is the correct state here, not a missing step: an
advertised endpoint that answers nothing looks to the provider like a broken service. The canonical
description of the mechanism is
[troubleshooting → Known limits](troubleshooting.md#6-known-limits-and-things-that-are-not-bugs).

**Not verified against a live Okta tenant.** The section above follows Okta's own documentation and
this plugin's code; no Okta `LogoutRequest` has been observed arriving at a Craft install. The one
provider Single Logout has been exercised against end to end is Keycloak — see
[keycloak.md](keycloak.md).

---

## Known limits with Okta

* **Single Logout does not work with Okta alone.** The plugin answers `LogoutRequest`s and never
  sends one; Okta sends one only as the continuation of a logout begun at another SAML
  application. Signing out on either side leaves the other side signed in — see *Single Logout
  with Okta* above.
* **The login must start on the Craft side.** The plugin requires its own `RelayState` and a
  matching `InResponseTo`, so an assertion that belongs to no login of ours is refused as
  unsolicited. In practice: the Okta dashboard tile for this app will not sign anybody in. Send
  people to the Craft login screen. (This is also why **Default RelayState** must stay empty.)
* **Authentication requests are sent unsigned.** If the application is configured to require a
  signed request, every login fails at Okta.
* **OpenID Connect with Okta is unverified.** The fields exist and the protocol is implemented,
  but this combination has not been tested; the ACS-based SAML path above is the supported one.
* **Encrypted assertions** are implemented in the plugin (**SP private key**) but **unverified**
  — not covered by an automated test and not run against a live Okta tenant. There is also no field
  for an SP *certificate*, so the metadata document contains no key material. If you turn on
  assertion encryption in Okta, the certificate matching your private key has to get there by
  another route.
* **`NameIDFormat` in our metadata is `unspecified`.** The plugin does not inspect the format
  attribute of the NameID, so this is not a check you can fail — but it does mean the metadata
  file will not set `EmailAddress` for you, and **the value still has to be stable**: the Name ID
  is part of how a returning user is recognised (Step 2).
* **The password fallback refuses a sign-in rather than hiding the password form**, and only on
  the control panel (Step 5).

This list covers what is specific to Okta. The complete, canonical list of this release's limits —
including those that apply to every provider — is
[troubleshooting → Known limits](troubleshooting.md#6-known-limits-and-things-that-are-not-bugs).
Read it once before you go live; this page is not the whole picture.
