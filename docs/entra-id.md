# Microsoft Entra ID (OpenID Connect)

> ⚠ **Not verified against a live tenant.**
> This guide was written from Microsoft's published documentation and from the measured behaviour
> of this plugin's own OIDC reader. **Nobody has run it end to end against a real Entra ID
> tenant.** Everything stated about *this plugin* is taken from its source code and is exact.
> Everything stated about *the Microsoft portal* — screen names, section names, button labels — is
> the part that may be wrong or out of date, and it is marked **[portal]** wherever it appears.
> Where a portal detail could not be pinned down, the step says **what you need to achieve** rather
> than which button to click.
>
> The plugin's OIDC layer has been run end to end against Keycloak only (30 September 2026 — see
> [keycloak.md](keycloak.md)); that says nothing about Entra ID's own behaviour. If you want a
> provider this project has actually driven, use Keycloak, or SAML with [Okta](okta.md).

Related pages: [overview](README.md) · [Keycloak](keycloak.md) · [Okta](okta.md) ·
[troubleshooting](troubleshooting.md).

---

## What you will need

* A Craft 5 site served over **HTTPS**. The plugin refuses an OIDC redirect URI that is not
  `https`, with no loopback exception and no setting to relax it.
* An administrator account in Craft that you can still sign in to with a password.
* Enough rights in the Entra tenant to register an application and to grant its permissions.
* **A single-tenant issuer.** The plugin compares the issuer byte for byte in two places — against
  the `issuer` field of the discovery document, and against the `iss` claim of every id token — so
  a multi-tenant endpoint whose discovery document returns a *templated* issuer (one containing a
  `{tenantid}`-style placeholder rather than a literal value) can never match. Use your tenant's own
  issuer. See step 3 for how to read the real value instead of guessing it.
* About 15 minutes, and a second browser (or a private window) so that you never lock yourself out
  of the session you are configuring from.

---

## Step 1 — Turn the plugin on and copy this site's values

1. In Craft: **Settings → Plugins → Keyway SSO**.
2. Set **Protocol** to **OpenID Connect**. The screen now shows the **OpenID Connect** section.
3. Do not fill in the provider fields yet. First copy the read-only value from **Redirect URI this
   site answers on** — this is the address you will register at Entra. It deliberately carries no
   control panel prefix: that prefix can be renamed at any time, and a redirect URI the provider no
   longer recognises stops every login.
4. **Check the shape of that address before you register it.** If it contains `index.php?p=`, this
   site generates URLs with the script name in them. Turn on Craft's `omitScriptNameInUrls` and
   re-read the value. *(The plugin's own settings screen flags this because some providers refuse a
   redirect URI containing a query string — Google is the one named there. Whether Entra ID accepts
   such a URI is **not verified**; register the clean form and avoid the question.)*
5. Leave this tab open. You will paste values back into it in step 3.

Nothing is saved yet, and while the configuration is incomplete the SSO button stays off the login
screen — that is normal, not an error.

---

## Step 2 — Register the application at Entra ID

Do this in the Microsoft Entra admin centre or the Azure portal. **[portal]** The path has changed
several times; at the time of writing it is broadly *Identity → Applications → App registrations →
New registration*, but navigate by what you are trying to achieve rather than by these names.

**What you need to end up with:**

1. **An app registration in your tenant**, restricted to accounts in **this organizational
   directory only** (single tenant). See the issuer requirement in *What you will need*.
2. **A redirect URI of platform type "Web"**, set to exactly the address you copied in step 1 —
   character for character, including the scheme, any trailing element and letter case.

   **Do not enable the implicit grant / hybrid options** (id tokens or access tokens returned
   directly to the browser), and leave the response coming back as a **redirect with a query
   string**. This plugin uses the authorization code flow with PKCE and its callback reads query
   parameters only.

   **Know the symptom, because it is not what you would expect.** A response POSTed back
   (`response_mode=form_post`) does not reach the plugin at all: CSRF validation is switched off
   only for the SAML assertion endpoint, never for the OIDC callback, so Craft rejects the POST
   before the plugin's callback action runs. The administrator gets an HTTP **400 "Unable to verify
   your data submission."** and **no diagnostics row is written** — looking for one is a dead end.
   If you see that 400 after signing in at Microsoft, the response mode is the thing to check.
3. **A client secret**, unless you deliberately want a public client.

   The plugin accepts both: a secret makes it a confidential client, and an empty **Client secret**
   field makes it a public one. **PKCE (`S256`) is mandatory in both cases** — it is a constant in
   the code, not a setting, and `plain` is neither implemented nor reachable. For a server-side
   application a secret is the normal choice. **[portal]** Secrets are created under the
   registration's *Certificates & secrets*; copy the **value** immediately, it is shown once.
4. **The delegated permissions matching the scopes you will request**: at minimum `openid`,
   `profile` and `email`. **[portal]** Add them under the registration's API permissions for
   Microsoft Graph, and grant admin consent if your tenant requires it.

   This matters more than it looks: the plugin's default attribute mapping **requires** an `email`
   value, and an id token issued without the `email` scope (or for an account that has no mail
   attribute) will fail the login with `attributes_rejected`.
5. **Group claims, if you intend to map groups.** **[portal]** Group claims are configured on the
   registration's token configuration / optional claims. Read step 4 first — the format you
   choose there decides whether your mapping table contains readable names or GUIDs.

**What you do not need to configure:** signing algorithms (the plugin accepts `RS256` and `ES256`
only, and Entra's published id token signing algorithm is within that set), a PKCE method
(`S256` always), or a logout URL — **the OIDC side of this plugin has no logout support**
(see *Known limits with Entra ID*).

---

## Step 3 — Paste Entra ID's values back into the plugin

Back on the Keyway SSO settings screen, **OpenID Connect** section:

**Issuer.** Do not type this from memory and do not copy it out of a blog post. Fetch your tenant's
OpenID configuration document and copy the value of its `issuer` field **verbatim**:

```
curl -s https://login.microsoftonline.com/<your-tenant-id>/v2.0/.well-known/openid-configuration \
  | grep -o '"issuer":"[^"]*"'
```

Then paste that exact string into **Issuer**. Why this ceremony: the plugin appends
`/.well-known/openid-configuration` to whatever you enter, fetches that document, and refuses to go
any further unless the document's own `issuer` equals your setting **byte for byte** — no
trailing-slash forgiveness, no case folding. The same string is then compared against the `iss`
claim of every id token. A value that differs by one character fails with `issuer_mismatch`, and
the message on the diagnostics screen quotes what the provider actually sent, which is the fastest
way to fix it.

Run that same `curl` from **the web server**, not only from your laptop: if the server cannot reach
Microsoft (proxy, firewall, TLS trust store), every login fails at `start_failed` /
`discovery_failed` before the user ever sees Microsoft's page.

**Client ID.** The application (client) ID of the registration. The plugin requires it to appear in
the id token's `aud`; when a token carries several audiences it additionally requires `azp` to name
this client.

**Client secret.** Paste the secret — but store it as an **environment variable**, not as a literal.
The field offers environment variables for exactly this reason: the value then stays out of project
config and out of your git history. Put `KEYWAY_OIDC_SECRET=…` in the server's environment and write
`$KEYWAY_OIDC_SECRET` in the field.

> If the variable is missing or empty on the server, the settings screen says so **by name** at the
> top of the page and single sign-on stays off. It is not treated as "no secret", because that would
> silently downgrade a confidential client to a public one. Leave the field **empty** only if you
> genuinely registered a public client.

**Redirect URI.** Paste the address from step 1 — the same characters you registered at Entra. The
screen compares what you typed against what this site actually answers on and comments underneath if
they reach the same endpoint but are written differently (trailing slash, letter case, default
port). Take that comment seriously: both sides compare this value character for character.

**Scopes.** One per line. The shipped default is `openid`, `profile`, `email`. **`openid` is added
automatically** whether you list it or not — without it the provider would run a plain OAuth 2.0
flow and return no id token at all, which would leave userinfo as the only source of identity, and
this plugin will not accept that. Clearing the box entirely restores the three defaults. Scopes
containing a space are dropped silently (a space would split one scope into two in the query
string).

**Fetch userinfo.** Off by default. Turn it on only if a claim you need is missing from the id token.
When it is on, the plugin calls the userinfo endpoint with the access token **after** the id token
has verified, and:

* the userinfo `sub` must equal the id token's `sub`, or the login is refused with
  `subject_mismatch`;
* **id token claims win** on conflict — userinfo can only add claims that are not already there;
* if the provider advertises no userinfo endpoint, or the token response carried no access token,
  the login fails rather than silently continuing;
* a **signed** userinfo response (`application/jwt`) is refused outright — that verification path
  does not exist in this plugin yet.

**Clock skew (seconds).** Default 60, maximum **120**. The time checks cannot be turned off. An id
token is also refused once it is more than 300 seconds old, whatever this is set to.

Save. If the configuration is usable, the warning about an unusable connection disappears and the
SSO button appears on the control panel login screen.

---

## Step 4 — Map attributes and groups

**Attributes — do not leave the table empty here.** With no rows, the plugin falls back to its
shipped defaults, whose **source** names are:

| IdP attribute | User field | Required |
|---|---|---|
| `email` | `email` | yes |
| `firstName` | `firstName` | no |
| `lastName` | `lastName` | no |

**That default does not fit OpenID Connect**, because the standard OIDC claims — the ones Entra ID
issues — are `given_name` and `family_name`. `firstName` and `lastName` are not required, so the
failure is **quiet**: the login succeeds, the diagnostics row is a green success, nothing warns you,
and accounts are simply created with an empty first and last name. It is not completely invisible,
though — open that row's **Details → Mapped to** and look at `skippedSources`. A rule whose source
attribute never arrived is listed there by name, unmasked, so `["firstName","lastName"]` under an
otherwise successful login is exactly this problem. For Entra ID fill the table in explicitly:

| IdP attribute | User field |
|---|---|
| `email` | `email` (switch **Required** on) |
| `given_name` | `firstName` |
| `family_name` | `lastName` |

Targets may be `email`, `username`, `firstName`, `lastName`, `fullName`, or `field:<handle>` for a
custom field on the user's field layout. Nothing else is writable. A `username` row is optional:
when a new account is created and the mapping carries no username, the e-mail address becomes the
Craft username. Craft accepts an address there, and on Craft's default configuration
(`useEmailAsUsername` off) an account with no username at all cannot be saved.

Confirm the claim names against your own tenant rather than against this page: after the first
attempt, the failing or succeeding row's **Details → Attributes received** lists exactly what
arrived.

If the first login fails with `attributes_rejected`, open the failing row's **Details → Attributes
received** on the diagnostics screen: that list is the ground truth about what your tenant actually
sent. Point the rule at a claim that is there, or clear its **Required** switch. A value mapped to
`email` must be a valid address — mapping a claim that holds a UPN works only when that UPN really
is an address.

**Groups — read this before you build the table.** Microsoft's group claim commonly carries **group
object IDs (GUIDs), not group names**. This plugin does not resolve them: it matches the strings it
receives, and nothing more. Consequences:

* Your rules under **Groups** will contain patterns such as
  `9a8b7c6d-1234-4321-abcd-0123456789ab` in the **IdP group** column, mapped to a Craft group
  handle in the next column.
* **Prefix** and **Suffix** matching is useless against GUIDs — use **Exact**.
* The table becomes unreadable to anyone who did not build it. Keep a note somewhere of which GUID
  is which group.
* The same applies to **Admin rules**, which is worse: a wrong GUID there grants Craft admin to the
  wrong people. Note that **Allow admin escalation** is off by default, and while it is off the
  admin rules do nothing.

**[portal]** Entra can be configured to emit group names instead of object IDs for groups
synchronised from on-premises Active Directory (sAMAccountName / on-premises group name). If your
tenant supports it for your groups, it makes the mapping table far easier to maintain. **Whether
that applies to your directory is not something this guide can verify — check what actually arrives**
rather than trusting either format: the diagnostics screen shows group values **in full, unmasked**,
under **Details → Mapped to → `matchedIdpGroups` / `unmatchedIdpGroups`**.

**Source attributes.** The plugin reads group membership from the attributes listed under **Source
attributes**, one per line; the shipped default is `groups`, which is the name Entra uses. If your
tenant emits the claim under a different name, add it here.

Also on this screen: **Sync mode** (`Append` keeps groups the user already has; `Replace` makes the
provider the only source of truth), **Default group**, and **Deny login when no group matches** —
note that the default group deliberately does **not** satisfy that check.

---

## Step 5 — Keep a way back in

Before you test, know where your way back in is.

**With Single sign-on only off — the default — a broken Entra configuration cannot lock you out of
the control panel.** Craft's password login is untouched by the plugin: sign in with a password and
fix it.

With it on, a password sign-in on the control panel is refused unless an escape hatch applies. The
anti-lockout guard will not let you *save* settings that close every hatch — but it checks the
settings, not the accounts, so an **Emergency accounts** entry that names no real account, or one
with no local Craft password (**which is every account this plugin creates**), is not a way back
in. Keeping **Admins may still use a password** on avoids the whole question. Read
[troubleshooting → If you really cannot get in](troubleshooting.md#if-you-really-cannot-get-in)
before you turn it off.

The password fields stay on screen either way; the refusal happens on submit. Front-end logins,
passkeys and the "confirm your password" prompt are not affected.

Two things *can* cost you access — but **only on a login that writes to the account**: a
first-time `jit_create`, or an `update_on_login` with **Update accounts on every login** switched
on. With that switch off the decision is `existing_unchanged` and neither of them is applied at all,
so a test that "changed nothing" proves nothing:

* **Sync mode `Replace`**, which removes Craft groups the mapping does not ask for — including, if
  you are not careful, the group that grants control panel access;
* **Revoke admin when no rule matches** (active only while **Allow admin escalation** is on), which
  clears the admin flag of anybody who signs in without matching an admin rule.

Test both on a throwaway account before applying them to your own. Keep a second administrator
account you can sign in to with a password — verify that you actually can — and put it in
**Emergency accounts** so that it keeps password access once **Single sign-on only** is on.

Full detail: [troubleshooting → Locked out of the control panel](troubleshooting.md#5-locked-out-of-the-control-panel).

---

## Step 6 — Test the login and read the diagnostics

1. Open the Craft control panel login screen in a **private window**, leaving your normal
   administrator session signed in elsewhere.
2. Click the single sign-on button (its text is whatever you set as **Login button label**).
3. Sign in at Microsoft.

**If it works**, you land back in the control panel. Then go and look at the row anyway: Settings →
Plugins → Keyway SSO → **Open sign-in diagnostics**. A green **Signed in** row at stage
**Session**, with a green **Accepted** row at stage **Provisioning** under it: reason `jit_create` on the second means a new Craft account was created;
`update_on_login` means an existing one matched and was updated; `existing_unchanged` means it
matched and nothing was changed. A **Provisioning** row records the *decision*, written before the account is saved and the session starts. If an **Error** row at stage **Session** (for example `no_cp_access` or `user_not_saved`) stands directly above it instead of **Signed in**, both belong to the same attempt and the person was **not** signed in. Expand **Details** and check **Mapped to** — this is where you
confirm that the Craft groups are the ones you intended, and it is worth doing on day one rather
than after somebody has the wrong permissions.

Watch for a blue **Notice** row too: `provisioning_incomplete` means the login succeeded but part of
the configuration could not be applied (a Craft group handle that does not exist, a custom field
missing from the user's field layout). Nothing else in Craft will ever tell you that.

**If it fails**, the person signing in sees one deliberately vague sentence — that is by design, not
a broken error message. The real reason is on the diagnostics screen, in the **Reason** column of
the newest row. Look the code up in
[troubleshooting → reason codes](troubleshooting.md#3-reason-code--what-actually-happened--what-to-do).

The four you are most likely to meet on a first Entra attempt:

| Code | Usual cause on a first attempt |
|---|---|
| `start_failed` (with `discovery_failed` or `issuer_mismatch` in the message) | The **Issuer** value is not exactly what the discovery document reports, or the server cannot reach Microsoft. Re-run the `curl` from step 3 **on the server**. |
| `state_missing` | The callback arrived without our state parameter — usually a redirect URI that does not point at this plugin's endpoint. Note that a **POSTed** response produces no row at all: it fails Craft's CSRF check with an HTTP 400 before the plugin sees it (step 2). |
| `identity_rejected` with `audience_mismatch` | The **Client ID** in Craft is not the one in the token's `aud`. |
| `attributes_rejected` | No usable `email` claim arrived. Check the `email` scope and the account's mail attribute; see step 4. |

---

## Known limits with Entra ID

* **This guide is not verified against a live tenant.** Treat every **[portal]** instruction as a
  description of intent, not as a confirmed click path.
* **No Single Logout over OIDC.** Signing out of Craft does not sign the user out of Microsoft,
  and signing out at Microsoft does not end the Craft session. The plugin's logout endpoint
  (`sso/slo`) is **SAML-only**: it verifies a signed SAML `LogoutRequest` and is dead on an
  install configured for OIDC, so nothing in this guide applies to it.
* **Single-tenant issuers only**, for the byte-for-byte reason given in *What you will need*.
* **The `sub` claim is how a returning user is recognised**, together with the issuer and the Craft
  account. Entra's `sub` is a pairwise identifier: it is stable for a given user **in a given
  application registration**, and it is a *different* value in a different registration. So moving
  this site to a new app registration, or recreating the registration, changes `sub` for everybody —
  and every account single sign-on created is then refused with `linking_disabled` until an
  administrator clears the stale records. It is not a reason to avoid doing it; it is a reason to
  plan it. The procedure is in
  [troubleshooting → one person suddenly refused](troubleshooting.md#3e-provisioning-stage-provisioning-outcome-refused).
* **Group claims usually arrive as GUIDs**, which makes the mapping table unreadable; see step 4.
  There is no name resolution in this plugin.
* **The response must come back on the query string.** A registration that returns the response by
  POST breaks every login, and does so **outside** the plugin: Craft's CSRF validation rejects the
  POST first, so the administrator sees HTTP 400 "Unable to verify your data submission." and finds
  nothing on the diagnostics screen.
* **PKCE is mandatory and not configurable.** So is the signing-algorithm allow list (`RS256`,
  `ES256` only) and the fact that the time checks run; only their tolerance is adjustable, up to
  120 seconds.
* **Signed userinfo responses are refused.**
* **Entra publishes its JWKS signing keys without an `alg` parameter.** This plugin handles that
  (the algorithm is derived per key from the key type), and it is mentioned here only so that the
  behaviour is not mistaken for a fault if you compare the JWKS with another integration.
* **Nothing in this guide is a statement about support, certification or any commercial
  relationship with Microsoft.** It is a technical description of how this plugin's OIDC reader
  behaves.
