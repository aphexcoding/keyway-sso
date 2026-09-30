# Keycloak

Keycloak is the provider this plugin has been exercised against most directly: its discovery
document, its JWKS (including the realm's `sig` / `enc` key layout) and a real id token signed by
a real realm key are read by `bin/smoke-keycloak.php` against a live realm. **SAML was verified
end to end on 17 September 2026** against a live Keycloak 26.0 realm and a live Craft install:
sign-in, attribute and group mapping, account creation, and the IdP-initiated logout path of
step 7. **OpenID Connect has not been run end to end** — for it the smoke check above is all
the proof there is.

This guide covers **both protocols**. Read Step 2 twice if you are undecided: SAML is the safer
default when your Craft site is not served over `https` yet, because OpenID Connect refuses
anything but `https` here, without exception.

Keycloak's admin console has been reorganised more than once. The item names below are from the
current console (left menu: **Clients**, **Client scopes**, **Realm settings**, **Groups**,
**Users**); on an older version, look for the section that does the same job rather than for the
same wording.

---

## What you will need

* A Craft 5 site where you can reach **Settings → Plugins → Keyway SSO**, and a Craft account
  with admin rights on it.
* A Keycloak realm and an account allowed to create clients and mappers in it (`manage-clients`
  in that realm, or realm admin).
* The realm's base URL and realm name. Everything Keycloak exposes hangs off
  `<KEYCLOAK_BASE>/realms/<REALM>`; you will paste variants of that string several times.
* For OpenID Connect only: your Craft site must be served over `https`, and its redirect URI must
  not carry a query string (see Step 1).

---

## Step 1 — Turn the plugin on and copy this site's values

1. Open **Settings → Plugins → Keyway SSO** on the Craft site.
2. Set **Protocol** to `SAML 2.0` or `OpenID Connect`. The fields for the other protocol stay on
   the page but are not validated and are not used.
3. Optionally change **Login button label** (default: `Sign in with SSO`, at most 120
   characters). This is the text on the button the plugin adds to the control-panel login screen.
4. Copy the addresses this installation actually answers on — do not retype them. **They are on
   the screen before you save anything**, because the plugin builds them from its own registered
   routes and this site's base URL:
   * SAML: **ACS URL this site answers on**, and **This site's URL** (the usual choice for the SP
     entity ID).
   * OIDC: **Redirect URI this site answers on**.
5. If the copied address contains `index.php?p=`, this site generates URLs with the script name in
   them. For SAML that is acceptable. For OpenID Connect, turn on `omitScriptNameInUrls` in your
   Craft general config first — several providers refuse a redirect URI with a query string.

**Do not try to save a half-filled SAML configuration yet, and do not expect the metadata file at
this point.** The settings screen is validated as a whole: with **Protocol** set to `SAML 2.0`, a
save is rejected until **IdP entity ID**, **IdP signing certificate**, **IdP SSO URL**, **SP entity
ID** and **ACS URL** are all present and well-formed — and a rejected save stores nothing at all.
Since the values in the first three of those fields come from Keycloak, the working order is: read
the addresses here (Step 1), create the client in Keycloak with them (Step 2), come back with
Keycloak's values and save the complete configuration (Step 3). **Download metadata** and the
**Metadata URL** become live only after that save; until then the button is inert and the address
answers **404** on purpose.

---

## Step 2 — Create the application at Keycloak

### 2a. SAML

1. In the realm, go to **Clients** and create a new client with client type **SAML**. The
   **Client ID** of a SAML client in Keycloak *is* the SP entity ID, so it must be exactly the
   string you will put in **SP entity ID** on the Craft side — the **This site's URL** copy field
   from Step 1 (this site's URL without a trailing slash) is the usual choice.
   *(If you prefer to configure Keycloak from our metadata file rather than by hand, you can: but
   the file exists only after the complete configuration has been saved in Step 3, so that route
   means creating the client roughly as below, finishing Step 3, and then re-importing the
   document over it. Either way the entity ID and the ACS URL must end up identical on both
   sides — they are compared character for character.)*
2. Set the client's valid redirect URI and its SAML processing URL to the **ACS URL this site
   answers on** value from Step 1. Keycloak posts the assertion to that address.
3. In the client's key settings, **turn off the requirement for a signed client (AuthnRequest)
   signature**. This plugin sends authentication requests unsigned, deliberately, and Keycloak
   enables that requirement by default — leaving it on makes every login fail at Keycloak before
   Craft ever sees a response.
4. Leave assertion signing **on**: the plugin requires a signed assertion unconditionally and has
   no setting to relax it.
5. Set the client's **Name ID format** to `email`, and have Keycloak send the user's e-mail
   address as the subject. The plugin does not inspect the NameID *format* attribute, so this is
   about getting a usable subject value, not about passing a check — but the value has to be
   **stable**, and that part is not cosmetic: accounts this plugin creates are recognised on later
   logins by (account, issuer, **Name ID**). `transient` is a new value on every login by
   definition and makes every second login fail with `linking_disabled`; use `email` or
   `persistent`. See
   [troubleshooting → one person suddenly refused](troubleshooting.md#3e-provisioning-stage-provisioning-outcome-refused).
6. Add the attributes. In the client's dedicated client scope, add three mappers of the
   "user property" kind so that the assertion carries attributes named **exactly**:

   | SAML attribute name | Keycloak user property |
   |---|---|
   | `email` | email |
   | `firstName` | firstName |
   | `lastName` | lastName |

   The plugin matches on the attribute's `Name`, not on its friendly name, and falls back to a
   case-insensitive match only if the exact name is not present. Avoid the predefined X.500
   mappers here unless you also change the mapping table in Step 4 — they send names like
   `urn:oid:1.2.840.113549.1.9.1`.
7. If you want group mapping, add a group-list mapper whose attribute name is `groups`. Turn the
   full-group-path option **off** unless you want to match on `/engineering` instead of
   `engineering` in Step 4.
8. Collect what Craft needs from Keycloak. All three values are in the realm's SAML descriptor,
   which you can open directly:

   ```
   <KEYCLOAK_BASE>/realms/<REALM>/protocol/saml/descriptor
   ```

   | Craft field | Value |
   |---|---|
   | **IdP entity ID** | the `entityID` attribute of the document — `<KEYCLOAK_BASE>/realms/<REALM>` |
   | **IdP SSO URL** | the `SingleSignOnService` location for the HTTP-Redirect binding — `<KEYCLOAK_BASE>/realms/<REALM>/protocol/saml` |
   | **IdP signing certificate** | the `X509Certificate` element inside `KeyDescriptor use="signing"` |

### 2b. OpenID Connect

1. In the realm, go to **Clients** and create a new client with client type **OpenID Connect**.
   The **Client ID** you choose here is what goes into **Client ID** on the Craft side.
2. Turn **client authentication** on (a confidential client). A public client also works — the
   plugin always uses PKCE with `S256` — but then leave **Client secret** empty on the Craft side.
   An empty-looking secret that is really an unresolved environment reference is treated as "no
   secret", which silently downgrades a confidential client, so the plugin refuses to sign anyone
   in until the reference resolves.
3. Set the client's valid redirect URI to the **Redirect URI this site answers on** value from
   Step 1, exactly as shown. Keycloak also accepts wildcards here; do not use one — the plugin
   compares the registered value with what it sends.
4. Read the client secret from the client's credentials, if you made it confidential.
5. Make sure the client can issue the `profile` and `email` scopes (they are assigned by default
   on a new Keycloak client).
6. If you want group mapping, add a group-membership mapper to the client's dedicated scope with
   the token claim name `groups`, included **in the ID token**, and the full-path option off.
   The plugin reads identity from the id token; the userinfo endpoint is only consulted when you
   turn **Fetch userinfo** on, and even then the id token stays the source of identity.
7. The value Craft needs as **Issuer** is:

   ```
   <KEYCLOAK_BASE>/realms/<REALM>
   ```

   That string is also what Keycloak puts in the `iss` claim, and the plugin compares the two byte
   for byte — including or excluding a trailing slash. The plugin appends
   `/.well-known/openid-configuration` itself; do not paste the discovery URL.

---

## Step 3 — Paste Keycloak's values back into the plugin

### SAML fields

| Field on the settings screen | What to put in it |
|---|---|
| **IdP entity ID** | `<KEYCLOAK_BASE>/realms/<REALM>`. Compared byte for byte against the assertion issuer. |
| **IdP signing certificate** | The realm signing certificate, PEM or bare base64. A fingerprint is rejected. |
| **IdP SSO URL** | `<KEYCLOAK_BASE>/realms/<REALM>/protocol/saml`. Required — without it the login cannot start, because there is nowhere to send the browser. |
| **SP entity ID** | The client ID you gave the SAML client. The **This site's URL** copy field above it is the usual choice. |
| **ACS URL** | Paste the **ACS URL this site answers on** value. |
| **SP private key** | Required for encrypted assertions, and for Single Logout (Step 7). Use an environment variable (`$KEYWAY_SP_KEY`); leave empty if you use neither. |
| **Clock skew (seconds)** | Default `60`, maximum `120`. |

Save. The screen compares what you typed into **ACS URL** with the address this site really
answers on and comments underneath the field: silence means the two are identical, and every other
message tells you precisely how they differ (a trailing slash, the control-panel alias, another
site of this installation, or a host this install does not serve).

### OpenID Connect fields

| Field on the settings screen | What to put in it |
|---|---|
| **Issuer** | `<KEYCLOAK_BASE>/realms/<REALM>`, `https` only. |
| **Client ID** | The client ID from Keycloak. |
| **Client secret** | The client secret, written as an environment reference (`$KEYWAY_OIDC_SECRET`). Leave empty for a public client. |
| **Redirect URI** | Paste the **Redirect URI this site answers on** value, `https` only. |
| **Scopes** | One per line. Default `openid`, `profile`, `email`; `openid` is added automatically. |
| **Fetch userinfo** | Off by default. Turn on only if a claim you map is missing from the id token. |
| **Clock skew (seconds)** | Default `60`, maximum `120`. |

Save. If anything is still wrong, the screen says so at the top: *"Single sign-on is selected but
the connection is not usable yet, so the login screen keeps password login only."*

---

## Step 4 — Map attributes and groups

**Attributes.** Leaving the **Attributes** table empty does not mean "map nothing" — it means
"use the shipped defaults":

| IdP attribute | User field | Required |
|---|---|---|
| `email` | `email` | yes |
| `firstName` | `firstName` | no |
| `lastName` | `lastName` | no |

That default fits the SAML setup in Step 2a exactly. **It does not fit OpenID Connect**, because
Keycloak's standard claims are `given_name` and `family_name`. For OIDC add three rows:

| IdP attribute | User field |
|---|---|
| `email` | `email` (switch **Required** on) |
| `given_name` | `firstName` |
| `family_name` | `lastName` |

Targets may be `email`, `username`, `firstName`, `lastName`, `fullName`, or `field:<handle>` for a
custom field on the user's field layout. Nothing else is writable. A `username` row is optional:
when a new account is created and the mapping carries no username, the e-mail address becomes the
Craft username. Craft accepts an address there, and on Craft's default configuration
(`useEmailAsUsername` off) an account with no username at all cannot be saved. Two extra sources
exist: `@nameId` and `@issuer` read the assertion itself rather than an attribute. **Multiple
values** decides what happens when an attribute arrives more than once (`First`, `Last`, `Join`),
and **Transform** can force the value to lower or upper case — useful for e-mail addresses from a
directory that stores them in mixed case.

**Groups.** **Source attributes** lists the attributes that carry group membership, one per line;
the default is `groups`, which is what the mappers in Step 2 produce. Each row of the **Groups**
table maps an identity-provider group to a **Craft group handle** by `Exact`, `Prefix` or `Suffix`
match — there are no regular expressions. A Craft group handle must start with a letter and
contain only letters, digits and underscores (64 characters at most), and prefix/suffix patterns
must be at least two characters long. Matching ignores case unless you turn on **Case-sensitive
matching**.

* **Default group** — a handle everybody signing in joins; leave empty for none.
* **Sync mode** — `Append` (default) keeps groups the user already has and adds the mapped ones;
  `Replace` makes Keycloak the only source of truth, which means a login that maps to nothing
  strips the account of every group it has. Pair `Replace` with **Deny login when no group
  matches** if that is not what you want.
* **Allow admin escalation** is **off by default**, and leaving it off is the right default: with
  it on, anybody who can edit groups in your realm can make themselves a Craft admin. Turn it on
  only deliberately; the **Admin rules** table and **Revoke admin when no rule matches** appear
  once you do, and the settings screen keeps a standing warning while it is on.

**Provisioning.** **Create accounts on first login** and **Update accounts on every login** are on
by default, and **Match existing accounts by** is `E-mail`. **Link to existing Craft accounts** is
**off**: a Craft account that already exists with the same address will *not* be adopted by an
identity from Keycloak until you turn that on — and the separate switch **Linking may include
admin accounts** exists so that "let the team in" and "let the directory hand out the owner's
account" are not the same decision. Fill in **Allowed e-mail domains** when you enable linking:
one per line, `example.com` matches exactly, `.example.com` matches sub-domains only, empty means
any domain.

---

## Step 5 — Keep a way back in

Before you tell anyone that single sign-on is live, make sure a broken realm cannot lock you out
of your own control panel.

* **Keep at least one Craft admin whose password you know**, and confirm that password still works
  before you rely on it. The switches below decide who may keep using one; leaving **Admins may
  still use a password** on is what keeps that answer safe.
* **`Single sign-on only` refuses a password sign-in on the control panel.** The password fields
  stay on screen; the refusal happens when the form is submitted, with the message *"This site
  requires single sign-on. Use the sign-in button on this screen."* Front-end logins on your own
  site, passkeys, and the "confirm your password" prompt for an admin who is already signed in are
  all left alone. Detail:
  [troubleshooting → Locked out of the control panel](troubleshooting.md#5-locked-out-of-the-control-panel).
* **Admins may still use a password** is on by default. If a combination of settings would leave
  nobody able to get in when Keycloak fails, the plugin turns this switch back on when you save
  and tells you it did. It checks the settings, not the accounts — see the next point.
* **Emergency accounts** — e-mail addresses or usernames, one per line: the accounts that keep
  password access while **Single sign-on only** is on. An entry only counts if it names an existing
  account **with a local Craft password** — accounts this plugin created from Keycloak logins have
  none — so sign in as one to prove it works before turning the admin fallback off. Detail:
  [troubleshooting → If you really cannot get in](troubleshooting.md#if-you-really-cannot-get-in).
* **Emergency password login (break glass)** with **Emergency login expires at** — a Unix
  timestamp, mandatory when the switch is on, in the future, and **at most 24 hours ahead**. Those
  three rules are enforced when you save: no expiry is refused, an expiry in the past is refused,
  and a window longer than 24 hours is refused with *"Emergency password login can be enabled for
  at most 24 hours at a time."* An expiry that somehow ends up further out than 24 hours is
  treated as closed rather than honoured. Generate the value with, for example,
  `date -u -d '+8 hours' +%s`. While it is active the settings screen counts the remaining minutes
  down for you.

---

## Step 6 — Test the login and read the diagnostics

1. Open the Craft control-panel login screen in a private window. The SSO button appears only when
   the configuration is actually usable — if it is missing, go back to the settings screen and
   read the warnings.
2. Press it. You should land on Keycloak, authenticate, and come back signed in.
3. Whatever happens, open **Settings → Plugins → Keyway SSO → Open sign-in diagnostics**. Each
   attempt is one row: time, outcome (`Signed in`, `Refused`, `Error`, `Notice`), protocol, the
   stage it reached (`Protocol`, `Login state`, `Attributes`, `Groups`, `Provisioning`,
   `Session`), a machine reason code, the subject and the issuer. Open **Details** to see the
   attributes that arrived, what they mapped to, and the decision.
4. The reason code is the thing to act on. A few you are likely to meet on a first attempt:
   `signature_invalid` (wrong certificate in **IdP signing certificate**), `issuer_mismatch`
   (**IdP entity ID** does not match what Keycloak sends), `audience_mismatch` (**SP entity ID**
   does not match the client ID), `destination_mismatch` (**ACS URL** is not the address the
   assertion was posted to), `unsolicited_response` (the response does not belong to a login this
   site started), `jit_disabled`, `linking_disabled`, `domain_not_allowed`, `no_group_match`.
   [troubleshooting.md](troubleshooting.md) goes through them one by one.
5. If the screen says the diagnostics store is unavailable, the plugin's migration has not run —
   `php craft up`.

A login has five minutes between pressing the button and coming back; after that the single-use
login state has expired and the attempt is refused. That is a browser-tab timeout, not a session
length.

---

## Step 7 — Single Logout, if you want it (SAML only)

Optional, off until it is configured on both sides, and **one-directional: a sign-out in Keycloak
ends the Craft session; a sign-out in Craft does not end the Keycloak session.** The settings below
are the ones exercised end to end on 17 September 2026 against **Keycloak 26.0** (realm `keyway`)
and a live Craft install.

**In Keycloak, on the SAML client from Step 2a:**

| Keycloak setting | Value |
|---|---|
| **Front channel logout** (`frontchannelLogout`) | on |
| **Logout service redirect binding URL** (`saml_single_logout_service_url_redirect`) | the **SP single logout URL** copy field on the plugin's settings screen — `<BASE>/actions/keyway-sso/sso/slo` |

The plugin reads logout messages on the **HTTP-Redirect** binding only, so that is the field to
fill; leave the POST-binding one empty.

**In the plugin, in the SAML 2.0 section:**

| Field on the settings screen | What to put in it |
|---|---|
| **IdP single logout URL** | `<KEYCLOAK_BASE>/realms/<REALM>/protocol/saml` — the same address as **IdP SSO URL** |
| **SP private key** | A private key, as an environment reference (`$KEYWAY_SP_KEY`). The plugin signs its `LogoutResponse` with it. It is the same field encrypted assertions use, so one key serves both purposes. |

**Those two count together** (with the plugin's own address, which it derives itself, as the third
part). Until both are filled in, `sso/slo` refuses every message and the metadata document
advertises no `SingleLogoutService` — deliberately, because an advertised endpoint that answers
nothing makes every provider reading the document send logout requests to a dead address. Once they
are set, the metadata publishes `SingleLogoutService` on the HTTP-Redirect binding, and the help
text under **SP single logout URL** changes to say the address is live.

**What the live test showed:**

* **Keycloak → Craft works.** A sign-out in Keycloak reaches `sso/slo`, the plugin answers with a
  **signed `LogoutResponse` carrying `Success`**, and the Craft session is genuinely gone: the
  control panel bounces to the login screen on the next request.
* **Craft → Keycloak does not happen.** Signing out of the Craft control panel leaves the Keycloak
  session open, because SP-initiated logout is not implemented. If both sessions have to end, people
  sign out twice.
* **A browser with no Craft session** is answered `Requester` / `UnknownPrincipal`, and Keycloak
  ends its own session regardless. That status is the normal answer to "there was nothing here to
  end", not a fault to chase; a request whose subject does not match the session in the browser
  that carried it gets the same answer and ends nothing.

**Not checked:** the same user signed in from several browsers at once, and Single Logout against
any provider other than Keycloak (with Okta it will not work at all, for reasons on both sides —
see [okta.md](okta.md)). Treat both as unverified rather than as working.

---

## Known limits with Keycloak

* **Single Logout runs one way only, and only over SAML.** With Step 7 in place Keycloak can end
  the Craft session; Craft cannot end the Keycloak session, and the OpenID Connect path has no
  logout support in either direction.
* **Authentication requests are unsigned.** A Keycloak realm advertises
  `WantAuthnRequestsSigned="true"` in its descriptor, and a new SAML client requires a client
  signature by default. Turning that requirement off for this client (Step 2a.3) is mandatory, not
  optional.
* **OpenID Connect needs `https` on both sides.** The **Issuer** and the **Redirect URI** must
  both be `https`, with no loopback exception and no override. A Keycloak that speaks plain HTTP —
  the usual local-development setup — cannot be used over OIDC; put a certificate on it, or use
  the SAML path while developing.
* **Group paths.** With Keycloak's full-group-path option on, group values arrive as
  `/parent/child`, with a leading slash. Either leave that option off, or write your rules to
  match the path form.
* **Only `RS256` and `ES256`** id-token signatures are accepted. Keycloak's default realm key is
  RS256, so this only matters if somebody changed it.
* **Encrypted assertions** work (**SP private key**), but the metadata document publishes no key
  material, so the matching SP certificate has to reach Keycloak by another route.
* **The password fallback refuses a sign-in rather than hiding the password form**, and only on
  the control panel (Step 5).

This list covers what is specific to Keycloak. The complete, canonical list of this release's
limits — including the ones that apply to every provider — is
[troubleshooting → Known limits](troubleshooting.md#6-known-limits-and-things-that-are-not-bugs).
Read it once before you go live; do not assume this page is the whole picture.
