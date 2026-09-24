# Keyway SSO — deployment documentation

Keyway SSO signs people into the Craft CMS control panel with your own identity provider over
SAML 2.0 or OpenID Connect, maps the attributes and groups it receives onto Craft users and user
groups, and records every attempt on a diagnostics screen inside the control panel.

These pages are written for the person who has the Craft site on one screen and the identity
provider's admin console on the other. Everything below is taken from the plugin's own code and
from its settings screen, so the field names quoted here are the ones you will actually see.

---

## Requirements

| What | Version |
|---|---|
| PHP | 8.2 or newer |
| Craft CMS | 5.0 or newer |
| PHP extensions | `dom`, `mbstring`, `openssl`, `zlib` |

`zlib` is not optional and is declared as a requirement, so Composer refuses to install the plugin
without it: the SAML authentication request is DEFLATE-encoded before it is sent, and the SAML
logout messages are encoded and read back the same way.

---

## Installation

From the project root of your Craft site:

```bash
composer require aphexcoding/keyway-sso
php craft plugin/install keyway-sso
```

The plugin handle is `keyway-sso`. Installing it creates two tables: the one behind the
diagnostics screen, and the record of which accounts single sign-on created (without which a
just-in-time account is refused on its second login). If you install through **Settings →
Plugins** in the control panel instead, Craft runs the same migration for you.

**After any later update, run `php craft up`.** It is not optional housekeeping: a site that
already had the plugin installed gets new tables only that way, and the one added in schema
version 1.1.0 is the one that keeps people signing in.

Then open **Settings → Plugins → Keyway SSO** and follow the guide for your provider. Until you
choose a protocol there, the login screen looks exactly as it did before the plugin was
installed — **Protocol** starts at `Disabled (password login only)`.

---

## Choose your provider

| Provider | Protocols covered by the guide | Guide | Verification status |
|---|---|---|---|
| Keycloak | SAML 2.0 and OpenID Connect | [keycloak.md](keycloak.md) | **SAML verified end to end on 17 September 2026** against a live Keycloak 26.0 realm and a live Craft install: sign-in, attribute and group mapping, account creation, and IdP-initiated Single Logout (step 7) — which is SAML only and one way (signing out of Craft ends nothing at the provider), opt-in (it needs the provider's logout URL and an SP private key before it does anything), and will not work with Okta, which will not send such a request after an ordinary Okta sign-out. **OpenID Connect has not been run end to end**; for it a smoke check (`bin/smoke-keycloak.php`) reads a real realm's discovery document and JWKS and verifies a real id token's key selection and signature — but not the HTTPS transport (the scheme is rewritten before the document is handed over) and not the full id-token reader. |
| Okta | SAML 2.0 | [okta.md](okta.md) | **SAML verified end to end on 17 September 2026** against a live Okta tenant (Integrator Free Plan) and a fresh Craft 5.11 install on default settings: the first sign-in created the account just in time with the mapped group, and the second one updated it and reached the control panel. **Single Logout will not work with Okta** — by Okta's own documentation (read 17 September 2026) Okta will not send a logout request to the application after an ordinary Okta sign-out; that half was not exercised on the live tenant. OIDC with Okta has not been checked. |
| Microsoft Entra ID | OpenID Connect | [entra-id.md](entra-id.md) | **Guide provided, not yet verified against a live tenant.** |

Any other SAML 2.0 or OpenID Connect provider works the same way — the three guides differ only
in where each value is found in the provider's console.

---

## The five addresses

The plugin answers on five addresses. Each one exists twice: as an **action URL** and as a
control-panel alias (`sso/start`, `sso/acs`, `sso/callback`, `sso/metadata`, `sso/slo`). **Give the identity
provider the action URL and nothing else.** The control-panel alias contains this site's
`cpTrigger` (the `admin` part of the URL), which the site owner can rename at any time, and a
renamed address is a configuration that quietly stops working.

| Address | What it does | Who needs it |
|---|---|---|
| `<BASE>/actions/keyway-sso/sso/start` | Begins a login: issues the single-use login state and the browser-binding cookie, then redirects to your provider. | Nobody. The SSO button on the login screen links to the control-panel alias (`<cp>/sso/start`), and a person may bookmark either form. |
| `<BASE>/actions/keyway-sso/sso/acs` | SAML assertion consumer service: receives the provider's HTTP-POST assertion. | Your provider (SAML), as the **ACS / Single sign-on URL**. |
| `<BASE>/actions/keyway-sso/sso/callback` | OIDC redirect URI: receives the authorization code. | Your provider (OIDC), as the **redirect URI**. |
| `<BASE>/actions/keyway-sso/sso/metadata` | Serves this site's SAML service-provider metadata document. Public and unauthenticated, because several providers fetch it themselves. | Your provider (SAML), optionally — it is also the file behind the **Download metadata** button. |
| `<BASE>/actions/keyway-sso/sso/slo` | Receives the provider's SAML `LogoutRequest` on the HTTP-Redirect binding and ends the matching Craft session. Refuses every message until both the provider's logout URL and an SP private key are set — and until then the metadata document advertises no `SingleLogoutService`. | Your provider (SAML), only if you opt into Single Logout — which is SAML only and one way (signing out of Craft ends nothing at the provider), and which Okta will not trigger after an ordinary Okta sign-out. |

`<BASE>` is your site's own base URL. **Do not type these by hand:** the settings screen shows the
exact addresses this installation answers on, as copy fields (**ACS URL this site answers on**,
**Redirect URI this site answers on**, **Metadata URL**, **SP single logout URL**). For the two you have to repeat in a
field of your own — **ACS URL** and **Redirect URI** — the screen also compares what you pasted
with the address this site really answers on and comments underneath the field. There is no such
comparison for the metadata or single-logout addresses, because there is no field to compare
them with. Both protocols
compare the ACS URL and the redirect URI character for character, and a one-character difference
fails the login with a message that reads like a certificate problem.

Two things worth knowing before they surprise you:

* On an installation with Craft's default `omitScriptNameInUrls = false`, those addresses come out
  as `<BASE>/index.php?p=actions/keyway-sso/sso/acs`. That address routes correctly and is the
  honest answer for such a site. For SAML it is fine. For OpenID Connect it is often not: some
  providers refuse a redirect URI that carries a query string, which is why the help text under
  **Redirect URI this site answers on** says such a site needs `omitScriptNameInUrls` turned on
  before OpenID Connect can be registered.
* The metadata address answers **404** whenever **Protocol** is not `SAML 2.0`, or **SP entity
  ID** or **ACS URL** is empty or malformed. That is deliberate, not a fault: a metadata document
  naming a blank entity ID would configure your provider against a login that can never validate.
  In practice the document appears only once a **complete** SAML configuration has been saved,
  because the settings screen is validated as a whole: with `SAML 2.0` selected, a save is rejected
  until **IdP entity ID**, **IdP signing certificate**, **IdP SSO URL**, **SP entity ID** and
  **ACS URL** are all present and well-formed, and a rejected save stores nothing. So the metadata
  file is a way to hand the finished configuration to your provider, not a way to start it — the
  guides set the steps out in the order that actually works.

The sixth address is not an address you give away: the **diagnostics screen** is a control-panel
page (`<cp>/sso/diagnostics`), reachable from the **Open sign-in diagnostics** button at the
bottom of the settings screen. The plugin adds no navigation item, so that button is the way in.

---

## Secrets belong in environment variables

Exactly two settings accept an environment-variable reference (they are the two rendered as
Craft's env-aware fields):

* **SP private key** (SAML — needed for encrypted assertions, and for Single Logout), and
* **Client secret** (OpenID Connect).

Write them as `$KEYWAY_SP_KEY` / `$KEYWAY_OIDC_SECRET` and put the value in the server's
environment. Craft resolves the reference on read, so the secret stays out of project config and
out of version control.

**Every other field is stored as typed.** Writing `$SOMETHING` into, say, **SP entity ID** or
**ACS URL** does not read an environment variable — the literal string is what goes into the
metadata document and into the comparison, and the login fails on the audience or the ACS check.

If one of the two supported fields points at a variable that is not set (or is set to an empty
value), the plugin fails closed: single sign-on stays off, the settings screen shows a warning
naming the missing variable at the top of the page, and the field itself carries the error
`Environment variable … is not set, or is empty. Set it, or clear this field.`

---

## When a login does not work

1. Open **Settings → Plugins → Keyway SSO** and read the warnings at the top of the screen. A
   connection that is selected but not usable says so there, and the login screen keeps password
   login only until it is fixed.
2. Open **Open sign-in diagnostics**. Every attempt is recorded with the stage it reached
   (`protocol`, `state`, `attributes`, `groups`, `provisioning`, `session`), the outcome
   (`success`, `denied`, `error`, `notice`), a machine reason code such as `signature_invalid` or
   `state_rejected`, and — under **Details** — the attributes that arrived, what they mapped to,
   and the decision that was made. Values from the provider are masked when they are written.
3. Look the reason code up in [troubleshooting.md](troubleshooting.md).

The diagnostics screen is visible to Craft admins in the control panel. Entries are pruned
automatically: the plugin keeps 30 days of history and at most 2000 rows, whichever runs out
first.

---

## What this release does and does not do

* Logins are **started from this site** (SP-initiated). A response that does not match a login
  this site started is refused as unsolicited, so provider-initiated tiles and bookmarks that
  jump straight into the provider's login flow do not work — send people to the Craft login
  screen and let them press the SSO button.
* **SAML authentication requests are sent unsigned.** A provider configured to require a signed
  request will reject every login; each guide says where that switch lives.
* SAML assertions **must** be signed; that check cannot be turned off. Time checks cannot be
  turned off either — only their tolerance, up to 120 seconds.
* Encrypted assertions are supported (**SP private key**), but the plugin has no field for an SP
  *certificate*, so the metadata document carries no key material: if you encrypt assertions, the
  matching certificate has to reach your provider by another route.
* OpenID Connect requires `https` for both the **Issuer** and the **Redirect URI**, with no
  exception and no override, and always uses PKCE with `S256`. Only `RS256` and `ES256` id-token
  signatures are accepted.
* **Single Logout works one way, and only over SAML.** The plugin answers a signed
  `LogoutRequest` sent by your provider and ends the Craft session it names; it never sends one, so
  signing out of Craft does not sign anybody out of the provider. It stays off until an **IdP
  single logout URL** and an **SP private key** are both set, and until then the metadata document
  advertises no `SingleLogoutService` on purpose. Verified end to end with Keycloak
  ([keycloak.md](keycloak.md), step 7); **by Okta's own documentation it will not work with Okta at
  all**, because Okta does not send a logout request to an application after an ordinary Okta
  sign-out — that half has not been observed on a live tenant, and [okta.md](okta.md) says so and
  gives the sources. OpenID Connect has no logout support in either direction.
* **The password fallback refuses a sign-in rather than hiding the form.** **Single sign-on only**
  blocks a password sign-in **on the control panel** when it is submitted; the password fields stay
  on screen, because there is always somebody the settings still permit to use them. Front-end
  logins, passkeys and the "confirm your password" elevated-session check are deliberately
  untouched.
* **The anti-lockout guard checks your settings, not your accounts.** It will not let you save a
  combination that shuts the password door outright, but it cannot tell whether the **Emergency
  accounts** you nominated can really sign in — an account that does not exist, or has no local
  Craft password (as none of the accounts this plugin creates do), is not a way back in. Read
  [troubleshooting → Locked out of the control panel](troubleshooting.md#5-locked-out-of-the-control-panel)
  before you turn **Admins may still use a password** off.

The canonical list of what this release does not do, with the reasoning, is
[troubleshooting → Known limits](troubleshooting.md#6-known-limits-and-things-that-are-not-bugs).
