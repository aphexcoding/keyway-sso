# Release Notes for Keyway SSO

## 1.0.0 - 2026-09-30

First public release. Keyway SSO signs people into the Craft CMS 5 control panel with your own
identity provider over SAML 2.0 or OpenID Connect, maps the attributes and groups it receives onto
Craft users and user groups, and records every attempt on a diagnostics screen inside the control
panel.

> [!NOTE]
> Requires Craft CMS 5.0 or newer, **Team edition or higher**, PHP 8.2 or newer, and the
> `dom`, `mbstring`, `openssl` and `zlib` PHP extensions. One feature — assigning Craft user
> groups — needs **Pro**, because Craft itself only has user groups from Pro upwards; on Team the
> plugin leaves group membership untouched and says so. Everything else works on Team.

> [!TIP]
> Until you pick a protocol in **Settings → Plugins → Keyway SSO**, the login screen looks
> exactly as it did before installation — **Protocol** starts at `Disabled (password login only)`.
> After any later update, run `php craft up`.

### Added

- **SAML 2.0 sign-in**, HTTP-POST binding for the assertion. Signed assertions are required and
  that check cannot be switched off; encrypted assertions are implemented but unverified (see
  "Known limits"); the service-provider
  metadata document is served from your own site.
- **OpenID Connect sign-in** — run end to end with Keycloak only (see "Verified against live
  systems" below): Authorization Code with PKCE (`S256`, always), discovery, `RS256` and `ES256`
  id-token signatures (`ES256` is covered by automated tests only). `https` is required for both the issuer and the redirect URI.
- **Attribute and group mapping**: provider attributes onto `email`, `username`, `firstName`,
  `lastName`, `fullName` or any custom field; provider groups onto Craft group handles by exact,
  prefix or suffix match, including a "refuse a sign-in that matches no group" switch.
- **Just-in-time accounts**: create on first login, update on every login, or match an account
  that already exists — each one its own switch. Matching an existing account also asks you to
  name the e-mail domains it may match, and linking to an administrator account is a second,
  separate opt-in.
- **Password fallback with an anti-lockout guard.** A combination that would leave nobody able to
  sign in if the provider broke has admin password login switched back on, with a warning saying
  so. The guard reads your settings, not your accounts: an emergency account that does not exist,
  or that has no local Craft password — as none of the accounts this plugin creates do — is not a
  way back in, and the guard cannot tell.
- **A diagnostics screen** recording every sign-in attempt that reaches a connection, with the
  stage it got to, the outcome, a machine reason code (`domain_not_allowed`, `state_rejected`, …),
  the attributes that arrived and the decision that was made. Provider values are masked when
  written; history is pruned to 30 days or 2000 rows.
- **Single Logout** (SAML only, one direction, opt-in: it needs your provider's logout URL and an
  SP private key before it does anything): when your identity provider sends a signed SAML
  `LogoutRequest`, the plugin ends the matching Craft session. Signing out of Craft does not end
  the session at your identity provider, and Okta will not send such a request after an ordinary
  Okta sign-out — so with Okta as your only provider, plan on single sign-on, not single logout.
  Verified end to end against Keycloak 26.0; OpenID Connect has no logout support.
- **Step-by-step guides** for Keycloak and Okta, written against the field names you actually see
  in each console. The Microsoft Entra ID guide is written from Microsoft's published documentation
  and is marked, in the guide itself, as not yet verified against a live tenant. A troubleshooting
  page lists every refusal code the plugin can produce.

### Verified against live systems

- **SAML with Keycloak 26.0** — verified end to end on 17 September 2026 against a live realm and
  a live Craft install: sign-in, attribute and group mapping, account creation, and the
  IdP-initiated SAML logout described above.
- **SAML with Okta** (Integrator Free Plan) — verified end to end on 17 September 2026 against a
  live tenant and a fresh Craft 5.11 install on default settings: the first sign-in created the
  account just in time with the mapped group, the second updated it and reached the control panel.
- **OpenID Connect with Keycloak 26.0** — verified end to end on 30 September 2026 against a live
  Craft 5.11 install on PHP 8.2, over HTTPS with certificate verification: Authorization Code
  with PKCE (`S256`), a confidential and a public client, `RS256` id tokens, first and repeat
  sign-in, and refusals (wrong client secret, domain not allowed, no matching group). Not
  covered: `ES256` id tokens, key rotation, and any OpenID Connect provider other than Keycloak.
- **Microsoft Entra ID** — the guide is written and **not yet verified against a live tenant**;
  the guide itself says so.

### Known limits — stated here rather than discovered after purchase

- Logins are **started from the Craft site** (SP-initiated). Provider-initiated tiles and
  bookmarks that jump straight into the provider do not work.
- **SAML authentication requests are sent unsigned.** A provider configured to require signed
  requests will refuse every login.
- **One connection at a time** — the protocol setting selects a single provider; there is no
  multi-provider mode.
- **A `transient` NameID format cannot be used.** Accounts are recognised on later logins by their
  subject, and a transient NameID is a new value every time, so the second login of every user is
  refused. Configure `persistent` or `emailAddress` at the provider.
- **Encrypted SAML assertions are unverified.** Decryption is implemented (**SP private key**),
  but it is not covered by an automated test and has not been run against a live provider. Test
  it yourself before relying on it.
- **No SCIM, no LDAP**, and the plugin is not an identity provider itself.
- **No field for an SP certificate**, so a site using encrypted assertions has to hand that
  certificate to its provider out of band.
- **Clock-skew tolerance tops out at 120 seconds** and the time checks themselves cannot be
  switched off.
- **Just-in-time accounts stop at five on Craft Team.** That ceiling is Craft's own licence limit
  for the Team edition, not a limit of this plugin; a site that expects to provision more users
  needs Craft Pro.
- **The password fallback refuses a sign-in rather than hiding the form.** With **Single sign-on
  only**, a control-panel password sign-in is blocked when it is submitted, but the password fields
  stay on screen. Front-end logins, passkeys and the "confirm your password" elevated-session check
  are deliberately untouched.
- **On Craft's default `omitScriptNameInUrls = false`, the ACS URL and the redirect URI come out
  as `<BASE>/index.php?p=actions/keyway-sso/…`.** That address routes correctly, and for SAML
  either form is fine; for OpenID Connect it often is not, because some providers refuse a redirect
  URI that carries a query string — such a site needs `omitScriptNameInUrls` turned on before
  OpenID Connect can be registered.
- **Single Logout will not work with Okta.** By Okta's own documentation, Okta does not send a
  logout request to an application after an ordinary Okta sign-out — with Okta as your only
  provider, plan on single sign-on, not single logout.
