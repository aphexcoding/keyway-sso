# Keyway SSO

Single sign-on for the **Craft CMS 5** control panel over **SAML 2.0** or **OpenID Connect**.

Keyway SSO signs people into Craft with your own identity provider, maps the attributes and
groups it receives onto Craft users and user groups, and records every attempt on a diagnostics
screen inside the control panel.

## Requirements

| What | Version |
|---|---|
| PHP | 8.2 or newer |
| Craft CMS | 5.0 or newer, **Team edition or higher** (one feature needs Pro - see below) |
| PHP extensions | `dom`, `mbstring`, `openssl`, `zlib` |

Craft Solo holds one user account, so just-in-time provisioning has nowhere to provision. From
Team upwards everything works except **assigning Craft user groups**, which Craft itself only has
from Pro upwards — on Team, sign-in, just-in-time accounts, attribute mapping, "refuse a sign-in
that matches no group" and the administrator rules all work, while rules that name a Craft group
do nothing and say so. Details: [`docs/README.md`](docs/README.md).

## Installation

**From the Plugin Store (the usual route):** in the control panel open **Plugin Store**, search for
"Keyway SSO" and press **Install**. Craft downloads the package and runs the installation.

**With Composer,** from the project root of your Craft site:

```bash
composer require aphexcoding/keyway-sso
php craft plugin/install keyway-sso
```

`composer require` only works if Composer can find the package: through Craft's own repository
(`https://composer.craftcms.com`, which Craft adds to your `composer.json` the first time anything
is installed from the control panel) or through Packagist, if the package is listed there. If
Composer answers that the package could not be found, use the Plugin Store route.

Then open **Settings → Plugins → Keyway SSO**. Until you choose a protocol there, the login
screen looks exactly as it did before the plugin was installed — **Protocol** starts at
`Disabled (password login only)`.

After any later update, run `php craft up`.

## Documentation

Full deployment documentation is in **[`docs/`](docs/README.md)**:

| Page | What it covers |
|---|---|
| [`docs/README.md`](docs/README.md) | Requirements, installation, settings reference, provider overview |
| [`docs/keycloak.md`](docs/keycloak.md) | Keycloak — SAML 2.0 and OpenID Connect |
| [`docs/okta.md`](docs/okta.md) | Okta — SAML 2.0 |
| [`docs/entra-id.md`](docs/entra-id.md) | Microsoft Entra ID — OpenID Connect |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Every refusal code the plugin can produce, and what to do about it |

The settings are the same for any other SAML 2.0 or OpenID Connect provider — the guides differ
only in where each value is found in the provider's console — but only Keycloak and Okta have
been tested with SAML, and OpenID Connect has been run end to end with Keycloak only.

**Verification status** is stated per provider in
[`docs/README.md`](docs/README.md#choose-your-provider), including what has been exercised
against a live tenant and what has not. Read it before you plan a rollout.

## License

Commercial software under the Craft License. See [LICENSE.md](LICENSE.md).
