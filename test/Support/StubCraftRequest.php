<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\web\Request;

/**
 * The request Craft sees when an identity provider posts back to this plugin.
 *
 * NOT a control panel request, and that is the whole point rather than a shortcut. The callback
 * address an administrator registers with the identity provider is an action URL
 * (`/actions/keyway-sso/sso/acs`), and `getIsCpRequest()` is true only under the site's
 * `cpTrigger` or control panel base URL (web/Request.php). On such a request
 * `helpers\User::getAuthStatus()` never reaches its `accessCp` branch - measured: an active
 * account with no permissions at all comes back from it as null, "no objection" - which is
 * precisely why CraftSignIn asks about control panel access itself.
 *
 * `getIsConsoleRequest()` is pinned to false because the inherited implementation answers
 * `PHP_SAPI === 'cli'`, and under the test runner that is true. Left alone it would skip the
 * branch above and the fixture would stop resembling a real login.
 */
final class StubCraftRequest extends Request
{
    public bool $isCpRequest = false;

    public function __construct()
    {
        // Deliberately does not call parent::__construct(): no application, no PHP superglobals.
    }

    public function getIsConsoleRequest(): bool
    {
        return false;
    }

    public function getIsCpRequest(): bool
    {
        return $this->isCpRequest;
    }
}
