<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

use Keyway\Sso\Core\Provisioning\ExistingUser;

/**
 * Read-only view of the host CMS user store, implemented by the Craft layer.
 *
 * The core never writes users. It returns a ProvisioningDecision and the Craft layer applies it,
 * so that account creation stays on one side of the boundary and stays auditable.
 *
 * Contract for the implementer: fill in the WHOLE ExistingUser, in particular `status`
 * (AccountStatus, mapped from Craft's `active`/`pending`/`suspended`/`inactive`), `isLocked` and
 * `isAdmin`. Reporting a deactivated or locked account as Active is not a cosmetic bug - it is
 * how single sign-on silently reinstates somebody an administrator deprovisioned on purpose,
 * because ProvisioningPolicy decides on exactly these fields and has no other source of truth.
 * `findByEmail()` receives a normalised (trimmed, lower-cased) address and must look up
 * case-insensitively.
 */
interface UserDirectoryInterface
{
    public function findByEmail(string $email): ?ExistingUser;

    public function findByUsername(string $username): ?ExistingUser;
}
