<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

use Keyway\Sso\Core\Attribute\EmailNormalizer;
use Keyway\Sso\Core\Support\Ascii;

/**
 * A Craft account as the core sees it: identity plus the flags that decide access.
 *
 * Read-only snapshot supplied by the Craft layer. The core never mutates it.
 *
 * EVERY PARAMETER IS REQUIRED, AND THAT IS THE POINT. `isAdmin`, `status` and `isLocked` used to
 * have permissive defaults (not an admin, active, not locked), which was harmless while nothing
 * depended on them. Since ProvisioningPolicy gained the linking gates, these three fields carry
 * four separate security decisions - admin takeover, deactivated account, locked account,
 * suspension - so an adapter written in good faith as `new ExistingUser($id, $email, $username)`
 * would have described every account as "not an admin, active, unlocked" and walked past all of
 * them at once. A missing argument is now a fatal error at integration time, which is the moment
 * we want it, rather than a silent yes at login time. The rule is the same one behind the reader
 * contract: a contract that can be satisfied unsafely is not a contract.
 *
 * The address is normalised the same way mapped attributes are (lower-cased, trimmed), because
 * the two are compared: an account stored as `Jan.Kowalski@Example.com` and an assertion
 * carrying `jan.kowalski@example.com` are the same person, and treating them as two would
 * create a duplicate account on every single login.
 */
final class ExistingUser
{
    public readonly string $id;
    public readonly string $email;
    public readonly string $username;
    public readonly bool $isAdmin;
    public readonly AccountStatus $status;

    /** True when Craft locked the account after repeated failed password attempts. */
    public readonly bool $isLocked;

    /**
     * @param string        $username Craft's username; pass '' only when the install really has
     *                                none (useEmailAsUsername).
     * @param bool          $isAdmin  Craft's `admin` flag, verbatim - never a guess.
     * @param AccountStatus $status   Craft's account status, mapped 1:1. Reporting a deactivated
     *                                account as Active is how SSO reinstates somebody an
     *                                administrator deprovisioned on purpose.
     * @param bool          $isLocked Craft's lockout flag after repeated failed sign-ins.
     */
    public function __construct(
        string $id,
        string $email,
        string $username,
        bool $isAdmin,
        AccountStatus $status,
        bool $isLocked
    ) {
        $this->id = Ascii::trim($id);
        $this->email = EmailNormalizer::normalize($email);
        $this->username = Ascii::trim($username);
        $this->isAdmin = $isAdmin;
        $this->status = $status;
        $this->isLocked = $isLocked;
    }

    public function isSuspended(): bool
    {
        return $this->status === AccountStatus::Suspended;
    }
}
