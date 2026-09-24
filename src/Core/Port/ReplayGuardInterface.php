<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * Single-use registry for protocol message identifiers (contract A5).
 *
 * This is NOT the login state in Core\State\StateStore. StateStore burns the state token this
 * site issued; the replay guard burns the identifier the IdP issued (SAML `Assertion/@ID`,
 * OIDC `jti`). The contract demands both, because they fail differently: a response captured
 * from a proxy log carries a perfectly valid state token the first time it is used, and an
 * assertion that is accepted twice is accepted twice even though every signature checks out.
 *
 * Implementations MUST be atomic in the same sense as StateStorageInterface::markConsumed():
 * `remember()` returns true for the first caller only, and false for every repeat, even when
 * two requests race. A read-then-write adapter breaks the guarantee.
 *
 * Retention: at least until `$expiresAt`, which the caller sets to the end of the accepted time
 * window (assertion expiry plus the configured skew). Forgetting earlier re-opens the window;
 * forgetting later only costs storage.
 */
interface ReplayGuardInterface
{
    /**
     * @param string $id        Identifier guaranteed unique by the protocol.
     * @param int    $expiresAt Unix timestamp after which the entry may be dropped.
     * @return bool True when this call recorded the id for the first time.
     */
    public function remember(string $id, int $expiresAt): bool;
}
