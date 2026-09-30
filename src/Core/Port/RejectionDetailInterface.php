<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Port;

/**
 * A reader that can say, for an administrator, why it rejected the last response.
 *
 * Separate from IdentityReaderInterface on purpose: the exception a reader throws carries one
 * neutral sentence and a stable reason code, and that pair is the whole contract (A8). The
 * detail is an extra - `malformed_response` is true of a wrong client secret and of a token
 * endpoint that answered with HTML, and only the detail tells the two apart - so a reader
 * without one is still a complete reader.
 *
 * WHAT COMES BACK IS NOT OURS. It quotes the identity provider and, through it, whoever can
 * reach the login endpoint: an `error` parameter, an issuer, a Destination. The caller treats it
 * as hostile text - LoginFlow reduces it to printable ASCII and bounds it before it reaches the
 * diagnostics record, and it is never shown to the person signing in.
 */
interface RejectionDetailInterface
{
    /**
     * Administrator-facing detail of the last rejection. Empty when nothing was rejected yet.
     */
    public function detail(): string;
}
