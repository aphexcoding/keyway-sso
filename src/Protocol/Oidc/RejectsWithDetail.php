<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use Keyway\Sso\Core\Identity\IdentityReaderException;

/**
 * One way out of every OIDC class: throw with a stable reason code, keep the detail aside.
 *
 * Contract A8 - failure is an exception, never a partial result, and never a "success with a
 * warning". The message is the same neutral sentence for every cryptographic failure so that
 * the login screen cannot be used as an oracle telling an attacker which check they tripped.
 */
trait RejectsWithDetail
{
    /** Shown to the end user; deliberately identical for every rejection. */
    private const USER_MESSAGE = 'We could not verify the sign-in response from your identity provider.';

    private RejectionDetail $rejectionDetail;

    /**
     * Administrator-facing detail of the last rejection. Empty when nothing was rejected yet.
     */
    public function detail(): string
    {
        return $this->rejectionDetail->last();
    }

    private function reject(string $reasonCode, string $detail): never
    {
        $this->rejectionDetail->set($detail);

        throw new IdentityReaderException($reasonCode, self::USER_MESSAGE);
    }
}
