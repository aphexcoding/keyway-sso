<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

/**
 * The administrator-facing half of a rejection, shared by the four OIDC classes that can reject.
 *
 * Contract A8 says the user sees one neutral sentence and the detail goes to the masked
 * diagnostics record. In the SAML reader that was easy: one class, one `$detail` field. The OIDC
 * flow spans discovery, the key store, the authorization request and the reader, and a failure
 * in the key store must still surface through OidcTokenReader::detail() - otherwise the
 * diagnostics panel shows "we could not verify the sign-in" and nothing else, which is the
 * support ticket this plugin is supposed to prevent.
 *
 * Deliberately mutable and shared by reference: it is a sink for the last rejection, not state
 * anything trusts. Nothing here ever reaches the login screen.
 */
final class RejectionDetail
{
    private string $last = '';

    public function set(string $detail): void
    {
        $this->last = $detail;
    }

    public function last(): string
    {
        return $this->last;
    }

    public function clear(): void
    {
        $this->last = '';
    }
}
