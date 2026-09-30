<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\IdentityLinkStoreInterface;
use RuntimeException;

/**
 * A link store that is broken in the worst permitted way: it THROWS.
 *
 * IdentityLinkStoreInterface forbids that, and this double exists precisely because a contract
 * is only as strong as what happens when somebody breaks it. The real adapter swallows its own
 * database faults, but an adapter is code somebody can get wrong, and the failure would land
 * inside a login. So LoginFlow is required here to survive an implementation that does not
 * honour the contract - refusing the login (fail closed), not returning a 500 from the callback.
 */
final class FailingIdentityLinkStore implements IdentityLinkStoreInterface
{
    /**
     * The kind of message a real driver would carry: it names a table and would name a
     * statement. Tests assert it does NOT reach the diagnostics row.
     */
    public const MESSAGE = 'SQLSTATE[42S02]: Base table or view not found: keyway_sso_links';

    /** @var list<array{userId: string, issuer: string, subject: string}> */
    public array $attempted = [];

    public function isLinkedTo(string $userId, string $issuer, string $subject): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }

    /**
     * Says it is ready and then throws, which is the combination that reaches the catch block.
     * A store that admitted it was not ready would be answered by the other branch and would
     * never prove anything about an implementation breaking the contract.
     */
    public function isReady(): bool
    {
        return true;
    }

    public function remember(string $userId, string $issuer, string $subject): void
    {
        $this->attempted[] = ['userId' => $userId, 'issuer' => $issuer, 'subject' => $subject];

        throw new RuntimeException(self::MESSAGE);
    }
}
