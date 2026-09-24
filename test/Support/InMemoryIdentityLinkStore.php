<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Port\IdentityLinkStoreInterface;

/**
 * The "which accounts did we create, and for whom" table, as an array.
 *
 * `written` keeps every remember() in order, so a test can see that a link was recorded once,
 * with the issuer and subject the response really carried - the things that decide whether the
 * NEXT login works.
 *
 * `ready` is the missing-table state (`craft up` not run). It is a plain flag rather than a
 * thrown exception because the shipped adapter never throws either: that is exactly what made
 * the failure invisible before LoginFlow started asking isReady().
 */
final class InMemoryIdentityLinkStore implements IdentityLinkStoreInterface
{
    /** @var array<string, string> "<userId>|<issuer>" => subject */
    public array $links = [];

    /** @var list<array{userId: string, issuer: string, subject: string}> */
    public array $written = [];

    /** Flip to false for a site whose migrations have not been run. */
    public bool $ready = true;

    public function isLinkedTo(string $userId, string $issuer, string $subject): bool
    {
        if (!$this->ready || $subject === '') {
            return false;
        }

        return isset($this->links[self::key($userId, $issuer)])
            && $this->links[self::key($userId, $issuer)] === $subject;
    }

    public function remember(string $userId, string $issuer, string $subject): void
    {
        $this->written[] = ['userId' => $userId, 'issuer' => $issuer, 'subject' => $subject];
        $this->links[self::key($userId, $issuer)] = $subject;
    }

    public function isReady(): bool
    {
        return $this->ready;
    }

    /** Plants a link without going through remember(), for "this account already exists" setups. */
    public function plant(string $userId, string $issuer, string $subject = 'subject-1'): void
    {
        $this->links[self::key($userId, $issuer)] = $subject;
    }

    private static function key(string $userId, string $issuer): string
    {
        return $userId . '|' . $issuer;
    }
}
