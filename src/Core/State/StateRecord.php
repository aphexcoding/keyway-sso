<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\State;

/**
 * The server-side half of a login state token.
 *
 * Only the SHA-256 hash of the secret is stored. A dump of the cache or of the database table
 * therefore does not let anyone forge a valid RelayState / `state` value.
 */
final class StateRecord
{
    public readonly string $id;
    public readonly string $secretHash;
    public readonly string $returnUrl;
    public readonly int $createdAt;
    public readonly int $expiresAt;
    public readonly ?int $consumedAt;

    /** @var array<string, string> */
    private array $context;

    /**
     * @param array<string, string> $context Small, non-secret bookkeeping (connection handle,
     *                                       protocol) carried across the round trip.
     */
    public function __construct(
        string $id,
        string $secretHash,
        string $returnUrl,
        int $createdAt,
        int $expiresAt,
        array $context = [],
        ?int $consumedAt = null
    ) {
        $this->id = $id;
        $this->secretHash = $secretHash;
        $this->returnUrl = $returnUrl;
        $this->createdAt = $createdAt;
        $this->expiresAt = $expiresAt;
        $this->context = $context;
        $this->consumedAt = $consumedAt;
    }

    /** @return array<string, string> */
    public function context(): array
    {
        return $this->context;
    }

    public function isExpired(int $now): bool
    {
        return $now >= $this->expiresAt;
    }

    public function isConsumed(): bool
    {
        return $this->consumedAt !== null;
    }

    public function withConsumedAt(int $consumedAt): self
    {
        return new self(
            $this->id,
            $this->secretHash,
            $this->returnUrl,
            $this->createdAt,
            $this->expiresAt,
            $this->context,
            $consumedAt
        );
    }
}
