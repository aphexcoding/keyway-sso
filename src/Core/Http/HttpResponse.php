<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Http;

/**
 * What came back from a back-channel call. Immutable, protocol-agnostic, no vendor types.
 *
 * Deliberately dumb: it carries bytes and a status, and it does not decode anything. The layer
 * that knows what a document is supposed to look like does the decoding, so a JSON parse error
 * ends up as a protocol rejection with a reason code instead of a stray warning.
 */
final class HttpResponse
{
    public readonly int $statusCode;
    public readonly string $body;

    /** @var array<string, string> lowercased header name => value */
    private array $headers;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(int $statusCode, string $body, array $headers = [])
    {
        $this->statusCode = $statusCode;
        $this->body = $body;

        $normalised = [];
        foreach ($headers as $name => $value) {
            $normalised[strtolower(trim((string)$name))] = trim((string)$value);
        }
        $this->headers = $normalised;
    }

    public function isSuccessful(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower(trim($name))] ?? null;
    }

    /**
     * Media type without parameters, lowercased: `application/json` from
     * `application/json; charset=utf-8`.
     */
    public function mediaType(): ?string
    {
        $contentType = $this->header('content-type');
        if ($contentType === null || $contentType === '') {
            return null;
        }

        $type = explode(';', $contentType, 2)[0];

        return strtolower(trim($type));
    }
}
