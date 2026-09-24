<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use Keyway\Sso\Core\Http\HttpResponse;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Port\HttpClientInterface;
use RuntimeException;

/**
 * The IdP, as far as the tests are concerned.
 *
 * Test double only. It exists so the reader suite never touches the network: a test that talks
 * to a real provider passes or fails on somebody else's uptime, and it cannot serve the hostile
 * discovery document or the rotated JWKS that half of section C is about.
 *
 * A route can be a fixed response, an exception to throw (transport failure), or a callable that
 * receives the posted form and decides - which is how the fake token endpoint checks the PKCE
 * verifier the way a real one does. Queued routes are served in order and the last one repeats,
 * so "the second fetch returns a rotated key set" is one line.
 */
final class FakeHttpClient implements HttpClientInterface
{
    /** @var array<string, list<HttpResponse|HttpTransportException|callable>> */
    private array $routes = [];

    /** @var list<array{method: string, url: string, form: array<string, string>, headers: array<string, string>}> */
    private array $requests = [];

    public function on(string $url, HttpResponse|HttpTransportException|callable $response): void
    {
        $this->routes[$url] = [$response];
    }

    public function queue(string $url, HttpResponse|HttpTransportException|callable $response): void
    {
        $this->routes[$url][] = $response;
    }

    public function onJson(string $url, array $document, int $status = 200): void
    {
        $this->on($url, self::json($document, $status));
    }

    public function queueJson(string $url, array $document, int $status = 200): void
    {
        $this->queue($url, self::json($document, $status));
    }

    public static function json(array $document, int $status = 200): HttpResponse
    {
        return new HttpResponse(
            $status,
            (string)json_encode($document, JSON_UNESCAPED_SLASHES),
            ['Content-Type' => 'application/json']
        );
    }

    public function get(string $url, array $headers = []): HttpResponse
    {
        return $this->serve('GET', $url, [], $headers);
    }

    public function postForm(string $url, array $form, array $headers = []): HttpResponse
    {
        return $this->serve('POST', $url, $form, $headers);
    }

    /**
     * How many times a URL was called - the measurement behind the C5 rate limit tests.
     */
    public function callCount(string $url): int
    {
        $count = 0;
        foreach ($this->requests as $request) {
            if ($request['url'] === $url) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * @return array{method: string, url: string, form: array<string, string>, headers: array<string, string>}|null
     */
    public function lastRequest(string $url): ?array
    {
        for ($i = count($this->requests) - 1; $i >= 0; $i--) {
            if ($this->requests[$i]['url'] === $url) {
                return $this->requests[$i];
            }
        }

        return null;
    }

    /**
     * @param array<string, string> $form
     * @param array<string, string> $headers
     */
    private function serve(string $method, string $url, array $form, array $headers): HttpResponse
    {
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'form' => $form,
            'headers' => $headers,
        ];

        if (!isset($this->routes[$url]) || $this->routes[$url] === []) {
            throw new RuntimeException('No fake route for ' . $url);
        }

        $response = count($this->routes[$url]) > 1
            ? array_shift($this->routes[$url])
            : $this->routes[$url][0];

        if ($response instanceof HttpTransportException) {
            throw $response;
        }

        if ($response instanceof HttpResponse) {
            return $response;
        }

        return $response($form, $headers);
    }
}
