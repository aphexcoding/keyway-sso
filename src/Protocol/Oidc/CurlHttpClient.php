<?php

declare(strict_types=1);

namespace Keyway\Sso\Protocol\Oidc;

use CurlHandle;
use Keyway\Sso\Core\Http\HttpResponse;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Core\Port\HttpClientInterface;

/**
 * The production back-channel: ext-curl, HTTPS only, no way to turn the safety off.
 *
 * Written here rather than taken from a library on purpose. league/oauth2-client 2.9.0 does its
 * HTTP through a Guzzle client that the integrator may replace
 * (AbstractProvider::setHttpClient(), src/Provider/AbstractProvider.php:235), and Guzzle's
 * `verify` option is a constructor array away from `false`. The JWKS is the root of trust for
 * every id token this plugin accepts, so the one thing that must not be configurable is whether
 * we check who served it.
 *
 * What is nailed down, and why each one matters:
 *  - CURLOPT_SSL_VERIFYPEER / VERIFYHOST: on, always. There is no constructor flag, no setting
 *    and no environment variable that changes this. Without it, anyone on the path between the
 *    site and the IdP can serve their own JWKS and mint identities.
 *  - HTTPS only (CURLOPT_PROTOCOLS, the bitmask form — the `_STR` constants only exist from
 *    PHP 8.3 and the plugin supports 8.2): a plain-HTTP back-channel call would hand the same
 *    power to anyone on the path, and a token endpoint call would leak the client secret.
 *  - No redirect following: a 302 is the cheapest way to move a back-channel request from the
 *    configured issuer to somewhere else. Nothing in OIDC discovery needs one.
 *  - Two timeouts: a connect timeout and a total timeout, so an IdP that accepts the connection
 *    and then goes quiet cannot pin a PHP worker until the request limit.
 *  - A response size cap enforced in the write callback, not after the fact: a hostile endpoint
 *    that streams gigabytes must not be able to exhaust memory before we notice.
 *
 * Non-2xx is a normal return value (the token endpoint reports `invalid_grant` as 400 with a
 * JSON body the caller needs to read). Only transport failures throw.
 */
final class CurlHttpClient implements HttpClientInterface
{
    public const DEFAULT_CONNECT_TIMEOUT = 5;
    public const DEFAULT_TIMEOUT = 10;

    /** 512 KiB is roomy for a discovery document or a JWKS and far below anything that hurts. */
    public const MAX_RESPONSE_BYTES = 524288;

    private int $connectTimeout;
    private int $timeout;
    private int $maxBytes;
    private string $userAgent;

    public function __construct(
        int $connectTimeout = self::DEFAULT_CONNECT_TIMEOUT,
        int $timeout = self::DEFAULT_TIMEOUT,
        int $maxBytes = self::MAX_RESPONSE_BYTES,
        string $userAgent = 'Keyway-SSO/1.0'
    ) {
        // Clamped rather than validated: a caller that asks for "no timeout" gets the ceiling,
        // because an unbounded back-channel call is a denial of service against our own site.
        $this->connectTimeout = max(1, min($connectTimeout, 30));
        $this->timeout = max(1, min($timeout, 30));
        $this->maxBytes = max(1024, min($maxBytes, self::MAX_RESPONSE_BYTES));
        $this->userAgent = $userAgent;
    }

    /**
     * @param array<string, string> $headers
     */
    public function get(string $url, array $headers = []): HttpResponse
    {
        return $this->send($url, null, $headers);
    }

    /**
     * @param array<string, string> $form
     * @param array<string, string> $headers
     */
    public function postForm(string $url, array $form, array $headers = []): HttpResponse
    {
        $headers['Content-Type'] = 'application/x-www-form-urlencoded';

        // http_build_query does RFC 1738 encoding; RFC 6749 wants application/x-www-form-
        // urlencoded, which is the same thing for the character set the parameters use here.
        return $this->send($url, http_build_query($form, '', '&', PHP_QUERY_RFC1738), $headers);
    }

    /**
     * @param array<string, string> $headers
     */
    private function send(string $url, ?string $body, array $headers): HttpResponse
    {
        if (strtolower((string)parse_url($url, PHP_URL_SCHEME)) !== 'https') {
            throw new HttpTransportException(
                'Refusing a back-channel call over anything but https.'
            );
        }

        $handle = curl_init();
        if (!$handle instanceof CurlHandle) {
            throw new HttpTransportException('curl could not be initialised.');
        }

        $responseBody = '';
        $responseHeaders = [];
        $tooLarge = false;

        $options = $this->options($url, $body, $headers, $responseBody, $responseHeaders, $tooLarge);

        curl_setopt_array($handle, $options);
        $ok = curl_exec($handle);
        $error = curl_error($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        if ($tooLarge) {
            throw new HttpTransportException(sprintf(
                'Response from the identity provider exceeded %d bytes.',
                $this->maxBytes
            ));
        }

        if ($ok === false) {
            throw new HttpTransportException('Back-channel request failed: ' . $error);
        }

        return new HttpResponse($status, $responseBody, $responseHeaders);
    }


    /**
     * Every curl option this client will ever set, in one place so that it can be measured.
     *
     * Extracted deliberately: certificate verification, the https-only protocol list, the
     * refusal to follow redirects and the response cap are the four properties that make this
     * client safe, and a property nobody can assert on is a property nobody can defend in a
     * review. There is no code path that builds options any other way.
     *
     * @param array<string, string> $headers
     * @return array<int, mixed>
     */
    private function options(
        string $url,
        ?string $body,
        array $headers,
        string &$responseBody,
        array &$responseHeaders,
        bool &$tooLarge
    ): array {
        $maxBytes = $this->maxBytes;

        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => self::formatHeaders($headers),
            CURLOPT_WRITEFUNCTION => static function ($_handle, string $chunk) use (
                &$responseBody,
                &$tooLarge,
                $maxBytes
            ): int {
                $responseBody .= $chunk;

                if (strlen($responseBody) > $maxBytes) {
                    $tooLarge = true;

                    // Returning anything other than the chunk length aborts the transfer.
                    return 0;
                }

                return strlen($chunk);
            },
            CURLOPT_HEADERFUNCTION => static function ($_handle, string $line) use (
                &$responseHeaders
            ): int {
                $length = strlen($line);
                $parts = explode(':', $line, 2);

                if (count($parts) === 2) {
                    $responseHeaders[trim($parts[0])] = trim($parts[1]);
                }

                return $length;
            },
        ];

        if ($body !== null) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $body;
        }

        return $options;
    }

    /**
     * @param array<string, string> $headers
     * @return list<string>
     */
    private static function formatHeaders(array $headers): array
    {
        $out = ['Accept: application/json'];

        foreach ($headers as $name => $value) {
            $name = trim((string)$name);
            $value = trim((string)$value);

            // A newline in a header value is header injection; drop rather than sanitise.
            if ($name === '' || preg_match('/[\r\n]/', $name . $value) === 1) {
                continue;
            }

            $out[] = $name . ': ' . $value;
        }

        return $out;
    }
}
