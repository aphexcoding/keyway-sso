<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Keyway\Sso\Core\Http\HttpTransportException;
use Keyway\Sso\Protocol\Oidc\CurlHttpClient;
use Keyway\Sso\Test\Support\Assert;

/**
 * The back-channel transport, measured without a network.
 *
 * The turn 4 review was right that "it would need a TLS server" was too broad an excuse: the
 * scheme gate rejects before curl is ever initialised, the timeouts are clamped in the
 * constructor, and the option table is now built by one method that can simply be read back.
 * What still has no test here is the behaviour of a real TLS handshake - these cases prove the
 * client ASKS curl for the right things, not that curl honours them.
 */
if (!class_exists(JWT::class)) {
    fwrite(STDOUT, "oidc_http_client           skipped: vendor absent (run composer install)\n");

    return [];
}

/**
 * @param array<string, string> $headers
 * @return array<int, mixed>
 */
$options = static function (CurlHttpClient $client, string $url, ?string $body = null, array $headers = []): array {
    $method = new ReflectionMethod($client, 'options');
    $method->setAccessible(true);

    $responseBody = '';
    $responseHeaders = [];
    $tooLarge = false;

    return $method->invokeArgs(
        $client,
        [$url, $body, $headers, &$responseBody, &$responseHeaders, &$tooLarge]
    );
};

return [
    'anything that is not https is refused before curl is even initialised' =>
        static function (): void {
            $client = new CurlHttpClient();

            foreach ([
                'http://idp.example.test/certs',
                'ftp://idp.example.test/certs',
                'file:///etc/passwd',
                'gopher://idp.example.test/',
                '',
            ] as $url) {
                $error = Assert::throws(
                    HttpTransportException::class,
                    static fn () => $client->get($url),
                    'scheme ' . $url
                );

                // The message is asserted because "it threw" does not isolate the gate: with the
                // scheme check removed, curl itself fails on these URLs and throws the same
                // exception class. Only this sentence proves we never left the process.
                Assert::contains('anything but https', $error->getMessage(), 'scheme ' . $url);
            }
        },

    'certificate verification, the protocol list and redirects are not negotiable' =>
        static function () use ($options): void {
            $table = $options(new CurlHttpClient(), 'https://idp.example.test/certs');

            Assert::same(true, $table[CURLOPT_SSL_VERIFYPEER], 'peer verification');
            Assert::same(2, $table[CURLOPT_SSL_VERIFYHOST], 'host verification');
            Assert::same(CURLPROTO_HTTPS, $table[CURLOPT_PROTOCOLS]);
            Assert::same(CURLPROTO_HTTPS, $table[CURLOPT_REDIR_PROTOCOLS]);
            Assert::same(false, $table[CURLOPT_FOLLOWLOCATION], 'a redirect is an SSRF pivot');
            Assert::same(0, $table[CURLOPT_MAXREDIRS]);
            Assert::true(is_callable($table[CURLOPT_WRITEFUNCTION]), 'the size cap lives here');
        },

    'the response size cap aborts the transfer instead of growing the buffer' =>
        static function () use ($options): void {
            $client = new CurlHttpClient(5, 10, 2048);
            $table = $options($client, 'https://idp.example.test/certs');
            $write = $table[CURLOPT_WRITEFUNCTION];

            Assert::same(1024, $write(null, str_repeat('a', 1024)), 'normal chunk is consumed');
            Assert::same(0, $write(null, str_repeat('a', 4096)), 'past the cap curl is told to stop');
        },

    'timeouts are clamped rather than trusted' =>
        static function () use ($options): void {
            $table = $options(new CurlHttpClient(0, 9999, 99999999), 'https://idp.example.test/certs');

            Assert::same(1, $table[CURLOPT_CONNECTTIMEOUT], 'an unbounded connect is a DoS on us');
            Assert::same(30, $table[CURLOPT_TIMEOUT]);
            Assert::same(CurlHttpClient::MAX_RESPONSE_BYTES, (new ReflectionProperty(CurlHttpClient::class, 'maxBytes'))
                ->getValue(new CurlHttpClient(5, 10, 99999999)));
        },

    'a header value carrying CRLF is dropped, not sanitised' =>
        static function () use ($options): void {
            $table = $options(
                new CurlHttpClient(),
                'https://idp.example.test/userinfo',
                null,
                [
                    'Authorization' => "Bearer token\r\nX-Injected: yes",
                    'X-Fine' => 'value',
                ]
            );

            $headers = $table[CURLOPT_HTTPHEADER];
            Assert::sameList(['Accept: application/json', 'X-Fine: value'], $headers);
        },

    'a form post is the only shape a token request takes' =>
        static function () use ($options): void {
            $table = $options(
                new CurlHttpClient(),
                'https://idp.example.test/token',
                'grant_type=authorization_code&code=abc',
                ['Content-Type' => 'application/x-www-form-urlencoded']
            );

            Assert::same(true, $table[CURLOPT_POST]);
            Assert::same('grant_type=authorization_code&code=abc', $table[CURLOPT_POSTFIELDS]);
        },
];
