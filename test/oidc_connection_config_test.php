<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Keyway\Sso\Protocol\Oidc\OidcConnectionConfig;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\OidcFixtures;

/**
 * The settings object, tested for what it REFUSES to let an administrator do.
 *
 * The class needs no Composer package to run, but it is skipped without one anyway: the
 * vendor-less run is meant to be a pure core run, and everything under Protocol\ belongs to the
 * protocol layer regardless of what it happens to import.
 */
if (!class_exists(JWT::class)) {
    fwrite(STDOUT, "oidc_connection_config     skipped: vendor absent (run composer install)\n");

    return [];
}

/**
 * @param array<int, mixed> $arguments
 */
$config = static function (array $arguments = []): OidcConnectionConfig {
    return new OidcConnectionConfig(
        $arguments[0] ?? OidcFixtures::ISSUER,
        $arguments[1] ?? OidcFixtures::CLIENT_ID,
        array_key_exists(2, $arguments) ? $arguments[2] : OidcFixtures::CLIENT_SECRET,
        $arguments[3] ?? OidcFixtures::REDIRECT_URI,
        $arguments[4] ?? ['openid', 'profile', 'email'],
        $arguments[5] ?? 60,
        $arguments[6] ?? false
    );
};

return [
    'the algorithm allow list is a constant, and no argument can widen it' =>
        static function (): void {
            Assert::sameList(['RS256', 'ES256'], OidcConnectionConfig::ALLOWED_ALGORITHMS);
            Assert::same('S256', OidcConnectionConfig::CODE_CHALLENGE_METHOD);

            // C1 says "fixed in code, not a runtime if". If a constructor parameter ever appears
            // that could soften either of them, this fails and the review happens.
            $parameters = [];
            foreach ((new ReflectionClass(OidcConnectionConfig::class))->getConstructor()?->getParameters() ?? [] as $parameter) {
                $parameters[] = strtolower($parameter->getName());
            }

            Assert::sameList(
                ['issuer', 'clientid', 'clientsecret', 'redirecturi', 'scopes', 'clockskew', 'fetchuserinfo'],
                $parameters,
                'a new constructor argument here needs a security review, not a merge'
            );
        },

    'an issuer that is not absolute https is refused' =>
        static function () use ($config): void {
            foreach ([
                'http://idp.example.test/realms/keyway',
                'https://idp.example.test/realms?tenant=a',
                'https://idp.example.test/realms#frag',
                '/realms/keyway',
                '',
            ] as $issuer) {
                Assert::throws(
                    InvalidArgumentException::class,
                    static fn () => $config([$issuer]),
                    'issuer ' . $issuer
                );
            }
        },

    'the issuer is stored byte for byte, because it is compared byte for byte' =>
        static function () use ($config): void {
            $withSlash = $config([OidcFixtures::ISSUER . '/']);

            Assert::same(OidcFixtures::ISSUER . '/', $withSlash->issuer);
            Assert::same(
                OidcFixtures::ISSUER . '/.well-known/openid-configuration',
                $withSlash->discoveryUrl(),
                'the well-known path is appended without doubling the slash'
            );
            Assert::same(
                OidcFixtures::ISSUER . '/.well-known/openid-configuration',
                $config()->discoveryUrl()
            );
        },

    'a redirect URI over plain http is refused' =>
        static function () use ($config): void {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => $config([null, null, null, 'http://craft.example.test/sso/callback'])
            );

            // A query string is fine there - Craft sites route through index.php?p=...
            Assert::doesNotThrow(
                static fn () => $config([null, null, null, 'https://craft.example.test/index.php?p=sso/callback'])
            );
        },

    'an empty client id or an empty secret string is refused' =>
        static function () use ($config): void {
            Assert::throws(InvalidArgumentException::class, static fn () => $config([null, '  ']));
            Assert::throws(InvalidArgumentException::class, static fn () => $config([null, null, '   ']));

            // Null is a public client, which is a supported configuration - PKCE is mandatory
            // either way, so there is no "no secret, no protection" case.
            $public = $config([null, null, null]);
            Assert::false($public->isConfidential());
            Assert::null($public->clientSecret);
            Assert::true($config()->isConfidential());
        },

    'clock skew is capped at the contract ceiling' =>
        static function () use ($config): void {
            Assert::same(120, OidcConnectionConfig::MAX_CLOCK_SKEW);
            Assert::same(60, $config()->clockSkew, 'the default is the strict end');

            Assert::throws(InvalidArgumentException::class, static fn () => $config([null, null, null, null, null, 121]));
            Assert::throws(InvalidArgumentException::class, static fn () => $config([null, null, null, null, null, -1]));
            Assert::doesNotThrow(static fn () => $config([null, null, null, null, null, 120]));
        },

    'openid is always requested, and a scope that would split the parameter is dropped' =>
        static function () use ($config): void {
            Assert::sameList(['openid', 'profile'], $config([null, null, null, null, ['profile']])->scopes());
            Assert::sameList(
                ['openid', 'profile'],
                $config([null, null, null, null, ['openid', 'profile', 'profile', 'bad scope', '']])->scopes()
            );
            Assert::same('openid profile email', $config()->scopeParameter());
        },

    'the settings cannot be changed after the reader was built' =>
        static function () use ($config): void {
            $instance = $config();

            Assert::throws(
                Error::class,
                static function () use ($instance): void {
                    /** @phpstan-ignore-next-line intentional: readonly is the point of the test */
                    $instance->issuer = 'https://evil.test';
                },
                'a settings object that can be mutated between two checks is not settings'
            );
        },
];
