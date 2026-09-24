<?php

declare(strict_types=1);

use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Test\Support\Assert;

return [
    'single values become one-element lists' => static function (): void {
        $payload = new IdentityPayload('jan', ['email' => 'jan@example.com']);
        Assert::sameList(['jan@example.com'], $payload->values('email'));
    },

    'multi-valued attributes are preserved in order' => static function (): void {
        $payload = new IdentityPayload('jan', ['groups' => ['editors', 'admins']]);
        Assert::sameList(['editors', 'admins'], $payload->values('groups'));
    },

    'lookup falls back to case-insensitive match' => static function (): void {
        $payload = new IdentityPayload('jan', ['EmailAddress' => 'jan@example.com']);
        Assert::sameList(['jan@example.com'], $payload->values('emailaddress'));
        Assert::true($payload->has('EMAILADDRESS'));
    },

    'exact match wins over case-insensitive match' => static function (): void {
        $payload = new IdentityPayload('jan', [
            'mail' => 'exact@example.com',
            'MAIL' => 'variant@example.com',
        ]);
        Assert::sameList(['exact@example.com'], $payload->values('mail'));
        Assert::sameList(['variant@example.com'], $payload->values('MAIL'));
    },

    'first declaration wins for the case-insensitive index' => static function (): void {
        $payload = new IdentityPayload('jan', [
            'Mail' => 'first@example.com',
            'MAIL' => 'second@example.com',
        ]);
        Assert::sameList(['first@example.com'], $payload->values('mail'));
    },

    'unknown attribute returns an empty list, not null' => static function (): void {
        $payload = new IdentityPayload('jan');
        Assert::sameList([], $payload->values('nothing'));
        Assert::false($payload->has('nothing'));
    },

    'nulls are dropped and booleans stringified' => static function (): void {
        $payload = new IdentityPayload('jan', ['flags' => [null, true, false, 7, 'x']]);
        Assert::sameList(['true', 'false', '7', 'x'], $payload->values('flags'));
    },

    'nested arrays are dropped instead of being cast to "Array"' => static function (): void {
        $payload = new IdentityPayload('jan', ['weird' => [['nested'], 'ok']]);
        Assert::sameList(['ok'], $payload->values('weird'));
    },

    'empty attribute name is rejected' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new IdentityPayload('jan', ['   ' => 'x'])
        );
    },

    'nameId and issuer are trimmed' => static function (): void {
        $payload = new IdentityPayload("  jan  ", [], "  https://idp.example.com  ");
        Assert::same('jan', $payload->nameId());
        Assert::same('https://idp.example.com', $payload->issuer());
    },
];
