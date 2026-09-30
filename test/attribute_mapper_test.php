<?php

declare(strict_types=1);

use Keyway\Sso\Core\Attribute\AttributeMap;
use Keyway\Sso\Core\Attribute\AttributeMapper;
use Keyway\Sso\Core\Attribute\AttributeMappingException;
use Keyway\Sso\Core\Attribute\AttributeRule;
use Keyway\Sso\Core\Attribute\AttributeTransform;
use Keyway\Sso\Core\Attribute\EmailNormalizer;
use Keyway\Sso\Core\Attribute\MultiValueStrategy;
use Keyway\Sso\Core\Attribute\UserField;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Test\Support\Assert;

$map = static fn (array $rules): AttributeMapper => new AttributeMapper(new AttributeMap($rules));

return [
    'maps a straightforward assertion' => static function () use ($map): void {
        $mapper = $map([
            AttributeRule::required('mail', UserField::EMAIL),
            AttributeRule::optional('givenName', UserField::FIRST_NAME),
            AttributeRule::optional('sn', UserField::LAST_NAME),
        ]);

        $result = $mapper->map(new IdentityPayload('jan', [
            'mail' => 'Jan.Kowalski@Example.COM',
            'givenName' => 'Jan',
            'sn' => 'Kowalski',
        ]));

        Assert::same('jan.kowalski@example.com', $result->email());
        Assert::same('Jan', $result->get(UserField::FIRST_NAME));
        Assert::same('Kowalski', $result->get(UserField::LAST_NAME));
    },

    'missing required attributes are reported together' => static function () use ($map): void {
        $mapper = $map([
            AttributeRule::required('mail', UserField::EMAIL),
            AttributeRule::required('sn', UserField::LAST_NAME),
        ]);

        $error = Assert::throws(
            AttributeMappingException::class,
            static fn () => $mapper->map(new IdentityPayload('jan', ['givenName' => 'Jan']))
        );

        Assert::same(AttributeMappingException::MISSING_REQUIRED, $error->reasonCode());
        Assert::sameList(['mail', 'sn'], $error->attributes());
        Assert::contains('mail, sn', $error->getMessage());
    },

    'an attribute present but blank counts as missing' => static function () use ($map): void {
        $mapper = $map([AttributeRule::required('mail', UserField::EMAIL)]);

        $error = Assert::throws(
            AttributeMappingException::class,
            static fn () => $mapper->map(new IdentityPayload('jan', ['mail' => ['  ', '']]))
        );

        Assert::same(AttributeMappingException::MISSING_REQUIRED, $error->reasonCode());
    },

    'optional attribute without a default is left absent, not empty' => static function () use ($map): void {
        $mapper = $map([
            AttributeRule::required('mail', UserField::EMAIL),
            AttributeRule::optional('givenName', UserField::FIRST_NAME),
        ]);

        $result = $mapper->map(new IdentityPayload('jan', ['mail' => 'jan@example.com']));

        Assert::false($result->has(UserField::FIRST_NAME));
        Assert::null($result->get(UserField::FIRST_NAME));
        Assert::sameList(['givenName'], $result->skipped());
        Assert::sameList([UserField::EMAIL], array_keys($result->toArray()));
    },

    'default value is used when the IdP sends nothing' => static function () use ($map): void {
        $mapper = $map([
            AttributeRule::required('mail', UserField::EMAIL),
            AttributeRule::optional('department', 'field:department', 'unassigned'),
        ]);

        $result = $mapper->map(new IdentityPayload('jan', ['mail' => 'jan@example.com']));

        Assert::same('unassigned', $result->get('field:department'));
        Assert::sameList([], $result->skipped());
    },

    'multi-value strategies pick first, last and join' => static function () use ($map): void {
        $payload = new IdentityPayload('jan', [
            'mail' => 'jan@example.com',
            'roles' => ['alpha', 'beta', 'gamma'],
        ]);

        $first = $map([new AttributeRule('roles', 'field:role', MultiValueStrategy::First)])
            ->map($payload);
        $last = $map([new AttributeRule('roles', 'field:role', MultiValueStrategy::Last)])
            ->map($payload);
        $joined = $map([new AttributeRule(
            'roles',
            'field:role',
            MultiValueStrategy::Join,
            false,
            null,
            AttributeTransform::None,
            ', '
        )])->map($payload);

        Assert::same('alpha', $first->get('field:role'));
        Assert::same('gamma', $last->get('field:role'));
        Assert::same('alpha, beta, gamma', $joined->get('field:role'));
    },

    'join skips blank values instead of producing double separators' => static function () use ($map): void {
        $mapper = $map([new AttributeRule(
            'roles',
            'field:role',
            MultiValueStrategy::Join,
            false,
            null,
            AttributeTransform::None,
            '|'
        )]);

        $result = $mapper->map(new IdentityPayload('jan', ['roles' => ['a', '  ', 'b']]));

        Assert::same('a|b', $result->get('field:role'));
    },

    'last strategy uses the last non-blank value' => static function () use ($map): void {
        $mapper = $map([new AttributeRule('roles', 'field:role', MultiValueStrategy::Last)]);
        $result = $mapper->map(new IdentityPayload('jan', ['roles' => ['a', 'b', '   ']]));

        Assert::same('b', $result->get('field:role'));
    },

    'transforms apply to the mapped value' => static function () use ($map): void {
        $lower = $map([new AttributeRule(
            'dept',
            'field:dept',
            MultiValueStrategy::First,
            false,
            null,
            AttributeTransform::Lowercase
        )])->map(new IdentityPayload('jan', ['dept' => 'MarKeting']));

        $upper = $map([new AttributeRule(
            'dept',
            'field:dept',
            MultiValueStrategy::First,
            false,
            null,
            AttributeTransform::Uppercase
        )])->map(new IdentityPayload('jan', ['dept' => 'MarKeting']));

        Assert::same('marketing', $lower->get('field:dept'));
        Assert::same('MARKETING', $upper->get('field:dept'));
    },

    'pseudo-sources read the NameID and the issuer' => static function () use ($map): void {
        $mapper = $map([
            AttributeRule::required(AttributeRule::SOURCE_NAME_ID, UserField::EMAIL),
            AttributeRule::optional(AttributeRule::SOURCE_ISSUER, 'field:idp'),
        ]);

        $result = $mapper->map(new IdentityPayload(
            'JAN@example.com',
            [],
            'https://idp.example.com/realms/acme'
        ));

        Assert::same('jan@example.com', $result->email());
        Assert::same('https://idp.example.com/realms/acme', $result->get('field:idp'));
    },

    'a required NameID that is empty is reported as missing' => static function () use ($map): void {
        $mapper = $map([AttributeRule::required(AttributeRule::SOURCE_NAME_ID, UserField::EMAIL)]);

        $error = Assert::throws(
            AttributeMappingException::class,
            static fn () => $mapper->map(new IdentityPayload('   '))
        );

        Assert::sameList(['@nameId'], $error->attributes());
    },

    'an unusable e-mail is rejected with a dedicated reason' => static function () use ($map): void {
        $mapper = $map([AttributeRule::required('mail', UserField::EMAIL)]);

        $error = Assert::throws(
            AttributeMappingException::class,
            static fn () => $mapper->map(new IdentityPayload('jan', ['mail' => 'not-an-email']))
        );

        Assert::same(AttributeMappingException::INVALID_EMAIL, $error->reasonCode());
    },

    'e-mail is normalised even without an explicit transform' => static function () use ($map): void {
        $mapper = $map([AttributeRule::required('mail', UserField::EMAIL)]);
        $result = $mapper->map(new IdentityPayload('jan', ['mail' => '  JAN@EXAMPLE.COM ']));

        Assert::same('jan@example.com', $result->email());
    },

    'attribute values cannot be mapped onto access-granting fields' => static function (): void {
        foreach (['admin', 'Admin', 'groups', 'permissions', 'password', 'suspended'] as $target) {
            Assert::throws(
                InvalidArgumentException::class,
                static fn () => new AttributeRule('anything', $target),
                'target ' . $target
            );
        }
    },

    'anything outside the allow list is refused, not just the names we thought of' =>
        static function (): void {
            // Every one of these was ACCEPTED by the old deny list. `enabled` alone turns a
            // deliberately disabled account back on from an IdP attribute; the two counters
            // below reset Craft's brute-force lockout.
            foreach ([
                'enabled',
                'archived',
                'invalidLoginCount',
                'lockoutDate',
                'currentPassword',
                'pending',
                'photo',
                'preferredLanguage',
                'lastPasswordChangeDate',
                'anythingNobodyThoughtOf',
            ] as $target) {
                Assert::throws(
                    InvalidArgumentException::class,
                    static fn () => new AttributeRule('anything', $target),
                    'target ' . $target
                );
                Assert::false(UserField::isWritable($target), 'target ' . $target);
            }
        },

    'the allow list is exactly the five identity fields plus custom fields' =>
        static function (): void {
            Assert::sameList(
                [
                    UserField::EMAIL,
                    UserField::USERNAME,
                    UserField::FIRST_NAME,
                    UserField::LAST_NAME,
                    UserField::FULL_NAME,
                ],
                UserField::allowed()
            );

            foreach (UserField::allowed() as $target) {
                Assert::doesNotThrow(static fn () => new AttributeRule('x', $target), $target);
            }

            Assert::true(UserField::isWritable('field:employeeId'));
            Assert::false(UserField::isWritable(''));
            Assert::false(UserField::isWritable('   '));
        },

    'a differently cased target is canonicalised, not silently misfiled' =>
        static function (): void {
            $rule = new AttributeRule('mail', ' EMAIL ');

            Assert::same(UserField::EMAIL, $rule->target, 'or the mapping would write a key '
                . 'nothing ever reads');
            Assert::same(UserField::FIRST_NAME, (new AttributeRule('gn', 'firstname'))->target);
            Assert::same('field:Dept', (new AttributeRule('d', 'FIELD:Dept'))->target);
        },

    'the forbidden names still get an error that explains itself' => static function (): void {
        $error = Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('anything', 'admin')
        );

        Assert::contains('not allowed', $error->getMessage());
        Assert::contains('identity provider', $error->getMessage());

        $unknown = Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('anything', 'someInventedField')
        );

        Assert::contains('not a writable user field', $unknown->getMessage());
        Assert::contains('field:', $unknown->getMessage(), 'point the admin at custom fields');
    },

    'custom field handles are validated' => static function (): void {
        Assert::doesNotThrow(static fn () => new AttributeRule('x', 'field:employeeId'));
        Assert::doesNotThrow(static fn () => new AttributeRule('x', 'field:' . str_repeat('a', 64)));
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('x', 'field:9bad')
        );
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('x', 'field:with space')
        );
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('x', 'field:'),
            'an empty handle is not a field'
        );
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('x', 'field:' . str_repeat('a', 65)),
            'the handle length bound is real'
        );
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule('x', 'field:has-dash')
        );
    },

    'a rule cannot be required and defaulted at the same time' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule(
                'mail',
                UserField::EMAIL,
                MultiValueStrategy::First,
                true,
                'fallback@example.com'
            )
        );
    },

    'empty source and unknown pseudo-source are rejected' => static function (): void {
        Assert::throws(InvalidArgumentException::class, static fn () => new AttributeRule('  ', 'email'));
        Assert::throws(InvalidArgumentException::class, static fn () => new AttributeRule('@whatever', 'email'));
    },

    'join with an empty separator is rejected' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeRule(
                'roles',
                'field:role',
                MultiValueStrategy::Join,
                false,
                null,
                AttributeTransform::None,
                ''
            )
        );
    },

    'two rules writing the same field are rejected' => static function (): void {
        Assert::throws(
            InvalidArgumentException::class,
            static fn () => new AttributeMap([
                AttributeRule::optional('mail', UserField::EMAIL),
                AttributeRule::optional('userPrincipalName', 'Email'),
            ])
        );
    },

    'the shipped default map logs in a plain Okta assertion' => static function (): void {
        $mapper = new AttributeMapper(AttributeMap::defaults());
        $result = $mapper->map(new IdentityPayload('jan', [
            'email' => 'jan@example.com',
            'firstName' => 'Jan',
            'lastName' => 'Kowalski',
        ]));

        Assert::same('jan@example.com', $result->email());
        Assert::same('Jan', $result->get(UserField::FIRST_NAME));
    },

    'usernameOrEmail falls back to the address' => static function () use ($map): void {
        $withUsername = $map([
            AttributeRule::required('mail', UserField::EMAIL),
            AttributeRule::optional('uid', UserField::USERNAME),
        ])->map(new IdentityPayload('jan', ['mail' => 'jan@example.com', 'uid' => 'jkowalski']));

        $withoutUsername = $map([AttributeRule::required('mail', UserField::EMAIL)])
            ->map(new IdentityPayload('jan', ['mail' => 'jan@example.com']));

        Assert::same('jkowalski', $withUsername->usernameOrEmail());
        Assert::same('jan@example.com', $withoutUsername->usernameOrEmail());
    },

    'e-mail helpers behave on edge cases' => static function (): void {
        Assert::false(EmailNormalizer::isValid(''));
        Assert::false(EmailNormalizer::isValid("jan@example.com\r\nBcc: x@y.z"));
        Assert::false(EmailNormalizer::isValid(str_repeat('a', 250) . '@example.com'));
        Assert::true(EmailNormalizer::isValid('jan+craft@example.co.uk'));
        Assert::same('example.com', EmailNormalizer::domain('jan@Example.COM'));
        Assert::same('b.example.com', EmailNormalizer::domain('a@b@b.example.com'));
        Assert::null(EmailNormalizer::domain('nope'));
    },
];
