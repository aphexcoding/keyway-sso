<?php

declare(strict_types=1);

use Keyway\Sso\Adapter\CraftSignIn;
use Keyway\Sso\Test\Support\Assert;

/**
 * The Craft API surface CraftSignIn writes against, pinned by reflection.
 *
 * CraftSignIn cannot be exercised without a database - `saveElement()` needs one - and that is a
 * real limit, honestly stated. It is NOT a reason to check nothing: the class rests on a set of
 * signatures and property types from `craftcms/cms`, and those can change under a
 * `composer update` inside the `^5.0` range. Today nothing would notice; the first person to
 * find out would be a client whose administrators stop being able to sign in.
 *
 * So this file asserts the contract, not the behaviour: the methods exist, take what this class
 * passes them and return what it believes. It is the same mechanism as
 * `sso_controller :: the login screen hook this plugin uses still exists in Craft`, which reads
 * Craft's own template to catch the hook being removed.
 *
 * WHAT IT DOES NOT COVER, so that a green line is not mistaken for coverage: that a user is
 * actually created, that group membership lands in the database, that a session starts. Those
 * are the acceptance test.
 */
if (!class_exists(\craft\elements\User::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'craft_signin_contract', 'skipped: vendor absent (run composer install)'));

    return [];
}

/** @return array{0: string, 1: string|null, 2: bool} [type name, class name or null, nullable] */
$typeOf = static function (?ReflectionType $type): array {
    if (!$type instanceof ReflectionNamedType) {
        return ['', null, false];
    }

    return [$type->getName(), $type->isBuiltin() ? null : $type->getName(), $type->allowsNull()];
};

return [
    // Asked before the session starts, exactly as craft\services\Sso::loginUser() does. Null
    // means "no objection"; anything else is a refusal with the reason in it.
    'helpers\User::getAuthStatus(User): ?string' => static function () use ($typeOf): void {
        $method = new ReflectionMethod(\craft\helpers\User::class, 'getAuthStatus');

        Assert::true($method->isStatic() && $method->isPublic());
        Assert::same(1, $method->getNumberOfParameters());
        Assert::same(
            \craft\elements\User::class,
            $typeOf($method->getParameters()[0]->getType())[1]
        );

        [$name, , $nullable] = $typeOf($method->getReturnType());
        Assert::same('string', $name);
        Assert::true($nullable, 'null is how this helper says "no objection"');
    },

    // The explicit control-panel check. getAuthStatus() only asks this inside its
    // `getIsCpRequest()` branch, and the canonical callback URL is an action URL, which is not
    // a control panel request - so CraftSignIn asks directly and needs this signature to hold.
    'elements\User::can(string): bool' => static function () use ($typeOf): void {
        $method = new ReflectionMethod(\craft\elements\User::class, 'can');

        Assert::same('string', $typeOf($method->getParameters()[0]->getType())[0]);
        Assert::same('bool', $typeOf($method->getReturnType())[0]);
    },

    // Replaces the whole set, which is why Core\Group\GroupSync merges with the existing
    // membership FIRST. A signature that started taking handles, or a partial-update semantic,
    // would silently change what "append" means.
    'services\Users::assignUserToGroups(int, array): bool' => static function () use ($typeOf): void {
        $method = new ReflectionMethod(\craft\services\Users::class, 'assignUserToGroups');
        $parameters = $method->getParameters();

        Assert::same(2, count($parameters));
        Assert::same('int', $typeOf($parameters[0]->getType())[0], 'a user id, not an element');
        Assert::same('array', $typeOf($parameters[1]->getType())[0], 'group IDs, not handles');
        Assert::same('bool', $typeOf($method->getReturnType())[0]);
    },

    'services\Users::getUserById(int): ?User' => static function () use ($typeOf): void {
        $method = new ReflectionMethod(\craft\services\Users::class, 'getUserById');

        Assert::same('int', $typeOf($method->getParameters()[0]->getType())[0]);
        [, $class, $nullable] = $typeOf($method->getReturnType());
        Assert::same(\craft\elements\User::class, $class);
        Assert::true($nullable, 'a deleted account has to come back as null, not as an exception');
    },

    // Handle -> id, and null for a handle this site does not have. CraftSignIn turns that null
    // into a note rather than a refusal: one typo in the group table must not lock everybody out.
    'services\UserGroups::getGroupByHandle(string): ?UserGroup' => static function () use ($typeOf): void {
        $method = new ReflectionMethod(\craft\services\UserGroups::class, 'getGroupByHandle');

        Assert::same('string', $typeOf($method->getParameters()[0]->getType())[0]);
        [, $class, $nullable] = $typeOf($method->getReturnType());
        Assert::same(\craft\models\UserGroup::class, $class);
        Assert::true($nullable);
    },

    'elements\User::getGroups(): array' => static function () use ($typeOf): void {
        $method = new ReflectionMethod(\craft\elements\User::class, 'getGroups');

        Assert::same(0, $method->getNumberOfParameters());
        Assert::same('array', $typeOf($method->getReturnType())[0]);
        Assert::true(
            property_exists(\craft\models\UserGroup::class, 'handle'),
            'the merge in GroupSync is done on handles'
        );
    },

    // `$active` may only be set on a NEW element - afterSave() throws "Unable to change a user's
    // active state like this" otherwise - and `$admin` is written on every save. Both are plain
    // bool properties today; a change to either shape is a change to what this class may touch.
    'elements\User::$active and $admin are writable bools' => static function () use ($typeOf): void {
        foreach (['active', 'admin'] as $name) {
            $property = new ReflectionProperty(\craft\elements\User::class, $name);

            Assert::true($property->isPublic(), $name . ' is assigned directly');
            Assert::false($property->isReadOnly(), $name . ' is still writable');
            Assert::same('bool', $typeOf($property->getType())[0], $name . ' is a bool');
        }
    },

    // The five identity fields Core\Attribute\UserField allows a mapping to write. A target that
    // stopped being a property would be assigned into Yii's magic setter and land nowhere.
    'the mapped identity fields are real properties on the user element' => static function (): void {
        foreach (['email', 'username', 'firstName', 'lastName', 'fullName'] as $field) {
            Assert::true(
                property_exists(\craft\elements\User::class, $field),
                $field . ' is a property, not a magic attribute'
            );
        }
    },

    // The session start and the return URL fallback.
    'web\User::login(), getReturnUrl() and removeReturnUrl() are where this class expects them' =>
        static function () use ($typeOf): void {
            $login = new ReflectionMethod(\craft\web\User::class, 'login');
            Assert::same(2, $login->getNumberOfParameters());
            Assert::same('bool', $typeOf($login->getReturnType())[0], 'false means "no session"');

            $return = new ReflectionMethod(\craft\web\User::class, 'getReturnUrl');
            Assert::same('string', $typeOf($return->getReturnType())[0], 'never null, so it is a usable fallback');

            Assert::true(method_exists(\craft\web\User::class, 'removeReturnUrl'));
        },

    // The class only ever touches Craft through the five collaborators it is given.
    'CraftSignIn takes its collaborators and never reaches for the application' =>
        static function (): void {
            $code = '';
            foreach (token_get_all((string)file_get_contents(
                (string)(new ReflectionClass(CraftSignIn::class))->getFileName()
            )) as $token) {
                if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                $code .= is_array($token) ? $token[1] : $token;
            }

            Assert::notContains('Craft::', $code, 'the services arrive as arguments, from Plugin');
            Assert::contains('Craft::$app->getIsLive()', (string)file_get_contents(
                dirname(__DIR__) . '/src/Plugin.php'
            ));
        },
];
