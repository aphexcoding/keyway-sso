<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\elements\User;
use ReflectionClass;

/**
 * Builds a real craft\elements\User outside a booted Craft.
 *
 * `new User()` cannot do this - it dies instantiating craft\behaviors\CustomFieldBehavior - and
 * an earlier turn concluded from that the adapter was simply untestable. It was wrong:
 * newInstanceWithoutConstructor() skips the behaviour wiring, every property the adapter reads
 * is public, and User::getStatus() (vendor/craftcms/cms/src/elements/User.php:1683-1708) then
 * derives the status from those flags for real, without touching the application.
 *
 * That matters because the status is not a value the adapter copies - it is a value Craft
 * COMPUTES, and it is computed in the order suspended, archived, pending, active. A fixture that
 * set the string directly would test our own opinion of that order instead of Craft's.
 */
final class CraftUserFixture
{
    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $properties Public properties of User / ElementTrait.
     */
    public static function make(array $properties): User
    {
        $user = (new ReflectionClass(User::class))->newInstanceWithoutConstructor();

        foreach ($properties as $name => $value) {
            $user->$name = $value;
        }

        return $user;
    }
}
