<?php

declare(strict_types=1);

namespace Keyway\Sso\Adapter;

use InvalidArgumentException;
use Keyway\Sso\Core\Provisioning\AccountStatus;
use Keyway\Sso\Core\Provisioning\ExistingUser;
use Keyway\Sso\Core\Support\Ascii;

/**
 * The two decisions inside CraftUserDirectory, extracted so they can be tested.
 *
 * Neither of them is arithmetic. One decides whether a row Craft handed back is really the
 * account that was asked for; the other decides what the core is told about that account, and
 * UserDirectoryInterface is explicit that getting it wrong is how single sign-on reinstates
 * somebody an administrator deprovisioned on purpose. Both therefore take plain scalars and no
 * Craft objects, so they run in the suite with no vendor directory at all - which is worth
 * something, because the rules they hold are rules about security, not about Craft.
 *
 * An earlier version of this comment claimed the logic HAD to live here because a Craft user
 * cannot be built outside a booted application. That was wrong and is corrected on the record:
 * `new craft\elements\User()` does die instantiating craft\behaviors\CustomFieldBehavior, but
 * ReflectionClass::newInstanceWithoutConstructor() does not, and CraftUserDirectory is tested
 * against real User objects in test/craft_user_directory_test.php. The split stays because it
 * is the better shape, not because the alternative was impossible.
 */
final class CraftUserSnapshot
{
    private function __construct()
    {
    }

    /**
     * Craft's account status, mapped 1:1 onto the four the core models.
     *
     * The four names are Craft's own (craft\elements\User::STATUS_* at
     * vendor/craftcms/cms/src/elements/User.php:154-157) and getStatus() derives them from the
     * `suspended` / `archived` / `pending` / `active` flags in that order (User.php:1683-1708).
     *
     * ANYTHING ELSE BECOMES Inactive. getStatus() can also answer with the element-level states
     * 'disabled' and 'archived' (craft\base\Element::STATUS_* at Element.php:182-184), and a
     * future Craft may add more. Inactive is the fail-closed answer because AccountStatus::
     * Inactive->allowsSignIn() is false: an account in a state we do not understand does not get
     * signed in. The alternative - defaulting to Active - is the exact bug the port warns about.
     *
     * 'locked' is a Craft constant (User.php:158) that getStatus() never returns; lockout is
     * carried separately by the `locked` property and reaches the core as ExistingUser::$isLocked.
     * It is mapped here anyway, to Inactive, so that a Craft that starts returning it fails shut.
     */
    public static function status(?string $craftStatus): AccountStatus
    {
        return match ($craftStatus) {
            'active' => AccountStatus::Active,
            'pending' => AccountStatus::Pending,
            'suspended' => AccountStatus::Suspended,
            default => AccountStatus::Inactive,
        };
    }

    /**
     * Did the column we asked about actually match?
     *
     * craft\services\Users::getUserByUsernameOrEmail() matches `username` OR `email`
     * (vendor/craftcms/cms/src/services/Users.php:272-299). Left unchecked, findByEmail('a@b.c')
     * would happily return an account whose USERNAME is 'a@b.c' and whose e-mail belongs to
     * somebody else - and the core would then treat that account as the owner of the address
     * the identity provider just asserted. So the answer is re-read from the column that was
     * asked for, and a hit on the other column is reported as no hit at all.
     *
     * The fold is ASCII-only, matching Core\Support\Ascii, which the core uses everywhere else -
     * the adapter must not be looser than the layer it feeds. Consequence, stated rather than
     * hidden: Craft's own lookup can be broader (Postgres lower-cases with mb_strtolower;
     * MySQL's default collation is accent-insensitive), so an identifier differing only by the
     * case of a non-ASCII letter, or only by an accent, is a row Craft finds and this method
     * rejects. That ends in "no such account" - a duplicate account at worst, never a login into
     * somebody else's.
     */
    public static function matchesIdentifier(string $wanted, ?string $columnValue): bool
    {
        $wanted = Ascii::trim($wanted);
        $columnValue = Ascii::trim((string)$columnValue);

        if ($wanted === '' || $columnValue === '') {
            return false;
        }

        return Ascii::equalsIgnoreCase($wanted, $columnValue);
    }

    /**
     * Builds the whole ExistingUser - every field, no permissive default.
     *
     * Property sources, so a Craft upgrade that renames one breaks here and not at login time:
     * `id` (craft\base\ElementTrait:38), `email` (User.php:697), `username` (User.php:691),
     * `admin` (User.php:685), `locked` (User.php:673), status via User::getStatus().
     *
     * @param int|null    $id          Craft's element id; null means an unsaved element, which
     *                                 cannot come out of a query and must not be papered over.
     * @param string|null $craftStatus The result of User::getStatus().
     */
    public static function map(
        ?int $id,
        ?string $email,
        ?string $username,
        bool $isAdmin,
        ?string $craftStatus,
        bool $isLocked
    ): ExistingUser {
        if ($id === null) {
            throw new InvalidArgumentException(
                'A Craft user loaded from the database always has an id; refusing to describe an '
                . 'unsaved element as an existing account.'
            );
        }

        return new ExistingUser(
            (string)$id,
            (string)$email,
            (string)$username,
            $isAdmin,
            self::status($craftStatus),
            $isLocked
        );
    }
}
