<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use craft\web\Application;

/**
 * The smallest `Craft::$app` that lets CraftSignIn be exercised for real, installed and removed
 * around a single test case.
 *
 * WHY A GLOBAL IS TOUCHED AT ALL, in a plugin whose tests assert that `Craft::$app` is never
 * read. CraftSignIn genuinely does not read it - `craft_signin_contract` checks that by parsing
 * the source, and that assertion stands. But the class calls `helpers\User::getAuthStatus()`
 * one step before the control-panel gate, and CRAFT'S helper reads `Craft::$app->getRequest()`
 * (helpers/User.php:47) for any account whose status is active. Reaching our own gate therefore
 * means getting through Craft's code, and Craft's code wants an application. The alternative was
 * a fixture disabled at the element level, which slips past getAuthStatus() without an
 * application but tests a state no real login is ever in.
 *
 * Install/restore is symmetric and the previous value is put back in a `finally`, so no case
 * leaks an application into the next file.
 */
final class StubCraftApplication extends Application
{
    public StubCraftRequest $stubRequest;

    /** What `getIsLive()` answers; Craft's own offline checks read this. */
    public bool $live;

    private mixed $previous = null;

    private function __construct(bool $live)
    {
        // Deliberately does not call parent::__construct(): no config, no components, no DB.
        $this->stubRequest = new StubCraftRequest();
        $this->live = $live;
    }

    public static function install(bool $systemIsLive = true): self
    {
        self::loadCraftClass();

        $app = new self($systemIsLive);
        $app->previous = \Craft::$app ?? null;
        \Craft::$app = $app;

        return $app;
    }

    public function restore(): void
    {
        \Craft::$app = $this->previous;
    }

    public function getRequest()
    {
        return $this->stubRequest;
    }

    public function getIsLive(): bool
    {
        return $this->live;
    }

    /**
     * `Craft` is a plain global class in `src/Craft.php`, outside the `craft\` PSR-4 prefix, so
     * Composer's autoloader never loads it - Craft's own bootstrap requires it by hand, and so
     * does this. Requiring Yii.php first is what makes `class Craft extends Yii` resolvable.
     */
    private static function loadCraftClass(): void
    {
        if (class_exists(\Craft::class, false)) {
            return;
        }

        $vendor = dirname(__DIR__, 2) . '/vendor';

        require_once $vendor . '/yiisoft/yii2/Yii.php';
        require_once $vendor . '/craftcms/cms/src/Craft.php';
    }
}
