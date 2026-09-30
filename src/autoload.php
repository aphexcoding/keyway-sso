<?php

declare(strict_types=1);

/**
 * Minimal PSR-4 autoloader for `Keyway\Sso\` -> `src/`.
 *
 * Production installs use Composer's autoloader (see composer.json). This file exists so the
 * core can be run and tested on a machine without Composer, and so `bin/test.php` has no
 * external dependency.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'Keyway\\Sso\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require $path;
    }
});
