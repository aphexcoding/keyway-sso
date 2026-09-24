<?php

declare(strict_types=1);

/**
 * Keyway SSO core test runner.
 *
 * Usage:  php bin/test.php [name-filter]
 * Exit:   0 when every case passes, 1 otherwise.
 *
 * No PHPUnit on purpose: the core has zero Composer dependencies so that it can be built and
 * verified on a host without ext-dom/ext-mbstring, where `composer install` cannot run at all.
 */

require __DIR__ . '/../src/autoload.php';

// Composer is optional: the core has no dependencies and must stay testable on a host where
// `composer install` cannot run. Protocol suites detect the absence themselves and skip.
$vendorAutoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($vendorAutoload)) {
    require $vendorAutoload;
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'Keyway\\Sso\\Test\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $path = __DIR__ . '/../test/'
        . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

    if (is_file($path)) {
        require $path;
    }
});

use Keyway\Sso\Test\Support\Assert;

$filter = $argv[1] ?? '';
$files = glob(__DIR__ . '/../test/*_test.php');
sort($files);

$passed = 0;
$total = 0;
/** @var list<array{0: string, 1: Throwable}> $failures */
$failures = [];

foreach ($files as $file) {
    $cases = require $file;

    if (!is_array($cases)) {
        fwrite(STDERR, sprintf("Test file %s did not return an array of cases.\n", $file));
        exit(1);
    }

    $suite = basename($file, '_test.php');
    $suiteLine = '';

    foreach ($cases as $name => $case) {
        $label = $suite . ' :: ' . $name;

        if ($filter !== '' && !str_contains($label, $filter)) {
            continue;
        }

        $total++;

        try {
            $case();
            $passed++;
            $suiteLine .= '.';
        } catch (Throwable $error) {
            $failures[] = [$label, $error];
            $suiteLine .= 'F';
        }
    }

    if ($suiteLine !== '') {
        printf("%-26s %s\n", $suite, $suiteLine);
    }
}

echo "\n";

foreach ($failures as [$label, $error]) {
    printf("FAIL  %s\n", $label);
    printf("      %s: %s\n", $error::class, $error->getMessage());

    $frame = null;
    foreach ($error->getTrace() as $candidate) {
        if (isset($candidate['file']) && str_contains($candidate['file'], '/test/')) {
            $frame = $candidate;
            break;
        }
    }

    $file = $frame['file'] ?? $error->getFile();
    $line = $frame['line'] ?? $error->getLine();
    printf("      at %s:%d\n\n", basename((string)$file), (int)$line);
}

printf(
    "%d/%d PASS  (%d assertions, %d case(s) failed)\n",
    $passed,
    $total,
    Assert::count(),
    count($failures)
);

exit($failures === [] ? 0 : 1);
