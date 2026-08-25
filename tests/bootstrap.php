<?php

/**
 * Standalone PSR-4 autoloader for host-side pure tests, so the package can be
 * tested without composer install or booting Laravel:
 *
 *   php vendor/bin/phpunit --bootstrap packages/funnypot/tests/bootstrap.php \
 *     --no-configuration packages/funnypot/tests
 */

declare(strict_types=1);

// Prefer the package's own composer autoloader when present: it pulls in symfony/yaml
// (needed by the compiler tests) and the package PSR-4 map. The hand-rolled loader below
// stays as a fallback so pure DTO/normalizer tests still run without `composer install`.
$vendorAutoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($vendorAutoload)) {
    require $vendorAutoload;
}

spl_autoload_register(static function (string $class): void {
    $prefixes = [
        'Funnypot\Core\\Tests\\' => __DIR__ . '/',
        'Funnypot\Core\\' => __DIR__ . '/../src/',
    ];

    foreach ($prefixes as $prefix => $baseDir) {
        $len = strlen($prefix);
        if (strncmp($class, $prefix, $len) !== 0) {
            continue;
        }
        $relative = substr($class, $len);
        $file = $baseDir . str_replace('\\', '/', $relative) . '.php';
        if (is_file($file)) {
            require $file;
        }

        return;
    }
});
